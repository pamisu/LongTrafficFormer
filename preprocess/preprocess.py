import os
import argparse
import pandas as pd
import dpkt
import concurrent.futures
from pathlib import Path
from scapy.all import rdpcap, wrpcap
from flow_data_preprocess import build_flow_data
from preprocess_utils import build_td_text_dataset, split_dataset
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, help="raw dataset path", required=True)
    parser.add_argument("--dataset_name", type=str, help="dataset name", required=True)
    parser.add_argument("--output_path", type=str, help="output dataset path", required=True)
    parser.add_argument("--num_workers", type=int, help="number of worker", required=True)
    args = parser.parse_args()
    return args

def get_session_feature(pcap, input):
    # BitTorrent.pcap.TCP_1-1-0-12_49252_1-2-7-170_443.pcap
    parts = pcap[0].name.split('.')
    filename = parts[0]+'.'+parts[1]+'_Flow.csv'
    feature_dir = os.path.join(input, 'feature', filename)
    data = pd.read_csv(feature_dir, encoding='gbk')

    features = []
    exclude_columns = {'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Label'}
    
    for p in pcap:
        feature_str = ""
        parts = p.name.split('.')
        five_tuple = parts[2].split('_')
        proto = '6' if five_tuple[0] == 'TCP' else '17'
        sip = five_tuple[1].replace('-', '.')
        sport = five_tuple[2]
        dip = five_tuple[3].replace('-', '.')
        dport = five_tuple[4]
        flow_id = f"{sip}-{dip}-{sport}-{dport}-{proto}"
        flow_id1 = f"{dip}-{sip}-{dport}-{sport}-{proto}"

        matching_row = data[data['Flow ID'].isin([flow_id, flow_id1])]
        
        if not matching_row.empty:
            row = matching_row.iloc[0]
            feature_columns = [col for col in data.columns if col not in exclude_columns]
            
            feature_parts = []
            for col in feature_columns:
                value = row[col]
                feature_parts.append(f"{col}: {value}")
            
            feature_str = ", ".join(feature_parts)
        
        features.append(feature_str)
    
    return features

def filter_flow(pcap_path, input):
    packets = []
    pnum = []
    fp = []
    features = []
    for p in pcap_path:
        size_kb = p.stat().st_size / 1024
        if size_kb < 2:
            continue
        with open(str(p), 'rb') as f:
            pcap_reader = dpkt.pcap.Reader(f)
            packet_count = 0
            for _, _ in pcap_reader:
                packet_count += 1
                if packet_count >= 3:
                    fp.append(p)
                    packet = rdpcap(str(p), count=5)
                    pnum.append(len(packet))
                    packets.extend(packet)
                    break
    if fp:
        features = get_session_feature(fp, input)
    return packets, pnum, features

def process_pcap_dir(pcap_dir: str, workers: int, outputfile, input):
    pcap_paths = list(Path(pcap_dir).glob('*.pcap'))
    pcap_paths = [pcap_paths[i::workers] for i in range(workers)]
    packets = []
    pnums = []
    features = []

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_path = {executor.submit(filter_flow, p, input): p for p in pcap_paths}
        
        for future in concurrent.futures.as_completed(future_to_path):
            filered_packets, pnum, session_features = future.result()
            packets.extend(filered_packets)
            pnums.extend(pnum)
            features.extend(session_features)
    if not packets:
        return []
    
    print(f"Total packets and flows after filtering: {len(packets)}, {len(pnums)}")
    wrpcap(outputfile, packets)
    build_data = build_flow_data(outputfile, pnums, features)
    print(f"Total flows after building: {len(build_data)}")
    
    return build_data

def main():
    args = get_args()

    if args.dataset_name == "ustc-tfc-2016":
        detection_task="EMD"
    elif args.dataset_name == "iscx-botnet":
        detection_task="BND"
    elif args.dataset_name == "iscx-vpn-2016" or args.dataset_name == "lfett-2021":
        detection_task="EVD"
    elif args.dataset_name == "dohbrw-2020":
        detection_task="MDD"
    elif args.dataset_name == "iscx-tor-2016":
        detection_task="TBD"
    # elif args.dataset_name == "cic-adware":
    #     detection_task="ATD"
    # elif args.dataset_name == "cic-ransomware":
    #     detection_task="RTD"
    # elif args.dataset_name == "cic-scareware":
    #     detection_task="STD"
    elif args.dataset_name == "dapt-2020":
        detection_task="APT"
    else:
        detection_task="EAC"

    if not os.path.exists(os.path.join(args.input, 'filtered')):
        os.makedirs(os.path.join(args.input, 'filtered'))
    if not os.path.exists(args.output_path):
        os.makedirs(args.output_path)

    subdirs = [d for d in Path(os.path.join(args.input, 'flow')).iterdir() if d.is_dir()]
    dataset = []
    train_dataset = []
    val_dataset = []
    test_dataset = []
    label = {'str': [], 'int': []}
    
    for subdir in subdirs:
        print(f"Processing directory: {subdir.name}")
        filtered_pcap_path = os.path.join(args.input, 'filtered', subdir.name + '.pcap')
        build_data = process_pcap_dir(str(subdir), args.num_workers, filtered_pcap_path, args.input) 
        if not build_data:
            print(f"Total packets and flows after filtering: 0, 0")
            continue
        label["int"].append(len(label["str"]))
        label["str"].append(subdir.name)
        train_data, val_data, test_data = split_dataset(build_data)

        build_text_data = build_td_text_dataset(build_data,int_label=label["int"][-1], str_label=label["str"][-1], task_name=detection_task, granularity='session')
        train_text_data = build_td_text_dataset(train_data, int_label=label["int"][-1], str_label=label["str"][-1], task_name=detection_task, granularity='session')
        val_text_data = build_td_text_dataset(val_data, int_label=label["int"][-1], str_label=label["str"][-1], task_name=detection_task, granularity='session')
        test_text_data = build_td_text_dataset(test_data, int_label=label["int"][-1], str_label=label["str"][-1], task_name=detection_task, granularity='session')
    
        dataset.append(build_text_data)
        train_dataset.append(train_text_data)
        val_dataset.append(val_text_data)
        test_dataset.append(test_text_data)

    dataset = pd.concat(dataset, ignore_index=True)
    train_dataset = pd.concat(train_dataset, ignore_index=True)
    val_dataset = pd.concat(val_dataset, ignore_index=True)
    test_dataset = pd.concat(test_dataset, ignore_index=True)
    label = pd.DataFrame(label)

    dataset.to_csv(os.path.join(args.output_path, "data.tsv"), index=False)
    train_dataset.to_csv(os.path.join(args.output_path, "train.tsv"), index=False)
    val_dataset.to_csv(os.path.join(args.output_path, "val.tsv"), index=False)
    test_dataset.to_csv(os.path.join(args.output_path, "test.tsv"), index=False)
    label.to_csv(os.path.join(args.output_path, "label.tsv"), index=False)

if __name__ == "__main__":
    main()