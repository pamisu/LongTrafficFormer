import os
import argparse
import pandas as pd
import dpkt
import concurrent.futures
from pathlib import Path
from scapy.all import rdpcap, wrpcap
from flow_data_preprocess import build_flow_data
from preprocess_utils import build_td_text_dataset, split_dataset
from sesstion_feature import get_session_feature
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

def filter_flow(pcap_path):
    packets = []
    pnum = []
    feature = []
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
                    feature_str = get_session_feature(str(p))
                    feature.append(feature_str)
                    packet = rdpcap(str(p), count=5)
                    pnum.append(len(packet))
                    packets.extend(packet)
                    break
    
    return packets, pnum, feature

def process_pcap_dir(pcap_dir: str, workers: int, outputfile):
    pcap_paths = list(Path(pcap_dir).glob('*.pcap'))
    pcap_paths = [pcap_paths[i::workers] for i in range(workers)]
    packets = []
    pnums = []
    features = []

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_path = {executor.submit(filter_flow, p): p for p in pcap_paths}
        
        for future in concurrent.futures.as_completed(future_to_path):
            filered_packets, pnum, feature = future.result()
            packets.extend(filered_packets)
            pnums.extend(pnum)
            features.extend(feature)
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
        build_data = process_pcap_dir(str(subdir), args.num_workers, filtered_pcap_path) 
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