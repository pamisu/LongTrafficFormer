import os
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
import pandas as pd


MAX_SAMPLING_NUMBER = 600  # 5000 # number of samples per class

def split_dataset(build_data):
    if len(build_data) < 10:
        return build_data, build_data, build_data
    if len(build_data) > MAX_SAMPLING_NUMBER:
        build_data = resample(build_data, n_samples=MAX_SAMPLING_NUMBER, random_state=42, replace=False)
    train_data, temp_data = train_test_split(build_data, test_size=0.2, random_state=42, shuffle=True)
    val_data, test_data = train_test_split(temp_data, test_size=0.5, random_state=42, shuffle=True)

    return train_data, val_data, test_data

def split_dataset_with_tsv(data_dir):
    data = pd.read_csv(os.path.join(data_dir, 'data.tsv'))
    grouped_data = data.groupby('labels')
    train_data = pd.DataFrame()
    val_data = pd.DataFrame()
    test_data = pd.DataFrame()
    for label, group in grouped_data:
        if len(group) < 10:
            train = val = test = group
        elif len(group) > MAX_SAMPLING_NUMBER:
            sampled_group = resample(group, n_samples=MAX_SAMPLING_NUMBER, random_state=42, replace=False)
            train, temp = train_test_split(sampled_group, test_size=0.2, random_state=42, shuffle=True)
            val, test = train_test_split(temp, test_size=0.5, random_state=42, shuffle=True)
        else:
            sampled_group = group
            train, temp = train_test_split(sampled_group, test_size=0.2, random_state=42, shuffle=True)
            val, test = train_test_split(temp, test_size=0.5, random_state=42, shuffle=True)

        train_data = pd.concat([train_data, train], ignore_index=True)
        val_data = pd.concat([val_data, val], ignore_index=True)
        test_data = pd.concat([test_data, test], ignore_index=True)
    
    train_data.to_csv(os.path.join(data_dir, 'train.tsv'), index=False)
    val_data.to_csv(os.path.join(data_dir, 'val.tsv'), index=False)
    test_data.to_csv(os.path.join(data_dir, 'test.tsv'), index=False)

def build_td_text_dataset(traffic_data, int_label=0, str_label='', task_name=None, granularity=''):
    """Building the text datasets of traffic detection task"""
    if task_name == "EMD":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                      "traffic features, and payloads of the first five packets in a session and the session statistical features. "\
                      "Please conduct the ENCRYPTED MALWARE DETECTION TASK to determine " \
                      "which application category the encrypted beign or malicious traffic belongs to. The categories " \
                      "include 'FTP, Gmail, SMB, Weibo, Cridex, Geodo, Htbot, Miuref, Neris, " \
                      "Nsis-ay, Shifu, Tinba, Virut, Zeus'."

        str_output = str_label
        int_output = int_label

        # instruction = "Below is a traffic " + granularity + ". Please conduct the encrypted malware detection task: "
        #
        # output = "This might be a " + first_label + \
        #          " traffic " + granularity + ". The category is likely to be recognized as " + label + "."

    elif task_name == "EAC":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                      "traffic features, and payloads. Please conduct the ENCRYPTED APP CLASSIFICATION TASK to determine " \
                      "which APP category the encrypted traffic belongs to. "
        # The categories " \
        #                       "include '163Mail, 51cto, Acm, Adobe, Alibaba, Alicdn, Alipay, Amap, AmazonAWS, AmpProject, Apple," \
        #                       "Arxiv, Asus, Atlassian, AzureEdge, Baidu, Bilibili, Biligame, Booking, LA'." \

        str_output = str_label
        int_output = int_label
        # instruction = "Below is a traffic " + granularity + ". Please conduct the encrypted App classification task: "
        #
        # output = "The traffic category is likely to be recognized as " + label + "."

    elif task_name == "BND":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                       "traffic features, and payloads. Please conduct the BOTNET DETECTION TASK to determine " \
                       "which type of network the traffic belongs to. The categories " \
                       "include 'IRC, Neris, RBot, Virut, normal'."

        str_output = str_label
        int_output = int_label
        # instruction = "Below is a traffic " + granularity + ". Please conduct the botnet detection task: "
        #
        # output = "The traffic category is likely to be recognized as " + label + "."

    elif task_name == "EVD":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                      "traffic features, and payloads. Please conduct the ENCRYPTED VPN DETECTION TASK to determine " \
                      "which behavior or application category the VPN encrypted traffic belongs to. The categories " \
                      "include 'aim, bittorrent, email, facebook, ftps, hangout, icq, netflix, sftp, skype, spotify, " \
                      "vimeo, voipbuster, youtube'."

        str_output = str_label
        int_output = int_label

        # instruction = "Below is a traffic " + granularity + ". Please conduct the encrypted VPN detection task: "
        #
        # output = "The traffic category is likely to be recognized as " + label + "."

    elif task_name == "MDD":
        instruction = "Below is a traffic " + granularity + ". Please conduct the malicious DoH detection task: "

        str_output = "The traffic category is likely to be recognized as " + str_label + "."

    elif task_name == "TBD":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                      "traffic features, and payloads. Please conduct the TOR BEHAVIOR DETECTION TASK to determine " \
                      "which behavior or application category the traffic belongs to under the Tor network. " \
                      "The categories include 'audio, browsing, chat, file, mail, p2p, video, voip'."

        str_output = str_label
        int_output = int_label

    elif task_name == "APT":
        instruction = "Given the following traffic data <" + granularity + "> that contains protocol fields, " \
                                                                           "traffic features, and payloads. Please conduct the APT DETECTION TASK to determine " \
                                                                           "which behavior or application category the traffic belongs to under the APT attacks. " \
                                                                           "The categories include 'APT and normal'."

        str_output = str_label
        int_output = int_label

        # instruction = "Below is a traffic " + granularity + ". Please conduct the Tor behavior detection task: "
        #
        # output = "The traffic category is likely to be recognized as " + label + "."

    # elif task_name == "ATD":
    #     instruction = "Below is a traffic " + granularity + ". Please conduct the adware traffic detection task: "
    #
    #     output = "The traffic category is likely to be recognized as " + label + "."
    #
    # elif task_name == "RTD":
    #     instruction = "Below is a traffic " + granularity + ". Please conduct the ransomware traffic detection task: "
    #
    #     output = "The traffic category is likely to be recognized as " + label + "."
    #
    # elif task_name == "STD":
    #     instruction = "Below is a traffic " + granularity + ". Please conduct the scareware traffic detection task: "
    #
    #     output = "The traffic category is likely to be recognized as " + label + "."

    dataset = {"inputs": [], "labels": [], "str_labels": []}
    for data in traffic_data:
        dataset["inputs"].append(
            str(instruction) + "\\n<" + granularity + ">: " + data
        )
        dataset["labels"].append(int_output)
        dataset["str_labels"].append(str_output)
    dataset = pd.DataFrame(dataset)

    return dataset