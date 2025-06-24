from preprocess.preprocess_utils import split_dataset_with_tsv

if __name__ == "__main__":
    split_dataset_with_tsv('dataset/ustc-tfc')
    # split_dataset_with_tsv('dataset/cic-adware')
    # split_dataset_with_tsv('dataset/cic-ransomware')
    # split_dataset_with_tsv('dataset/cic-scareware')
    # split_dataset_with_tsv('dataset/iscx-tor-2016')
    # split_dataset_with_tsv('dataset/dapt-2020')