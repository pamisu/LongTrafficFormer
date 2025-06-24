import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'
import argparse
import numpy as np
import pandas as pd
from datasets import Dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer,
    DataCollatorWithPadding,
    EarlyStoppingCallback
)
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task_name", type=str, help="task name", required=True)
    parser.add_argument("--model_name", type=str, help="pretrained model name", required=True)
    parser.add_argument("--num_labels", type=int, help="number of label", required=True)
    parser.add_argument("--batch_size", type=int, help="batch size", required=True)
    parser.add_argument("--epoch", type=int, help="epoch", required=True)
    parser.add_argument("--learning_rate", type=float, help="learning rate", required=True)
    parser.add_argument("--output_dir", type=str, help="output directory", required=True)
    parser.add_argument("--dataset_dir", type=str, help="data dir", required=True)
    parser.add_argument("--log_dir", type=str, help="log dir", required=True)

    args = parser.parse_args()
    return args

def load_data(dir):
    train_df = pd.read_csv(os.path.join(dir, "train.tsv"))
    val_df = pd.read_csv(os.path.join(dir, "val.tsv"))
    test_df = pd.read_csv(os.path.join(dir, "test.tsv"))
    
    train_dataset = Dataset.from_pandas(train_df).shuffle(seed=42)
    val_dataset = Dataset.from_pandas(val_df).shuffle(seed=42)
    test_dataset = Dataset.from_pandas(test_df).shuffle(seed=42)
    
    print(f"train size: {len(train_dataset)},val size: {len(val_dataset)}, test size: {len(test_dataset)}")
    
    return train_dataset, val_dataset, test_dataset

def preprocess_function(examples, tokenizer):
    return tokenizer(examples["inputs"], truncation=True, padding="max_length", max_length=512)

def compute_metrics(eval_pred):
    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)
    accuracy = accuracy_score(labels, predictions)
    precision = precision_score(labels, predictions, average="macro")
    recall = recall_score(labels, predictions, average="macro")
    f1 = f1_score(labels, predictions, average="macro")
    cm = confusion_matrix(labels, predictions)
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "cm": cm.tolist()
    }

def main():
    args = get_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        pretrained_model_name_or_path=args.model_name, num_labels=args.num_labels
    )
    
    train_dataset, val_dataset, test_dataset = load_data(args.dataset_dir)

    train_dataset = train_dataset.map(preprocess_function, batched=True, fn_kwargs={"tokenizer": tokenizer}).remove_columns(["inputs", "str_labels"])
    val_dataset = val_dataset.map(preprocess_function, batched=True, fn_kwargs={"tokenizer": tokenizer}).remove_columns(["inputs", "str_labels"])
    test_dataset = test_dataset.map(preprocess_function, batched=True, fn_kwargs={"tokenizer": tokenizer}).remove_columns(["inputs", "str_labels"])
    
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    
    training_args = TrainingArguments(
        run_name=args.task_name,
        output_dir=args.output_dir,
        logging_dir=args.log_dir,
        logging_strategy="steps",
        logging_steps=50,
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs= args.epoch,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=3,
        report_to="tensorboard",
        push_to_hub=False,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
    )
    
    trainer.train()
    
    result = trainer.evaluate()
    print(f"val result: {result}")
    result = trainer.predict(test_dataset)
    print(f"test result: {result}")
    
    trainer.save_model(os.path.join(args.output_dir, "final_model"))
    print(f"model is saved in: {os.path.join(args.output_dir, 'final_model')}")

if __name__ == "__main__":
    main()    