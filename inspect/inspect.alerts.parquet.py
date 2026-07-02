import pandas as pd
df = pd.read_parquet("data/processed/alerts.parquet")
print(df.shape)
print(df.head())
print(df["source_ids"].value_counts())
print(df["severity_norm"].value_counts())