import polars as pl

p = "dataset/raw_downloads/Code-Security-Vulnerability/train-00000-of-00001.parquet"
df = pl.read_parquet(p)

print("CWE-798 rows:",
      df.filter(pl.col("cwe_id") == "CWE-798").height)

print("Python rows:",
      df.filter(pl.col("language").str.to_lowercase() == "python").height)

print("Vulnerable rows:",
      df.filter(pl.col("is_vulnerable") == True).height)

print("CWE-798 AND Python:",
      df.filter(
          (pl.col("cwe_id") == "CWE-798") &
          (pl.col("language").str.to_lowercase() == "python")
      ).height)

print("CWE-798 AND vulnerable:",
      df.filter(
          (pl.col("cwe_id") == "CWE-798") &
          (pl.col("is_vulnerable") == True)
      ).height)

print("\nCWE-798 language distribution:")
print(
    df.filter(pl.col("cwe_id") == "CWE-798")
      .group_by("language")
      .len()
      .sort("len", descending=True)
)