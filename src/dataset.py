"""
Dataset pipeline for WAF testing:
Extracts benign traffic from CSIC 2010 dataset, pairs with mutated SQLi seeds
(WAF-A-MoLE style mutation operators), evaluates ground-truth labels against the
live WAF, and creates stratified train/val/test splits.

CSIC 2010 Dataset Schema (17 columns):
['', 'Method', 'User-Agent', 'Pragma', 'Cache-Control', 'Accept', 'Accept-encoding',
 'Accept-charset', 'language', 'host', 'cookie', 'content-type', 'connection',
 'lenght', 'content', 'classification', 'URL']
- Column '': Unnamed index / label string ('Normal' or 'Anomalous')
- Column 'classification': Target integer (0 = Normal, 1 = Anomalous)
- Column 'lenght': Source spelling preserved
- Column 'URL': Contains request path, query string, and HTTP version suffix
"""

import os
import random
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Tuple

import pandas as pd
from sklearn.model_selection import train_test_split

try:
    from src.waf_client import check_waf
except ImportError:
    from waf_client import check_waf

# Exact CSIC 2010 dataset columns
CSIC_COLUMNS = [
    "",
    "Method",
    "User-Agent",
    "Pragma",
    "Cache-Control",
    "Accept",
    "Accept-encoding",
    "Accept-charset",
    "language",
    "host",
    "cookie",
    "content-type",
    "connection",
    "lenght",
    "content",
    "classification",
    "URL",
]

# Hardcoded SQLi seeds
SQLI_SEEDS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR 'a'='a",
    "'; DROP TABLE users--",
    "' OR SLEEP(5)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' HAVING 1=1--",
    "' GROUP BY columnnames having 1=1--",
    "%' OR '1'='1",
    "' OR username LIKE '%admin%",
    "1; SELECT * FROM users",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' AND SUBSTRING(username,1,1)='a",
    "1' AND SLEEP(5) AND '1'='1",
    "' OR '1'='1' /*",
    "admin' OR '1'='1'#",
    "' OR 1=1 LIMIT 1--",
    "1 OR 1=1",
    "'||'1'='1",
    "' OR 1=1;--",
    "' union all select null,null,null--",
]

KEYWORDS = [
    "SELECT", "UNION", "ALL", "FROM", "WHERE", "ORDER", "BY",
    "HAVING", "GROUP", "DROP", "TABLE", "LIMIT", "LIKE", "EXISTS",
    "CONVERT", "SUBSTRING", "SLEEP", "NULL", "OR", "AND", "ADMIN", "USERS"
]


def _random_case(word: str, rng: random.Random) -> str:
    """Randomize the case of letters in a word while avoiding all-upper or all-lower."""
    res = "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in word)
    if res.lower() == word.lower() and (res.isupper() or res.islower()) and len(word) >= 2:
        res = word[0].upper() + word[1].lower() + word[2:].upper()
    return res


def _apply_case_swap(text: str, rng: random.Random) -> str:
    """Randomize case of SQL keywords in text."""
    res = text
    for kw in KEYWORDS:
        pattern = re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
        res = pattern.sub(lambda m: _random_case(m.group(0), rng), res)
    return res


def mutate_seed(payload: str) -> List[str]:
    """
    Applies WAF-A-MoLE style mutation operators to a single SQLi seed payload:
    - Case swapping (randomize case of SQL keywords: SELECT -> SeLeCt)
    - Whitespace substitution (replace spaces with /**/, %20, or tabs)
    - Inline comment injection (insert /**/ between keywords: OR/**/1=1)
    - Integer encoding variants (1=1 -> 2-1=1, 0x31=0x31)
    - Logically equivalent rewrites (OR 1=1 -> OR 2>1, OR 'a'='a' -> OR 'x'='x')

    Generates ~15-20 distinct variants per seed using combinations of these operators.
    """
    variants = set()

    # 1. Logically equivalent rewrites
    log_rewrites = []
    if "'1'='1'" in payload:
        log_rewrites.extend([
            payload.replace("'1'='1'", "'x'='x'"),
            payload.replace("'1'='1'", "'2'='2'"),
            payload.replace("'1'='1'", "'y'='y'"),
            payload.replace("'1'='1'", "2>1"),
            payload.replace("'1'='1'", "1<=1"),
            payload.replace("'1'='1'", "'a'='a'"),
        ])
    if "1=1" in payload:
        log_rewrites.extend([
            re.sub(r"\b1=1\b", "2>1", payload),
            re.sub(r"\b1=1\b", "1<=1", payload),
            re.sub(r"\b1=1\b", "'a'='a'", payload),
            re.sub(r"\b1=1\b", "3>=3", payload),
            re.sub(r"\b1=1\b", "'x'='x'", payload),
        ])
    if "'a'='a'" in payload:
        log_rewrites.extend([
            payload.replace("'a'='a'", "'x'='x'"),
            payload.replace("'a'='a'", "'b'='b'"),
            payload.replace("'a'='a'", "'1'='1'"),
            payload.replace("'a'='a'", "1=1"),
            payload.replace("'a'='a'", "2>1"),
            payload.replace("'a'='a'", "1<=1"),
        ])
    if "1=2" in payload:
        log_rewrites.extend([
            re.sub(r"\b1=2\b", "2<1", payload),
            re.sub(r"\b1=2\b", "1>2", payload),
            re.sub(r"\b1=2\b", "'a'='b'", payload),
            re.sub(r"\b1=2\b", "0=1", payload),
        ])
    if "admin'--" in payload:
        log_rewrites.extend([
            payload.replace("admin'--", "admin' OR 1=1--"),
            payload.replace("admin'--", "admin' OR 'x'='x'--"),
            payload.replace("admin'--", "admin' OR 2>1--"),
            payload.replace("admin'--", "admin'/*"),
            payload.replace("admin'--", "admin'#"),
            payload.replace("admin'--", "admin' AND 1=1--"),
        ])
    if "admin' OR '1'='1'#" in payload:
        log_rewrites.extend([
            payload.replace("'1'='1'", "'x'='x'"),
            payload.replace("'1'='1'", "2>1"),
            payload.replace("#", "--"),
        ])
    if "'||'1'='1" in payload:
        log_rewrites.extend([
            "'||'x'='x",
            "'||2>1",
            "' OR '1'='1",
            "' OR 1=1--",
            "'||1<=1",
            "'||'a'='a",
        ])
    if "SELECT * FROM users" in payload:
        log_rewrites.extend([
            payload.replace("SELECT * FROM users", "SELECT 1 FROM users WHERE 1=1"),
            payload.replace("SELECT * FROM users", "SELECT username,password FROM users"),
        ])

    # 2. Integer encoding variants
    int_encodings = []
    if "'1'='1'" in payload:
        int_encodings.extend([
            payload.replace("'1'='1'", "0x31=0x31"),
            payload.replace("'1'='1'", "(1)=(1)"),
            payload.replace("'1'='1'", "'2'-1='1'"),
            payload.replace("'1'='1'", "'1'=2-1"),
            payload.replace("'1'='1'", "1-0=1"),
        ])
    if "1=1" in payload:
        int_encodings.extend([
            re.sub(r"\b1=1\b", "2-1=1", payload),
            re.sub(r"\b1=1\b", "0x31=0x31", payload),
            re.sub(r"\b1=1\b", "3-2=1", payload),
            re.sub(r"\b1=1\b", "(1)=(1)", payload),
            re.sub(r"\b1=1\b", "1=2-1", payload),
        ])
    if "1=2" in payload:
        int_encodings.extend([
            re.sub(r"\b1=2\b", "2-1=2", payload),
            re.sub(r"\b1=2\b", "1=3-1", payload),
            re.sub(r"\b1=2\b", "0x31=0x32", payload),
            re.sub(r"\b1=2\b", "(1)=(2)", payload),
        ])
    if "SLEEP(5)" in payload:
        int_encodings.extend([
            payload.replace("SLEEP(5)", "SLEEP(2+3)"),
            payload.replace("SLEEP(5)", "SLEEP(6-1)"),
            payload.replace("SLEEP(5)", "SLEEP(0x5)"),
        ])
    if "ORDER BY 1" in payload:
        int_encodings.extend([
            re.sub(r"\bORDER BY 1\b", "ORDER BY 2-1", payload),
            re.sub(r"\bORDER BY 1\b", "ORDER BY 0x1", payload),
        ])
    if "ORDER BY 10" in payload:
        int_encodings.extend([
            payload.replace("ORDER BY 10", "ORDER BY 5+5"),
            payload.replace("ORDER BY 10", "ORDER BY 0xa"),
        ])
    if "LIMIT 1" in payload:
        int_encodings.extend([
            payload.replace("LIMIT 1", "LIMIT 2-1"),
            payload.replace("LIMIT 1", "LIMIT 0x1"),
        ])
    if "SUBSTRING(username,1,1)" in payload:
        int_encodings.extend([
            payload.replace("SUBSTRING(username,1,1)", "SUBSTRING(username,2-1,2-1)"),
            payload.replace("SUBSTRING(username,1,1)", "SUBSTRING(username,0x1,0x1)"),
        ])

    candidates = [payload] + log_rewrites + int_encodings

    # A. Case swapping
    for i in range(1, 5):
        rng = random.Random(len(payload) * 13 + i)
        for base in candidates[:5]:
            cs = _apply_case_swap(base, rng)
            if cs != payload:
                variants.add(cs)

    # B. Whitespace substitution (/**/, %20, \t)
    for ws in ["/**/", "%20", "\t"]:
        if " " in payload:
            variants.add(payload.replace(" ", ws))
        for base in (log_rewrites[:3] + int_encodings[:3]):
            if " " in base:
                variants.add(base.replace(" ", ws))

    # C. Inline comment injection
    if " " in payload:
        commented = re.sub(r" +", "/**/", payload)
        variants.add(commented)
        variants.add(_apply_case_swap(commented, random.Random(99)))
        parts = payload.split(" ", 1)
        if len(parts) == 2:
            variants.add(f"{parts[0]}/**/ {parts[1]}")
            variants.add(f"{parts[0]} /**/{parts[1]}")
    else:
        if "'" in payload:
            variants.add(payload.replace("'", "'/**/"))
            variants.add(payload.replace("'", "/**/'"))
        if "--" in payload:
            variants.add(payload.replace("--", "/**/--"))

    # D. Direct integer encodings and rewrites
    for ie in int_encodings:
        variants.add(ie)
    for lr in log_rewrites:
        variants.add(lr)

    # E. Multi-operator combinations (Case swap + Whitespace / Comment + Rewrite)
    combo_rng = random.Random(hash(payload))
    all_bases = list(variants) + [payload]
    for b in all_bases:
        if len(variants) >= 20:
            break
        if " " in b:
            v_c = _apply_case_swap(b.replace(" ", "/**/"), combo_rng)
            variants.add(v_c)
            v_t = _apply_case_swap(b.replace(" ", "\t"), combo_rng)
            variants.add(v_t)
            v_u = _apply_case_swap(b.replace(" ", "%20"), combo_rng)
            variants.add(v_u)

    variants.discard(payload)
    result = sorted(variants)
    if len(result) > 20:
        result = result[:20]
    return result


def load_benign(path: str, max_samples: Optional[int] = None) -> List[str]:
    """
    Extract query parameter values from normal-traffic rows only in CSIC 2010.

    Args:
        path: Path to the csic_database.csv file.
        max_samples: Optional limit on the number of extracted parameter values.

    Returns:
        List of extracted query parameter strings.
    """
    df = pd.read_csv(path, encoding="utf-8-sig")

    # Filter for normal traffic rows only (classification == 0)
    if "classification" in df.columns:
        normal_mask = df["classification"].astype(str).str.strip() == "0"
    else:
        # Fallback to the blank-header first column if classification column is absent
        first_col = df.columns[0]
        normal_mask = df[first_col].astype(str).str.strip().str.lower() == "normal"

    normal_df = df[normal_mask]

    benign_values: List[str] = []
    for u in normal_df["URL"].dropna():
        # URL field contains path + query + ' HTTP/1.1'
        clean_url = str(u).split()[0]
        parsed = urllib.parse.urlparse(clean_url)
        if parsed.query:
            # Extract query parameter values
            for _, val in urllib.parse.parse_qsl(parsed.query, keep_blank_values=False):
                if val and val.strip():
                    benign_values.append(val)
                    if max_samples is not None and len(benign_values) >= max_samples:
                        return benign_values

    return benign_values


def load_malicious_seeds() -> List[str]:
    """
    Return the hardcoded SQLi seed list.
    """
    return list(SQLI_SEEDS)


def build_labeled_dataset(
    benign: List[str],
    malicious: List[str],
    waf_client_fn: Callable[[str], Optional[int]],
    max_workers: int = 30,
) -> pd.DataFrame:
    """
    For every payload call waf_client_fn. Ground-truth label is the live result from the WAF.

    Columns: [payload, source, waf_label]
    """
    records = []

    # 1. Evaluate benign payloads
    print(f"[*] Querying WAF for {len(benign)} benign payloads...")
    if max_workers > 1 and len(benign) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            benign_labels = list(executor.map(waf_client_fn, benign))
    else:
        benign_labels = [waf_client_fn(p) for p in benign]

    for p, label in zip(benign, benign_labels):
        if label is not None:
            records.append({"payload": p, "source": "benign", "waf_label": int(label)})

    # 2. Evaluate malicious payloads
    print(f"[*] Querying WAF for {len(malicious)} malicious payloads...")
    if max_workers > 1 and len(malicious) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            malicious_labels = list(executor.map(waf_client_fn, malicious))
    else:
        malicious_labels = [waf_client_fn(p) for p in malicious]

    for p, label in zip(malicious, malicious_labels):
        if label is not None:
            records.append({"payload": p, "source": "malicious", "waf_label": int(label)})

    df = pd.DataFrame(records, columns=["payload", "source", "waf_label"])
    return df


def split_and_save(
    df: pd.DataFrame,
    out_dir: str = "data/processed/",
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    70/15/15 stratified split by waf_label.
    Saves train.csv, val.csv, and test.csv in out_dir.
    """
    os.makedirs(out_dir, exist_ok=True)

    # 70% train, 30% temp
    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=random_state,
        stratify=df["waf_label"],
    )

    # Split temp 50/50 -> 15% val, 15% test of original total
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=random_state,
        stratify=temp_df["waf_label"],
    )

    train_path = os.path.join(out_dir, "train.csv")
    val_path = os.path.join(out_dir, "val.csv")
    test_path = os.path.join(out_dir, "test.csv")

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    return train_df, val_df, test_df


def print_split_distribution(name: str, split_df: pd.DataFrame, total_len: int) -> None:
    """Print count and percentage distribution of labels for a dataset split."""
    counts = split_df["waf_label"].value_counts().to_dict()
    count_0 = counts.get(0, 0)
    count_1 = counts.get(1, 0)
    total_split = len(split_df)
    pct_of_total = (total_split / total_len * 100) if total_len > 0 else 0

    print(f"\n--- {name} Split ---")
    print(f"Total rows: {total_split} ({pct_of_total:.1f}% of dataset)")
    print(f"  waf_label = 0 (Allowed): {count_0} ({count_0 / total_split * 100:.2f}%)")
    print(f"  waf_label = 1 (Blocked): {count_1} ({count_1 / total_split * 100:.2f}%)")
    source_counts = split_df["source"].value_counts().to_dict()
    print(f"  Source breakdown: {source_counts}")


if __name__ == "__main__":
    csv_file = "archive/csic_database.csv"
    if not os.path.exists(csv_file):
        print(f"[-] CSV file not found at {csv_file}")
        sys.exit(1)

    print("=== Step 1: Loading & Downsampling Benign Payloads ===")
    all_benign = load_benign(csv_file)
    print(f"Extracted {len(all_benign)} total benign query parameter values from normal traffic.")

    # Downsample benign to 2000 samples with fixed random_state=42 for reproducibility
    sampled_benign = pd.Series(all_benign).sample(n=2000, random_state=42).tolist()
    print(f"Downsampled to {len(sampled_benign)} benign payloads (random_state=42).")

    print("\n=== Step 2: Mutating SQLi Seeds to Generate Malicious Payloads ===")
    seeds = load_malicious_seeds()
    mutated_set = set()
    for s in seeds:
        variants = mutate_seed(s)
        mutated_set.update(variants)
        mutated_set.add(s)  # Include original seed

    malicious_payloads = sorted(mutated_set)
    print(f"Generated {len(malicious_payloads)} unique malicious payloads from {len(seeds)} SQLi seeds.")

    print("\n=== Step 3: Querying Live WAF Ground Truth ===")
    dataset_df = build_labeled_dataset(sampled_benign, malicious_payloads, check_waf)
    print(f"Labeled dataset created: {len(dataset_df)} total records.")

    print("\n=== Step 4: Stratified Splitting (70/15/15) & Saving ===")
    out_directory = "data/processed/"
    train, val, test = split_and_save(dataset_df, out_dir=out_directory, random_state=42)
    print(f"Splits saved to {out_directory} (train.csv, val.csv, test.csv)")

    print("\n=== Step 5: Label Distribution Per Split ===")
    total_records = len(dataset_df)
    print_split_distribution("Train", train, total_records)
    print_split_distribution("Validation", val, total_records)
    print_split_distribution("Test", test, total_records)
