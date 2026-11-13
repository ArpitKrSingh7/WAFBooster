"""
Payload Corrector for WAF Testing (WAFBooster Section III-D, Algorithm 1).

Implements:
1. Keyword extractor extracting high-frequency SQL command keywords from seed payloads.
2. Edit distance computation (Levenshtein distance) via rapidfuzz.
3. Payload corrector implementing Algorithm 1:
   - Discards payloads shorter than 3 tokens or with any token distance > upper threshold (8).
   - Corrects tokens with edit distance between lower (4) and upper (8) to closest keyword.
   - Retains payloads unchanged where all token edit distances <= lower (4).
4. Batch corrector producing DataFrame [original_payload, corrected_payload, status].
"""

import os
from collections import Counter
from typing import List, Optional

import pandas as pd
from rapidfuzz.distance import Levenshtein

try:
    from src.dataset import load_malicious_seeds
    from src.shadow_model import tokenize
except ImportError:
    from dataset import load_malicious_seeds
    from shadow_model import tokenize

PUNCT_TOKENS = {"'", "--", "/*", "*/", "=", "(", ")", ",", ";", "#"}


def _join_tokens(tokens: List[str]) -> str:
    """
    Join tokens back into a string with no extra spaces around punctuation
    tokens (', --, /*, */, =, (, ), ,, ;) but normal spaces between word tokens.
    """
    if not tokens:
        return ""

    result = []
    for i, t in enumerate(tokens):
        if i == 0:
            result.append(t)
            continue

        prev = tokens[i - 1]
        if (
            t in PUNCT_TOKENS
            or prev in PUNCT_TOKENS
            or t.startswith("%")
            or prev.startswith("%")
            or prev == "0x"
        ):
            result.append(t)
        else:
            result.append(" " + t)

    return "".join(result)


def extract_keywords(seed_payloads: List[str], top_n: int = 5) -> List[str]:
    """
    Tokenizes all seed_payloads using tokenize() from shadow_model.py,
    counts frequency of each token, and returns the top_n most frequent
    SQL command keywords (e.g., SELECT, OR, UNION, FROM, --).
    """
    # Count tokens from seeds
    token_counts = Counter()
    for p in seed_payloads:
        for t in tokenize(p):
            t_clean = t.strip()
            # Retain word tokens (alpha) and SQL comment/operator tokens
            if (t_clean.isalpha() and len(t_clean) > 1) or t_clean == "--":
                token_counts[t_clean.upper()] += 1

    # Canonical paper keywords: SELECT, OR, UNION, FROM, --
    preferred_keywords = ["SELECT", "OR", "UNION", "FROM", "--"]

    # Select top_n keywords prioritizing high-frequency SQL keywords
    keywords: List[str] = []
    for kw in preferred_keywords:
        if kw in token_counts and kw not in keywords:
            keywords.append(kw)

    # Fill remaining from most common if needed
    for kw, _ in token_counts.most_common():
        if len(keywords) >= top_n:
            break
        if kw not in keywords:
            keywords.append(kw)

    return keywords[:top_n]


def min_token_edit_distance(substring: str, keywords: List[str]) -> int:
    """
    Uses rapidfuzz.distance.Levenshtein.distance to compute edit distance
    between substring and EACH keyword, returning the MINIMUM distance found.
    """
    sub_upper = substring.upper()
    return min(Levenshtein.distance(sub_upper, kw.upper()) for kw in keywords)


def correct_payload(
    payload: str,
    keywords: List[str],
    lower: int = 4,
    upper: int = 8,
) -> Optional[str]:
    """
    Implements Algorithm 1 from WAFBooster:
    - Splits payload into substrings using tokenize() from shadow_model.py.
    - Discards (returns None) payloads shorter than 3 tokens.
    - Computes min_token_edit_distance against keywords for each substring.
    - If ANY substring has edit distance > upper (8): discards payload, returns None.
    - If a substring's edit distance is between lower (4) and upper (8): attempts
      correction by replacing with closest-matching keyword.
    - If all substrings have edit distance <= lower (4): returns unchanged.
    """
    tokens = tokenize(payload)
    if len(tokens) < 3:
        return None

    # If ANY token has edit distance > upper threshold (8), discard entire payload
    for t in tokens:
        if min_token_edit_distance(t, keywords) > upper:
            return None

    modified = False
    new_tokens: List[str] = []

    for t in tokens:
        d = min_token_edit_distance(t, keywords)
        # If edit distance is between lower and upper (lower < d <= upper), correct it
        if d > lower:
            closest_kw = min(
                keywords,
                key=lambda kw: Levenshtein.distance(t.upper(), kw.upper()),
            )
            # Length-proximity guard: only replace if the token and keyword
            # are similar in length. Prevents short keywords (OR, --)
            # from falsely "correcting" long legitimate tokens (username, password).
            # Also require relative similarity: edit distance must be less than
            # half the token length to qualify as a plausible mutation.
            len_diff_ok = abs(len(t) - len(closest_kw)) <= 2
            relative_ok = d < max(len(t), len(closest_kw)) / 2
            if len_diff_ok and relative_ok:
                new_tokens.append(closest_kw)
                modified = True
            else:
                # Token is too different in length — keep original unchanged
                new_tokens.append(t)
        else:
            new_tokens.append(t)

    if modified:
        return _join_tokens(new_tokens)

    return payload


def correct_batch(
    payloads: List[str],
    keywords: List[str],
    lower: int = 4,
    upper: int = 8,
) -> pd.DataFrame:
    """
    Applies correct_payload to a list of payloads.
    Returns DataFrame with columns [original_payload, corrected_payload, status],
    where status is one of "unchanged", "corrected", "discarded".
    Prints summary counts of each status.
    """
    rows = []

    for p in payloads:
        tokens = tokenize(p)
        if len(tokens) < 3:
            rows.append({
                "original_payload": p,
                "corrected_payload": None,
                "status": "discarded",
            })
            continue

        # Check distances and closest keywords for each token
        dists = [min_token_edit_distance(t, keywords) for t in tokens]

        if any(d > upper for d in dists):
            rows.append({
                "original_payload": p,
                "corrected_payload": None,
                "status": "discarded",
            })
        else:
            # Check if any token actually qualifies for correction
            # (distance in (lower, upper] AND length-proximity <= 3)
            needs_correction = False
            for t, d in zip(tokens, dists):
                if d > lower:
                    closest_kw = min(
                        keywords,
                        key=lambda kw: Levenshtein.distance(t.upper(), kw.upper()),
                    )
                    len_diff_ok = abs(len(t) - len(closest_kw)) <= 2
                    d_val = Levenshtein.distance(t.upper(), closest_kw.upper())
                    relative_ok = d_val < max(len(t), len(closest_kw)) / 2
                    if len_diff_ok and relative_ok:
                        needs_correction = True
                        break

            if needs_correction:
                corrected = correct_payload(p, keywords, lower=lower, upper=upper)
                if corrected is not None:
                    rows.append({
                        "original_payload": p,
                        "corrected_payload": corrected,
                        "status": "corrected",
                    })
                else:
                    rows.append({
                        "original_payload": p,
                        "corrected_payload": None,
                        "status": "discarded",
                    })
            else:
                rows.append({
                    "original_payload": p,
                    "corrected_payload": p,
                    "status": "unchanged",
                })

    df = pd.DataFrame(rows, columns=["original_payload", "corrected_payload", "status"])
    print(f"\n[*] Correction Batch Summary (Total: {len(df)}):")
    counts = df["status"].value_counts().to_dict()
    for status, count in counts.items():
        print(f"    - {status.capitalize():<10}: {count} ({count / len(df) * 100:.2f}%)")

    return df


if __name__ == "__main__":
    candidates_path = "data/processed/generated_candidates.csv"
    if not os.path.exists(candidates_path):
        raise FileNotFoundError(f"Missing {candidates_path}. Run src/payload_generator.py first.")

    print("=== Step 1: Extracting Top-5 Keywords from Original Seeds ===")
    seeds = load_malicious_seeds()
    keywords = extract_keywords(seeds, top_n=5)
    print(f"Loaded {len(seeds)} SQLi seeds.")
    print(f"Top-5 Keywords: {keywords}")

    print("\n=== Step 2: Loading Candidate Payloads ===")
    candidates_df = pd.read_csv(candidates_path)
    raw_candidates = candidates_df["payload"].dropna().tolist()
    print(f"Loaded {len(raw_candidates)} candidate payloads from {candidates_path}")

    print("\n=== Step 3: Running Payload Corrector (Algorithm 1) ===")
    results_df = correct_batch(raw_candidates, keywords=keywords, lower=4, upper=8)

    print("\n=== Step 4: Sample Rows Per Category ===")
    for status in ["unchanged", "corrected", "discarded"]:
        subset = results_df[results_df["status"] == status]
        print(f"\n--- 5 Example Rows: {status.upper()} (Total: {len(subset)}) ---")
        if subset.empty:
            print("  (None)")
            continue

        sample_subset = subset.head(5)
        for idx, (_, row) in enumerate(sample_subset.iterrows(), 1):
            if status == "corrected":
                print(f"  {idx}. Original:  {row['original_payload']}")
                print(f"     Corrected: {row['corrected_payload']}")
            else:
                print(f"  {idx}. Payload:   {row['original_payload']}")

    print("\n=== Step 5: Saving Valid Corrected Candidates ===")
    os.makedirs("data/processed", exist_ok=True)
    out_path = "data/processed/corrected_candidates.csv"
    valid_df = results_df[results_df["status"] != "discarded"]
    valid_df.to_csv(out_path, index=False)
    print(f"Saved {len(valid_df)} valid payloads (unchanged + corrected) to: {out_path}")
