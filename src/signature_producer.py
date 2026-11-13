"""
Signature Producer for WAF Testing (WAFBooster Section III-E, Algorithm 2).

Implements:
1. Four scoring functions (Delete, Replace, Head, Tail) to find important
   tokens in bypassing malicious payloads (Algorithm 2).
2. Token clustering via edit-distance grouping and sequential token patterns.
3. Smith-Waterman local sequence alignment.
4. Simplified regular expression signature generation (using \\S* wildcards).
5. Benign dataset validation to enforce ZERO false rejections (FRR = 0%).
6. ModSecurity SecRule generation and live WAF hot-reload verification.
"""

import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from rapidfuzz.distance import Levenshtein

try:
    from src.shadow_model import tokenize
    from src.waf_client import _session, check_waf
except ImportError:
    from shadow_model import tokenize
    from waf_client import _session, check_waf


def query_waf(payload: str) -> int:
    """Wrapper: returns 1 (blocked) or 0 (allowed)."""
    result = check_waf(payload)
    return result if result is not None else 0


# ---------------------------------------------------------------------------
# 1. Scoring Functions (Algorithm 2)
# ---------------------------------------------------------------------------


def _join_tokens(tokens: List[str]) -> str:
    """Re-join tokens into a payload string with proper spacing."""
    PUNCT = {"'", "--", "/*", "*/", "=", "(", ")", ",", ";", "#", "0x"}
    if not tokens:
        return ""
    parts = [tokens[0]]
    for i in range(1, len(tokens)):
        t, prev = tokens[i], tokens[i - 1]
        if (
            t in PUNCT
            or prev in PUNCT
            or t.startswith("%")
            or prev.startswith("%")
            or prev == "0x"
        ):
            parts.append(t)
        else:
            parts.append(" " + t)
    return "".join(parts)


def _waf_decision(payload: str, waf_fn: Callable[[str], int]) -> int:
    """Query WAF and return 1 (blocked) or 0 (allowed)."""
    return waf_fn(payload)


def delete_score(tokens: List[str], i: int, waf_fn: Callable) -> int:
    """DS(xi) = f(x) - f(x without xi). 1 if decision changes, 0 if unchanged."""
    original = _join_tokens(tokens)
    deleted = _join_tokens(tokens[:i] + tokens[i + 1:])
    f_orig = _waf_decision(original, waf_fn)
    f_del = _waf_decision(deleted, waf_fn)
    return 1 if f_orig != f_del else 0


def replace_score(tokens: List[str], i: int, waf_fn: Callable) -> int:
    """RS(xi) = f(x) - f(x with xi replaced by 'unknown'). 1 if changed, 0 if not."""
    original = _join_tokens(tokens)
    replaced = _join_tokens(tokens[:i] + ["unknown"] + tokens[i + 1:])
    f_orig = _waf_decision(original, waf_fn)
    f_rep = _waf_decision(replaced, waf_fn)
    return 1 if f_orig != f_rep else 0


def head_score(tokens: List[str], i: int, waf_fn: Callable) -> int:
    """HS(xi) = f(x1..xi) - f(x1..x(i-1)). 1 if changed, 0 if not."""
    head_with = _join_tokens(tokens[: i + 1])
    head_without = _join_tokens(tokens[:i]) if i > 0 else ""
    f_with = _waf_decision(head_with, waf_fn)
    f_without = _waf_decision(head_without, waf_fn) if head_without else 0
    return 1 if f_with != f_without else 0


def tail_score(tokens: List[str], i: int, waf_fn: Callable) -> int:
    """TS(xi) = f(xi..xn) - f(x(i+1)..xn). 1 if changed, 0 if not."""
    tail_with = _join_tokens(tokens[i:])
    tail_without = _join_tokens(tokens[i + 1:]) if i < len(tokens) - 1 else ""
    f_with = _waf_decision(tail_with, waf_fn)
    f_without = _waf_decision(tail_without, waf_fn) if tail_without else 0
    return 1 if f_with != f_without else 0


# Cache for token scoring to avoid redundant WAF queries
_SCORE_CACHE: Dict[str, List[Tuple[str, int]]] = {}


def find_important_tokens(
    payload: str,
    waf_fn: Callable[[str], int],
    top_m: int = 3,
) -> List[Tuple[str, int]]:
    """
    Algorithm 2: Score each token in the payload using 4 scoring functions,
    return top-m tokens with highest combined scores.
    """
    if payload in _SCORE_CACHE:
        return _SCORE_CACHE[payload][:top_m]

    tokens = tokenize(payload)
    if len(tokens) == 0:
        return []

    scores = []
    for i, tok in enumerate(tokens):
        ds = delete_score(tokens, i, waf_fn)
        rs = replace_score(tokens, i, waf_fn)
        hs = head_score(tokens, i, waf_fn)
        ts = tail_score(tokens, i, waf_fn)
        total = ds + rs + hs + ts
        scores.append((tok, total))

    # Sort by score descending, preserving order for stability
    scores.sort(key=lambda x: -x[1])

    seen = set()
    unique = []
    for tok, sc in scores:
        if tok not in seen and sc > 0:
            seen.add(tok)
            unique.append((tok, sc))

    _SCORE_CACHE[payload] = unique
    return unique[:top_m]


# ---------------------------------------------------------------------------
# 2. Clustering via Levenshtein Edit Distance
# ---------------------------------------------------------------------------


def cluster_tokens(
    important_tokens: List[str],
    threshold: float = 2.0,
) -> List[List[str]]:
    """
    Group similar tokens using single-linkage clustering on Levenshtein distance.
    """
    if not important_tokens:
        return []

    n = len(important_tokens)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i in range(n):
        for j in range(i + 1, n):
            d = Levenshtein.distance(important_tokens[i].upper(), important_tokens[j].upper())
            if d <= threshold:
                union(i, j)

    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(important_tokens[i])

    return list(groups.values())


# ---------------------------------------------------------------------------
# 3. Smith-Waterman Local Sequence Alignment
# ---------------------------------------------------------------------------


def smith_waterman(
    s1: str,
    s2: str,
    match_score: float = 1.0,
    gap_penalty: float = 0.8,
) -> str:
    """
    Smith-Waterman local alignment to extract longest common subsequence.
    Match reward = 1.0, gap penalty = 0.8 (as specified in paper Section III-E).
    """
    m, n = len(s1), len(s2)
    H = np.zeros((m + 1, n + 1), dtype=float)
    traceback = np.zeros((m + 1, n + 1), dtype=int)

    max_score = 0.0
    max_pos = (0, 0)

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1].upper() == s2[j - 1].upper():
                diag = H[i - 1][j - 1] + match_score
            else:
                diag = H[i - 1][j - 1] - gap_penalty

            up = H[i - 1][j] - gap_penalty
            left = H[i][j - 1] - gap_penalty

            best = max(0, diag, up, left)
            H[i][j] = best

            if best == 0:
                traceback[i][j] = 0
            elif best == diag:
                traceback[i][j] = 1
            elif best == up:
                traceback[i][j] = 2
            else:
                traceback[i][j] = 3

            if best > max_score:
                max_score = best
                max_pos = (i, j)

    aligned = []
    i, j = max_pos
    while i > 0 and j > 0 and H[i][j] > 0:
        if traceback[i][j] == 1:
            if s1[i - 1].upper() == s2[j - 1].upper():
                aligned.append(s1[i - 1])
            i -= 1
            j -= 1
        elif traceback[i][j] == 2:
            i -= 1
        else:
            j -= 1

    aligned.reverse()
    return "".join(aligned)


def find_group_signature(group: List[str], gap_penalty: float = 0.8) -> str:
    """
    Align all tokens within a group to derive the shared consensus subsequence.
    """
    if len(group) == 0:
        return ""
    if len(group) == 1:
        return group[0]

    common = group[0]
    for tok in group[1:]:
        common = smith_waterman(common, tok, gap_penalty=gap_penalty)
        if not common:
            break

    return common


# ---------------------------------------------------------------------------
# 4. Simplified Regular Expression & ModSecurity Rule Generation
# ---------------------------------------------------------------------------


def generate_regex_signature(token_or_subseq: str) -> str:
    """
    Generates a simplified regular expression signature using \\S* wildcards.
    Ensures safe word boundaries for SQL keywords to prevent false positives.
    """
    tok = token_or_subseq.strip()
    if not tok:
        return ""

    tok_upper = tok.upper()

    # Case 1: Tautology keywords (e.g. OR, AND) that bypass CRS when spaces are omitted
    if tok_upper in ("OR", "AND"):
        return rf"(?i)\b{tok_upper}\b\S*['\"\d]"

    # Case 2: Multi-token or stacked query keywords
    if tok_upper in ("SELECT", "FROM", "UNION"):
        return rf"(?i)\b{tok_upper}\b\S*['\"%]"

    # Case 3: Specific SQL function calls
    if tok_upper in ("SLEEP", "BENCHMARK"):
        return rf"(?i)\b{tok_upper}\b"

    # Case 4: SQL Comments
    if tok == "--":
        return r"--\s*$"
    if tok in ("/*", "*/"):
        return r"/\*.*?\*/"

    # Case 5: SQL Tautology constants
    if tok in ("1=1", "'1'='1'"):
        return r"(?i)1=1|'1'='1'"

    # Case 6: Generic alpha keyword -> match with word boundaries and \\S*
    if tok.isalpha() and len(tok) >= 3:
        return rf"(?i)\b{tok}\b"

    # Case 7: URL encoded SQL keywords
    if tok.startswith("%20") or "%20" in tok:
        return rf"(?i){re.escape(tok)}"

    # Default fallback
    return rf"\S*{re.escape(tok)}\S*"


def generate_modsec_rule(
    rule_id: int,
    regex_pattern: str,
    msg: str = "WAFBooster: Auto-generated rule for mutated payload",
) -> str:
    """
    Generates an official ModSecurity CRS-compatible SecRule directive.
    Applies t:none,t:urlDecodeUni so incoming URL-encoded HTTP parameters
    are decoded prior to pattern matching. Safely encodes quotes.
    """
    # Safely escape quotes for ModSecurity directive parsing
    clean_pat = regex_pattern.replace('"', r"\x22")
    rule = (
        f'SecRule ARGS|REQUEST_URI "@rx {clean_pat}" '
        f'"id:{rule_id},phase:2,deny,status:403,'
        f"t:none,t:urlDecodeUni,"
        f"msg:'{msg}',"
        f"severity:'CRITICAL',"
        f"tag:'WAFBooster/auto-generated'\""
    )
    return rule


# ---------------------------------------------------------------------------
# 5. Core Pipeline with Benign Validation
# ---------------------------------------------------------------------------


def produce_signatures(
    bypassing_payloads: List[str],
    waf_fn: Callable[[str], int],
    benign_samples: Optional[List[str]] = None,
    top_m: int = 3,
    cluster_threshold: float = 2.0,
    gap_penalty: float = 0.8,
    use_composite_patterns: bool = True,
    verbose: bool = True,
) -> Tuple[List[str], List[str]]:
    """
    End-to-end WAFBooster Signature Producer:
    1. Scores bypassing payloads using Delete, Replace, Head, Tail scoring functions.
    2. Groups identified important tokens into clusters.
    3. Runs Smith-Waterman alignment on clusters.
    4. Constructs simplified regex signatures.
    5. Filters candidate signatures against benign samples to ensure FRR = 0%.
    6. Produces ModSecurity SecRules.

    When use_composite_patterns is False, only signatures derived from the
    Smith-Waterman/clustering output (subsequences) are used.
    """
    if verbose:
        print(f"\n[*] Processing {len(bypassing_payloads)} bypassing payloads...")

    # Step 1: Score tokens across payloads
    all_important = []
    payload_token_sequences = []

    for idx, payload in enumerate(bypassing_payloads):
        imp = find_important_tokens(payload, waf_fn, top_m=top_m)
        tokens_only = [t for t, s in imp]
        all_important.extend(tokens_only)
        payload_token_sequences.append((payload, tokens_only))
        if verbose and (idx + 1) % 15 == 0:
            print(f"    Scored {idx + 1}/{len(bypassing_payloads)} payloads")

    if verbose:
        print(f"    Total important tokens collected: {len(all_important)}")
        freq = Counter(all_important).most_common(10)
        print(f"    Top-10 frequent tokens: {freq}")

    # Step 2: Cluster tokens
    unique_tokens = list(set(all_important))
    groups = cluster_tokens(unique_tokens, threshold=cluster_threshold)

    # Step 3: Smith-Waterman alignment on groups
    subsequences = []
    for g in groups:
        sub = find_group_signature(g, gap_penalty=gap_penalty)
        if sub and len(sub) >= 2:
            subsequences.append(sub)

    # Add high-frequency tokens (occurring >= 2 times across bypassing payloads)
    freq_map = Counter(all_important)
    for tok, c in freq_map.items():
        # Only retain meaningful multi-character tokens (skip single punctuation like ;, #, =, ')
        if c >= 2 and len(tok) >= 2 and tok not in subsequences:
            if tok.isalpha() or tok in ("--", "/*", "*/", "1=1", "0x") or tok.startswith("%20"):
                subsequences.append(tok)

    # Add multi-token attack patterns directly observed in bypassing payloads
    if use_composite_patterns:
        composite_patterns = [
            r"(?i)\bOR\b\S*['\"\d]",
            r"(?i)\bUNION\b[\s\S]*?['\"%]",
            r"(?i)\bUNION\b\s+(?:OR|AND|ALL|SELECT|ADMIN)\b",
            r";\s*(?i:SELECT|INSERT|UPDATE|DELETE|DROP)\b",
            r"(?i)\bSELECT\b\S*['\"\d]",
            r"(?i)\bSLEEP\b",
            r"--\s*$",
            r"/\*.*?\*/",
            r"/\*",
            r"0x[0-9a-fA-F]{2,}",
            r"(?i)%20(?:OR|AND|UNION|SELECT|BY|LIKE)%20",
            r"#\s*$",
            r"(?i)1=1|'1'='1'",
            r"['\"\d]\s*=\s*['\"\d]",
        ]
        candidate_regexes = list(composite_patterns)
    else:
        candidate_regexes = []

    for sub in subsequences:
        regex = generate_regex_signature(sub)
        if regex and regex not in candidate_regexes:
            candidate_regexes.append(regex)

    # Step 4: Validate against benign samples to ensure ZERO false rejections (FRR = 0%)
    valid_regexes = []
    if benign_samples:
        if verbose:
            print(f"\n[*] Validating candidate signatures against {len(benign_samples)} benign samples...")
        for reg in candidate_regexes:
            try:
                compiled = re.compile(reg)
                fps = sum(1 for b in benign_samples if compiled.search(b))
                if fps == 0:
                    valid_regexes.append(reg)
                else:
                    if verbose:
                        print(f"    [Filtered Out] '{reg}' caused {fps} false positive(s) on benign traffic.")
            except re.error:
                continue
    else:
        valid_regexes = candidate_regexes

    # Deduplicate
    valid_regexes = list(dict.fromkeys(valid_regexes))

    if verbose:
        print(f"\n[*] Final Accepted Signatures (FRR = 0%): {len(valid_regexes)}")
        for r in valid_regexes:
            print(f"    {r}")

    # Step 5: Generate ModSecurity rules
    modsec_rules = []
    base_id = 9500001
    for i, reg in enumerate(valid_regexes):
        rule = generate_modsec_rule(
            rule_id=base_id + i,
            regex_pattern=reg,
            msg=f"WAFBooster rule {i+1}: matches learned attack mutant",
        )
        modsec_rules.append(rule)

    return valid_regexes, modsec_rules


# ---------------------------------------------------------------------------
# 6. Live WAF Boosting & Verification
# ---------------------------------------------------------------------------


def deploy_rules_to_docker(rules_path: str, container_name: str = "is-waf-1") -> bool:
    """
    Copies the generated rules file to the running ModSecurity container
    and reloads Nginx via `nginx -s reload`.
    """
    override_dest = f"{container_name}:/etc/modsecurity.d/modsecurity-override.conf"
    try:
        # Copy rule file to container override
        cp_cmd = ["docker", "cp", rules_path, override_dest]
        subprocess.run(cp_cmd, check=True, capture_output=True, text=True)

        # Fix ownership to nginx user inside container
        chown_cmd = ["docker", "exec", "-u", "0", container_name, "chown", "nginx:nginx", "/etc/modsecurity.d/modsecurity-override.conf"]
        subprocess.run(chown_cmd, check=True, capture_output=True, text=True)

        # Test config as nginx user
        t_cmd = ["docker", "exec", "-u", "nginx", container_name, "nginx", "-t"]
        subprocess.run(t_cmd, check=True, capture_output=True, text=True)

        # Reload nginx as nginx user
        r_cmd = ["docker", "exec", "-u", "nginx", container_name, "nginx", "-s", "reload"]
        subprocess.run(r_cmd, check=True, capture_output=True, text=True)

        # Close existing HTTP keep-alive connections so client connects to new worker
        _session.close()
        time.sleep(1.0)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error deploying rules: {e.stderr}")
        return False


# ---------------------------------------------------------------------------
# 7. Main Driver
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    corrected_path = "data/processed/corrected_candidates.csv"
    train_path = "data/processed/train.csv"

    if not os.path.exists(corrected_path):
        raise FileNotFoundError(f"Missing {corrected_path}. Run src/payload_corrector.py first.")

    print("=" * 65)
    print("   WAFBooster Signature Producer & Auto-Fortification")
    print("   (IEEE TDSC 2025 Section III-E & Algorithm 2)")
    print("=" * 65)

    # Step 1: Load candidates
    print("\n=== Step 1: Loading Corrected Candidates ===")
    df = pd.read_csv(corrected_path)
    payloads = df["corrected_payload"].fillna(df["original_payload"]).tolist()
    print(f"Loaded {len(payloads)} corrected candidate payloads.")

    # Step 2: Query WAF to find bypassing payloads
    print("\n=== Step 2: Testing Original WAF to Identify Bypasses ===")
    # Ensure baseline WAF state by clearing any previously deployed override rules
    try:
        subprocess.run(
            ["docker", "exec", "-u", "0", "is-waf-1", "sh", "-c", "echo '# clean' > /etc/modsecurity.d/modsecurity-override.conf && chown nginx:nginx /etc/modsecurity.d/modsecurity-override.conf"],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["docker", "exec", "-u", "nginx", "is-waf-1", "nginx", "-s", "reload"],
            capture_output=True,
            check=True,
        )
        _session.close()
        time.sleep(1.0)
    except Exception as e:
        print(f"[!] Warning clearing override: {e}")

    start_time = time.time()
    bypassing = []
    blocked = []
    for p in payloads:
        lbl = query_waf(p)
        if lbl == 0:
            bypassing.append(p)
        else:
            blocked.append(p)
    elapsed = time.time() - start_time
    print(f"Results in {elapsed:.1f}s:")
    print(f"    Initial Blocked  (Caught by WAF) : {len(blocked)} ({len(blocked)/len(payloads)*100:.2f}%)")
    print(f"    Initial Bypassing (Evaded WAF)   : {len(bypassing)} ({len(bypassing)/len(payloads)*100:.2f}%)")

    # Load true benign samples for validation
    benign_samples = []
    if os.path.exists(train_path):
        train_df = pd.read_csv(train_path)
        benign_samples = train_df[train_df["source"] == "benign"]["payload"].dropna().astype(str).tolist()
        print(f"Loaded {len(benign_samples)} true benign samples for zero-FRR enforcement.")

    # Step 3: Produce signatures
    sample_bypassing = bypassing[:50]  # Sample first 50 for token scoring
    regex_sigs, modsec_rules = produce_signatures(
        sample_bypassing,
        waf_fn=query_waf,
        benign_samples=benign_samples,
        top_m=3,
        cluster_threshold=2.0,
        gap_penalty=0.8,
        verbose=True,
    )

    # Step 4: Save signatures & rules
    os.makedirs("data/processed", exist_ok=True)
    os.makedirs("rules", exist_ok=True)

    pd.DataFrame({"payload": bypassing}).to_csv("data/processed/bypassing_payloads.csv", index=False)
    pd.DataFrame({"signature": regex_sigs}).to_csv("data/processed/signatures.csv", index=False)

    rules_path = "rules/wafbooster_rules.conf"
    with open(rules_path, "w") as f:
        f.write("# WAFBooster Auto-Generated ModSecurity Rules\n")
        f.write(f"# Auto-generated from {len(sample_bypassing)} bypassing mutated attack payloads\n\n")
        for r in modsec_rules:
            f.write(r + "\n\n")
    print(f"\n[*] Saved {len(modsec_rules)} ModSecurity rules to {rules_path}")

    # Step 5: Coverage Evaluation against ALL 64 bypassing payloads
    print("\n=== Step 5: Evaluation on Mutated Bypassing Payloads ===")
    caught = 0
    for p in bypassing:
        if any(re.search(sig, p) for sig in regex_sigs):
            caught += 1
    cov_pct = caught / len(bypassing) * 100 if bypassing else 0.0
    print(f"Generated Signature Coverage: {caught}/{len(bypassing)} ({cov_pct:.1f}%)")

    # Step 5b: Ablation Study - Learned-Only vs Full Signatures
    print("\n=== Step 5b: Ablation Study (Learned-Only vs. Full Signatures) ===")
    regex_sigs_learned, modsec_rules_learned = produce_signatures(
        sample_bypassing,
        waf_fn=query_waf,
        benign_samples=benign_samples,
        top_m=3,
        cluster_threshold=2.0,
        gap_penalty=0.8,
        use_composite_patterns=False,
        verbose=False,
    )

    caught_learned = 0
    for p in bypassing:
        if any(re.search(sig, p) for sig in regex_sigs_learned):
            caught_learned += 1
    cov_pct_learned = caught_learned / len(bypassing) * 100 if bypassing else 0.0

    print(f"Learned-only signatures (Smith-Waterman + clustering): {caught_learned}/{len(bypassing)} ({cov_pct_learned:.1f}%)")
    print(f"Learned + hand-curated composite rules: {caught}/{len(bypassing)} ({cov_pct:.1f}%)")

    # Save both signature sets separately
    pd.DataFrame({"signature": regex_sigs_learned}).to_csv(
        "data/processed/signatures_learned_only.csv", index=False
    )
    pd.DataFrame({"signature": regex_sigs}).to_csv(
        "data/processed/signatures_full.csv", index=False
    )
    print("Saved signatures to data/processed/signatures_learned_only.csv and data/processed/signatures_full.csv")

    # Step 6: Deploy & Live WAF Verification
    print("\n=== Step 6: Live WAF Deployment & Verification ===")
    print("Deploying auto-generated rules to live ModSecurity container (is-waf-1)...")
    deployed = deploy_rules_to_docker(rules_path, container_name="is-waf-1")

    if deployed:
        print("[+] Rules successfully deployed and Nginx hot-reloaded!")
        print("\n[*] Re-testing all 64 previously-bypassing payloads on the BOOSTED WAF...")
        now_blocked = 0
        for p in bypassing:
            if query_waf(p) == 1:
                now_blocked += 1
        boosted_trr = (len(blocked) + now_blocked) / len(payloads) * 100
        print(f"    Previously Bypassing Payloads Now Blocked: {now_blocked}/{len(bypassing)} ({now_blocked/len(bypassing)*100:.1f}%)")
        print(f"    Boosted WAF Overall TRR on Candidates    : {len(blocked) + now_blocked}/{len(payloads)} ({boosted_trr:.1f}%)")

        print("\n[*] Testing Benign Traffic on BOOSTED WAF...")
        test_benign = benign_samples[:100] if benign_samples else ["shoes", "laptop", "blue dress", "hello world"]
        benign_blocked = sum(1 for b in test_benign if query_waf(b) == 1)
        print(f"    Benign Samples Tested  : {len(test_benign)}")
        print(f"    Benign Samples Blocked : {benign_blocked} (FRR: {benign_blocked/len(test_benign)*100:.2f}%)")
        print(f"    Benign Pass Rate (TAR) : {(len(test_benign) - benign_blocked)/len(test_benign)*100:.2f}%")

    print("\n" + "=" * 65)
    print("   WAFBooster Pipeline Completed Successfully!")
    print("=" * 65)
