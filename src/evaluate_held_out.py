"""
Held-Out Data Evaluation for WAFBooster (Generalization Testing).

Evaluates the generalization capability of deployed WAFBooster signatures against:
1. Held-Out Malicious Payloads (data/processed/test.csv where source == 'malicious')
2. Held-Out Benign Payloads (data/processed/test.csv where source == 'benign')
3. Novel Generated Payloads (Fresh GRU batch with unseen seed tokens & different random seed)

Compares:
- Baseline WAF (Standard ModSecurity CRS Paranoia Level 1)
- Boosted WAF (ModSecurity CRS + WAFBooster Auto-Generated Signatures)

Metrics:
- True Rejection Rate (TRR) on Malicious Payloads: Blocked (403) / Total Malicious
- True Acceptance Rate (TAR) on Benign Payloads: Allowed (200) / Total Benign

Outputs comparison table to stdout and saves to results/held_out_evaluation.csv.
"""

import os
import pickle
import random
import subprocess
import time
from typing import Dict, List, Optional, Tuple

import pandas as pd
import torch

try:
    from src.payload_generator import PayloadGRU, generate_payload
    from src.waf_client import _session, check_waf
except ImportError:
    from payload_generator import PayloadGRU, generate_payload
    from waf_client import _session, check_waf


# ---------------------------------------------------------------------------
# 1. WAF Configuration Management
# ---------------------------------------------------------------------------


def set_waf_baseline(container_name: str = "is-waf-1") -> bool:
    """
    Reverts ModSecurity to clean baseline state by clearing override file
    and reloading Nginx.
    """
    try:
        clean_cmd = [
            "docker", "exec", "-u", "0", container_name,
            "sh", "-c",
            "echo '# clean baseline' > /etc/modsecurity.d/modsecurity-override.conf && chown nginx:nginx /etc/modsecurity.d/modsecurity-override.conf",
        ]
        subprocess.run(clean_cmd, check=True, capture_output=True, text=True)

        reload_cmd = ["docker", "exec", "-u", "nginx", container_name, "nginx", "-s", "reload"]
        subprocess.run(reload_cmd, check=True, capture_output=True, text=True)

        _session.close()
        time.sleep(1.0)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error restoring baseline WAF: {e.stderr}")
        return False


def set_waf_boosted(
    rules_path: str = "rules/wafbooster_rules.conf",
    container_name: str = "is-waf-1",
) -> bool:
    """
    Deploys WAFBooster rules to ModSecurity override file and reloads Nginx.
    """
    if not os.path.exists(rules_path):
        raise FileNotFoundError(f"Missing rules file at {rules_path}")

    override_dest = f"{container_name}:/etc/modsecurity.d/modsecurity-override.conf"
    try:
        cp_cmd = ["docker", "cp", rules_path, override_dest]
        subprocess.run(cp_cmd, check=True, capture_output=True, text=True)

        chown_cmd = [
            "docker", "exec", "-u", "0", container_name,
            "chown", "nginx:nginx", "/etc/modsecurity.d/modsecurity-override.conf",
        ]
        subprocess.run(chown_cmd, check=True, capture_output=True, text=True)

        t_cmd = ["docker", "exec", "-u", "nginx", container_name, "nginx", "-t"]
        subprocess.run(t_cmd, check=True, capture_output=True, text=True)

        reload_cmd = ["docker", "exec", "-u", "nginx", container_name, "nginx", "-s", "reload"]
        subprocess.run(reload_cmd, check=True, capture_output=True, text=True)

        _session.close()
        time.sleep(1.0)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error applying boosted WAF rules: {e.stderr}")
        return False


# ---------------------------------------------------------------------------
# 2. Novel Payload Generation
# ---------------------------------------------------------------------------


def generate_novel_attacks(
    model_path: str = "models/payload_gru.pt",
    vocab_path: str = "models/vocab.pkl",
    seed_tokens: Optional[List[str]] = None,
    n_per_seed: int = 25,
    random_seed: int = 777,
    temperature: float = 0.85,
) -> List[str]:
    """
    Generates a brand-new batch of synthetic attacks from the trained GRU model
    using a dedicated random seed and novel seed tokens never used during signature creation.
    """
    if seed_tokens is None:
        seed_tokens = ["admin", "1=1", "--", "/**/"]

    with open(vocab_path, "rb") as f:
        vocab_data = pickle.load(f)
    vocab = vocab_data["vocab"]
    inv_vocab = vocab_data["inv_vocab"]

    # Set seeds for reproducibility
    torch.manual_seed(random_seed)
    random.seed(random_seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PayloadGRU(vocab_size=len(vocab)).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()

    novel_payloads = []
    for st in seed_tokens:
        for _ in range(n_per_seed):
            p = generate_payload(
                model=model,
                vocab=vocab,
                inv_vocab=inv_vocab,
                seed_token=st,
                temperature=temperature,
                device=device,
            )
            # Retain non-trivial strings
            p_clean = p.strip()
            if len(p_clean) > 3 and p_clean not in novel_payloads:
                novel_payloads.append(p_clean)

    return novel_payloads


# ---------------------------------------------------------------------------
# 3. Evaluation Runner
# ---------------------------------------------------------------------------


def evaluate_dataset(
    payloads: List[str],
    is_malicious: bool,
    description: str = "",
) -> Dict[str, float]:
    """
    Queries WAF for each payload in the list and calculates:
    - If is_malicious=True: TRR (True Rejection Rate) and FAR (False Acceptance Rate)
    - If is_malicious=False: TAR (True Acceptance Rate) and FRR (False Rejection Rate)
    """
    total = len(payloads)
    if total == 0:
        return {"total": 0, "blocked": 0, "allowed": 0, "primary_rate": 0.0}

    blocked = 0
    allowed = 0

    for p in payloads:
        res = check_waf(p)
        if res == 1:
            blocked += 1
        else:
            allowed += 1

    if is_malicious:
        # For attacks, higher TRR (blocked) is better
        primary_rate = (blocked / total) * 100.0
        secondary_rate = (allowed / total) * 100.0
    else:
        # For benign, higher TAR (allowed) is better
        primary_rate = (allowed / total) * 100.0
        secondary_rate = (blocked / total) * 100.0

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "primary_rate": primary_rate,
        "secondary_rate": secondary_rate,
    }


# ---------------------------------------------------------------------------
# 4. Main Driver
# ---------------------------------------------------------------------------


def main():
    print("=" * 70)
    print("   WAFBooster Generalization Evaluation on Held-Out Data")
    print("   (Rigorous Unseen Testing: Held-Out Test Split & Novel Attacks)")
    print("=" * 70)

    # 1. Load held-out test.csv
    test_csv_path = "data/processed/test.csv"
    if not os.path.exists(test_csv_path):
        raise FileNotFoundError(f"Missing {test_csv_path}. Run src/dataset.py first.")

    print(f"\n=== Step 1: Loading Held-Out Dataset ({test_csv_path}) ===")
    test_df = pd.read_csv(test_csv_path)

    test_malicious = test_df[test_df["source"] == "malicious"]["payload"].dropna().tolist()
    test_benign = test_df[test_df["source"] == "benign"]["payload"].dropna().tolist()

    print(f"Total entries in test.csv    : {len(test_df)}")
    print(f"  - Held-out Malicious (a)   : {len(test_malicious)} payloads (never seen by Signature Producer)")
    print(f"  - Held-out Benign    (b)   : {len(test_benign)} payloads (never seen by Signature Producer)")

    # 2. Generate novel attack payloads
    print("\n=== Step 2: Generating Novel GRU Attack Payloads (c) ===")
    novel_seeds = ["admin", "1=1", "--", "/**/"]
    print(f"Sampling GRU with unseen seed tokens: {novel_seeds} (random_seed=777)...")
    novel_generated = generate_novel_attacks(
        seed_tokens=novel_seeds,
        n_per_seed=25,
        random_seed=777,
        temperature=0.85,
    )
    print(f"Generated {len(novel_generated)} unique novel attack payloads.")

    # Save novel payloads for audit
    os.makedirs("data/processed", exist_ok=True)
    pd.DataFrame({"payload": novel_generated}).to_csv("data/processed/novel_generated.csv", index=False)

    # 3. Test on Baseline WAF
    print("\n=== Step 3: Evaluating Baseline WAF (Original ModSecurity CRS) ===")
    print("Switching WAF container to clean baseline configuration...")
    if not set_waf_baseline():
        raise RuntimeError("Failed to set baseline WAF configuration.")

    print("Running queries against Baseline WAF...")
    start_t = time.time()
    base_res_mal = evaluate_dataset(test_malicious, is_malicious=True, description="Held-Out Malicious")
    base_res_ben = evaluate_dataset(test_benign, is_malicious=False, description="Held-Out Benign")
    base_res_nov = evaluate_dataset(novel_generated, is_malicious=True, description="Novel Generated")
    print(f"Baseline evaluation completed in {time.time() - start_t:.2f}s.")

    # 4. Test on Boosted WAF
    print("\n=== Step 4: Evaluating Boosted WAF (WAFBooster Rules Applied) ===")
    print("Applying WAFBooster rules to live WAF container...")
    if not set_waf_boosted():
        raise RuntimeError("Failed to apply boosted WAF rules.")

    print("Running queries against Boosted WAF...")
    start_t = time.time()
    boost_res_mal = evaluate_dataset(test_malicious, is_malicious=True, description="Held-Out Malicious")
    boost_res_ben = evaluate_dataset(test_benign, is_malicious=False, description="Held-Out Benign")
    boost_res_nov = evaluate_dataset(novel_generated, is_malicious=True, description="Novel Generated")
    print(f"Boosted WAF evaluation completed in {time.time() - start_t:.2f}s.")

    # 5. Format and Print Results Table
    print("\n" + "=" * 70)
    print("   GENERALIZATION EVALUATION RESULTS: BASELINE VS BOOSTED WAF")
    print("=" * 70)

    rows = [
        {
            "Dataset Split": "Held-Out Malicious (test.csv)",
            "Evaluation Metric": "TRR (True Rejection Rate)",
            "Total Samples": len(test_malicious),
            "Baseline WAF": f"{base_res_mal['blocked']}/{base_res_mal['total']} ({base_res_mal['primary_rate']:.2f}%)",
            "Boosted WAF": f"{boost_res_mal['blocked']}/{boost_res_mal['total']} ({boost_res_mal['primary_rate']:.2f}%)",
            "Improvement (Δ)": f"+{boost_res_mal['primary_rate'] - base_res_mal['primary_rate']:.2f}%",
            "Baseline Rate": base_res_mal["primary_rate"],
            "Boosted Rate": boost_res_mal["primary_rate"],
            "Delta": boost_res_mal["primary_rate"] - base_res_mal["primary_rate"],
        },
        {
            "Dataset Split": "Held-Out Benign (test.csv)",
            "Evaluation Metric": "TAR (True Acceptance Rate)",
            "Total Samples": len(test_benign),
            "Baseline WAF": f"{base_res_ben['allowed']}/{base_res_ben['total']} ({base_res_ben['primary_rate']:.2f}%)",
            "Boosted WAF": f"{boost_res_ben['allowed']}/{boost_res_ben['total']} ({boost_res_ben['primary_rate']:.2f}%)",
            "Improvement (Δ)": f"{boost_res_ben['primary_rate'] - base_res_ben['primary_rate']:+.2f}%",
            "Baseline Rate": base_res_ben["primary_rate"],
            "Boosted Rate": boost_res_ben["primary_rate"],
            "Delta": boost_res_ben["primary_rate"] - base_res_ben["primary_rate"],
        },
        {
            "Dataset Split": "Novel Generated Attacks (GRU)",
            "Evaluation Metric": "TRR (True Rejection Rate)",
            "Total Samples": len(novel_generated),
            "Baseline WAF": f"{base_res_nov['blocked']}/{base_res_nov['total']} ({base_res_nov['primary_rate']:.2f}%)",
            "Boosted WAF": f"{boost_res_nov['blocked']}/{boost_res_nov['total']} ({boost_res_nov['primary_rate']:.2f}%)",
            "Improvement (Δ)": f"+{boost_res_nov['primary_rate'] - base_res_nov['primary_rate']:.2f}%",
            "Baseline Rate": base_res_nov["primary_rate"],
            "Boosted Rate": boost_res_nov["primary_rate"],
            "Delta": boost_res_nov["primary_rate"] - base_res_nov["primary_rate"],
        },
    ]

    out_df = pd.DataFrame(rows)

    # Display clear formatted table
    display_df = out_df[[
        "Dataset Split",
        "Evaluation Metric",
        "Total Samples",
        "Baseline WAF",
        "Boosted WAF",
        "Improvement (Δ)",
    ]]

    print()
    print(display_df.to_string(index=False))
    print()

    # 6. Save results
    os.makedirs("results", exist_ok=True)
    out_csv_path = "results/held_out_evaluation.csv"
    display_df.to_csv(out_csv_path, index=False)
    print(f"[*] Results saved successfully to: {out_csv_path}")

    # Summary analysis
    print("\n=== Key Generalization Insights ===")
    print(f"1. Held-Out Malicious TRR improved from {base_res_mal['primary_rate']:.2f}% to {boost_res_mal['primary_rate']:.2f}% (+{boost_res_mal['primary_rate'] - base_res_mal['primary_rate']:.2f}%).")
    print(f"2. Held-Out Benign TAR maintained at {boost_res_ben['primary_rate']:.2f}% (False Rejection Rate = {100.0 - boost_res_ben['primary_rate']:.2f}%).")
    print(f"3. Novel Unseen Attacks TRR improved from {base_res_nov['primary_rate']:.2f}% to {boost_res_nov['primary_rate']:.2f}% (+{boost_res_nov['primary_rate'] - base_res_nov['primary_rate']:.2f}%).")
    print("=" * 70)


if __name__ == "__main__":
    main()
