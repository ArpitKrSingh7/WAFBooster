"""
Payload Generator for WAF Testing (WAFBooster Section III-C).

Implements:
1. Vocabulary builder using the SQL-aware tokenizer from shadow_model.py.
2. Sequence encoding with <START>, <END>, and <PAD> tokens.
3. PayloadGRU recurrent neural network for character/token-level language modeling.
4. Self-supervised next-token training with StepLR scheduler.
5. Temperature-scaled autoregressive generation of synthetic SQLi payloads.
6. Batch candidate generation across canonical SQLi seed prefixes.
"""

import os
import pickle
import warnings
from typing import Dict, List, Optional, Tuple

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

try:
    from src.shadow_model import tokenize
except ImportError:
    from shadow_model import tokenize

warnings.filterwarnings("ignore")

# Punctuation tokens around which no extra spaces should be inserted
PUNCT_TOKENS = {"'", "--", "/*", "*/", "=", "(", ")", ",", ";", "#"}


def build_vocab(payloads: List[str]) -> Tuple[Dict[str, int], Dict[int, str]]:
    """
    Tokenizes all payloads with tokenize() from shadow_model.py, builds token-to-int
    and int-to-token mappings. Special tokens: <PAD>=0, <START>=1, <END>=2, <UNK>=3.
    """
    special_tokens = ["<PAD>", "<START>", "<END>", "<UNK>"]
    vocab = {tok: idx for idx, tok in enumerate(special_tokens)}
    inv_vocab = {idx: tok for idx, tok in enumerate(special_tokens)}

    unique_tokens = set()
    for p in payloads:
        unique_tokens.update(tokenize(p))

    for tok in sorted(unique_tokens):
        if tok not in vocab:
            idx = len(vocab)
            vocab[tok] = idx
            inv_vocab[idx] = tok

    return vocab, inv_vocab


def encode_payload(payload: str, vocab: Dict[str, int], max_len: int = 30) -> List[int]:
    """
    Tokenizes payload, maps to ints via vocab (unknown tokens map to <UNK>),
    prepends <START>, appends <END>, and pads/truncates to max_len.
    """
    tokens = tokenize(payload)
    unk_idx = vocab.get("<UNK>", 3)
    start_idx = vocab.get("<START>", 1)
    end_idx = vocab.get("<END>", 2)
    pad_idx = vocab.get("<PAD>", 0)

    token_ids = [vocab.get(t, unk_idx) for t in tokens]
    full_seq = [start_idx] + token_ids + [end_idx]

    if len(full_seq) > max_len:
        full_seq = full_seq[:max_len]
    elif len(full_seq) < max_len:
        full_seq = full_seq + [pad_idx] * (max_len - len(full_seq))

    return full_seq


class PayloadGRU(nn.Module):
    """
    Autoregressive GRU for synthetic payload generation matching WAFBooster Section III-C:
    Embedding(vocab_size, 128) -> GRU(128, hidden_size=256, batch_first=True)
    -> Dropout(0.3) -> Linear(256, vocab_size)
    """

    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = 128,
        hidden_size: int = 256,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.gru = nn.GRU(embedding_dim, hidden_size, batch_first=True)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, vocab_size)

    def forward(
        self,
        x: torch.Tensor,
        hidden: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        embeds = self.embedding(x)
        out, hidden = self.gru(embeds, hidden)
        out = self.dropout(out)
        logits = self.fc(out)
        return logits, hidden


def train_generator(
    malicious_payloads: List[str],
    vocab: Dict[str, int],
    epochs: int = 50,
    lr: float = 0.001,
    batch_size: int = 32,
    device: Optional[torch.device] = None,
) -> PayloadGRU:
    """
    Trains PayloadGRU via self-supervised next-token prediction:
    input tokens[0:-1], target tokens[1:].
    Uses CrossEntropyLoss(ignore_index=<PAD>), Adam optimizer, and StepLR (gamma=0.5 every 10 epochs).
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Encode all payloads
    encoded_list = [encode_payload(p, vocab, max_len=30) for p in malicious_payloads]
    tensor_data = torch.tensor(encoded_list, dtype=torch.long)

    # Next-token prediction: input [:-1], target [1:]
    X = tensor_data[:, :-1]
    Y = tensor_data[:, 1:]

    dataset = TensorDataset(X, Y)
    train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    vocab_size = len(vocab)
    model = PayloadGRU(vocab_size=vocab_size).to(device)

    pad_idx = vocab.get("<PAD>", 0)
    criterion = nn.CrossEntropyLoss(ignore_index=pad_idx)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)

    print(f"\n[*] Training PayloadGRU on {device} (Samples: {len(malicious_payloads)}, Epochs: {epochs}, Batch Size: {batch_size})...")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0

        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            logits, _ = model(bx)
            loss = criterion(logits.view(-1, vocab_size), by.view(-1))
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(by)

        scheduler.step()
        epoch_loss = total_loss / len(malicious_payloads)

        if epoch % 5 == 0 or epoch == 1 or epoch == epochs:
            current_lr = scheduler.get_last_lr()[0]
            print(f"Epoch {epoch:2d}/{epochs:2d} | Train Loss: {epoch_loss:.4f} | LR: {current_lr:.6f}")

    return model


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
        # Skip space if either current or previous token is punctuation / url-escaped / hex prefix
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


def generate_payload(
    model: nn.Module,
    vocab: Dict[str, int],
    inv_vocab: Dict[int, str],
    seed_token: str = "'",
    max_len: int = 30,
    device: Optional[torch.device] = None,
    temperature: float = 0.8,
) -> str:
    """
    Start from <START> + seed_token's encoding, autoregressively sample next token
    from softmax(logits/temperature) (stopping at <END> or max_len).
    Joins tokens back into a properly formatted SQL string.
    """
    if device is None:
        device = next(model.parameters()).device

    model.eval()
    start_id = vocab["<START>"]
    seed_id = vocab.get(seed_token, vocab.get("<UNK>", 3))

    generated_token_ids = [seed_id]
    input_tensor = torch.tensor([[start_id, seed_id]], dtype=torch.long, device=device)
    hidden = None

    with torch.no_grad():
        for _ in range(max_len):
            logits, hidden = model(input_tensor, hidden)
            last_logits = logits[:, -1, :] / max(temperature, 1e-5)

            # Mask out non-generable special tokens
            for special in ["<PAD>", "<START>", "<UNK>"]:
                if special in vocab:
                    last_logits[:, vocab[special]] = -float("inf")

            probs = torch.softmax(last_logits, dim=-1)
            next_token_id = torch.multinomial(probs, num_samples=1).item()

            if next_token_id == vocab["<END>"]:
                break

            generated_token_ids.append(next_token_id)
            input_tensor = torch.tensor([[next_token_id]], dtype=torch.long, device=device)

    token_strings = [inv_vocab[tid] for tid in generated_token_ids]
    return _join_tokens(token_strings)


def generate_batch(
    model: nn.Module,
    vocab: Dict[str, int],
    inv_vocab: Dict[int, str],
    seed_tokens: Optional[List[str]] = None,
    n_per_seed: int = 15,
    device: Optional[torch.device] = None,
    temperature: float = 0.8,
) -> List[str]:
    """
    For each seed in seed_tokens, generates n_per_seed payloads, dedupes, and returns a flat list.
    """
    if seed_tokens is None:
        seed_tokens = ["'", "1", "admin", "UNION", "SELECT", "OR"]

    if device is None:
        device = next(model.parameters()).device

    candidates = set()
    for seed in seed_tokens:
        for _ in range(n_per_seed):
            p = generate_payload(
                model=model,
                vocab=vocab,
                inv_vocab=inv_vocab,
                seed_token=seed,
                max_len=30,
                device=device,
                temperature=temperature,
            )
            if p and p.strip():
                candidates.add(p.strip())

    return sorted(candidates)


if __name__ == "__main__":
    train_path = "data/processed/train.csv"
    if not os.path.exists(train_path):
        raise FileNotFoundError(f"Missing {train_path}. Run src/dataset.py first.")

    print("=== Step 1: Loading Malicious Payloads from Train Set ===")
    train_df = pd.read_csv(train_path)
    malicious_df = train_df[train_df["source"] == "malicious"]
    malicious_payloads = malicious_df["payload"].dropna().tolist()
    print(f"Loaded {len(malicious_payloads)} malicious payloads for generator training.")

    print("\n=== Step 2: Building Vocabulary ===")
    vocab, inv_vocab = build_vocab(malicious_payloads)
    print(f"Vocabulary size: {len(vocab)} unique tokens (including <PAD>, <START>, <END>, <UNK>)")

    print("\n=== Step 3: Training PayloadGRU ===")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Compute device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")
    gru_model = train_generator(
        malicious_payloads=malicious_payloads,
        vocab=vocab,
        epochs=50,
        lr=0.001,
        batch_size=32,
        device=device,
    )

    print("\n=== Step 4: Generating Candidate Payloads ===")
    seeds = ["'", "1", "admin", "UNION", "SELECT", "OR"]
    # n_per_seed=60 across 6 seeds generates ~360 raw, resulting in ~300 unique candidates
    candidates = generate_batch(
        model=gru_model,
        vocab=vocab,
        inv_vocab=inv_vocab,
        seed_tokens=seeds,
        n_per_seed=60,
        device=device,
        temperature=0.8,
    )
    print(f"Generated {len(candidates)} unique candidate payloads.")

    print("\n=== Step 5: First 15 Generated Candidates ===")
    for idx, c in enumerate(candidates[:15], 1):
        print(f"  {idx:2d}. {c}")

    print("\n=== Step 6: Saving Generated Candidates & Model Artifacts ===")
    os.makedirs("data/processed", exist_ok=True)
    candidates_csv = "data/processed/generated_candidates.csv"
    pd.DataFrame({"payload": candidates}).to_csv(candidates_csv, index=False)
    print(f"Saved candidate payloads to: {candidates_csv}")

    os.makedirs("models", exist_ok=True)
    gru_save_path = "models/payload_gru.pt"
    vocab_save_path = "models/vocab.pkl"

    torch.save(gru_model.state_dict(), gru_save_path)
    with open(vocab_save_path, "wb") as f:
        pickle.dump({"vocab": vocab, "inv_vocab": inv_vocab}, f)

    print(f"Saved PayloadGRU weights to: {gru_save_path}")
    print(f"Saved vocab/inv_vocab to:    {vocab_save_path}")
