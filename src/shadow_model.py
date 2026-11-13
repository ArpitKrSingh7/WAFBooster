"""
Shadow Model Builder for WAF Testing (WAFBooster Section III-B).

Implements:
1. SQL-aware tokenizer treating SQL symbols as distinct tokens.
2. Word2Vec embedding model (CBOW) for payload token representations.
3. Payload vector aggregation (averaging token vectors).
4. ShadowCNN PyTorch model (Conv1d -> ReLU -> MaxPool1d -> Dropout -> Linear -> ReLU -> Linear).
5. Training loop with CrossEntropyLoss and class-weight balancing.
6. Evaluation computing Accuracy, TRR (True Rejection Rate), and TAR (True Acceptance Rate).
"""

import copy
import os
import re
import warnings
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from gensim.models import Word2Vec

warnings.filterwarnings("ignore")

# Tokenizer pattern: SQL special sequences/tokens and words
TOKEN_PATTERN = re.compile(r"0x|--|/\*|\*/|['=(),;]|\w+|[^\s\w'=(),;]")


def tokenize(payload: str) -> List[str]:
    """
    Split on whitespace and treat SQL special characters/sequences as their own tokens:
    ', =, --, /*, */, (, ), ,, ;, 0x
    (e.g., "admin'--" -> ["admin", "'", "--"]).
    """
    if not isinstance(payload, str):
        payload = str(payload)
    return TOKEN_PATTERN.findall(payload)


def train_word2vec(payloads: List[str], vector_size: int = 128) -> Word2Vec:
    """
    Tokenizes all payloads using tokenize(), trains Word2Vec
    (CBOW: sg=0, window=5, min_count=1).
    """
    sentences = [tokenize(p) for p in payloads]
    model = Word2Vec(
        sentences=sentences,
        vector_size=vector_size,
        window=5,
        min_count=1,
        sg=0,  # CBOW
        workers=4,
        seed=42,
        epochs=15,
    )
    return model


def payload_to_vector(payload: str, w2v_model: Word2Vec) -> np.ndarray:
    """
    Tokenizes payload, looks up each token's vector, and averages them into a
    single vector_size-dimensional vector (returns zero vector if no tokens found).
    """
    tokens = tokenize(payload)
    vectors = [w2v_model.wv[t] for t in tokens if t in w2v_model.wv]
    if not vectors:
        return np.zeros(w2v_model.vector_size, dtype=np.float32)
    return np.mean(vectors, axis=0).astype(np.float32)


class ShadowCNN(nn.Module):
    """
    Convolutional Neural Network for payload classification matching WAFBooster Section III-B:
    Input: (batch, 128) -> unsqueeze to (batch, 1, 128) for Conv1d
    Conv1d(1, 32, kernel_size=3, padding=1) -> ReLU -> MaxPool1d(2) -> Dropout(0.3)
    -> Flatten -> Linear(2048, 256) -> ReLU -> Linear(256, 2)
    """

    def __init__(self, in_features: int = 128, num_classes: int = 2):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
        self.relu1 = nn.ReLU()
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.dropout = nn.Dropout(0.3)
        self.fc1 = nn.Linear(32 * (in_features // 2), 256)
        self.relu2 = nn.ReLU()
        self.fc2 = nn.Linear(256, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if x.dim() == 2:
            x = x.unsqueeze(1)
        x = self.conv1(x)
        x = self.relu1(x)
        x = self.pool(x)
        x = self.dropout(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        x = self.relu2(x)
        logits = self.fc2(x)
        return logits


def train_shadow_model(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    w2v_model: Word2Vec,
    epochs: int = 50,
    lr: float = 0.003,
    batch_size: int = 32,
    device: Optional[torch.device] = None,
) -> ShadowCNN:
    """
    Trains ShadowCNN using CrossEntropyLoss and Adam optimizer.
    Converts payloads to Word2Vec averaged vectors.
    Uses class weights inversely proportional to class frequency.
    Tracks validation accuracy each epoch and restores the best epoch's weights.
    Prints train loss and val accuracy each epoch.
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # 1. Feature extraction
    X_train = np.stack([payload_to_vector(p, w2v_model) for p in train_df["payload"]])
    y_train = train_df["waf_label"].values.astype(np.int64)

    X_val = np.stack([payload_to_vector(p, w2v_model) for p in val_df["payload"]])
    y_val = val_df["waf_label"].values.astype(np.int64)

    train_tensor_x = torch.tensor(X_train, dtype=torch.float32)
    train_tensor_y = torch.tensor(y_train, dtype=torch.long)
    train_loader = DataLoader(
        TensorDataset(train_tensor_x, train_tensor_y),
        batch_size=batch_size,
        shuffle=True,
    )

    val_tensor_x = torch.tensor(X_val, dtype=torch.float32).to(device)

    # 2. Class weights: weight inversely proportional to class frequency
    class_counts = np.bincount(y_train)
    weight_0 = 1.0
    weight_1 = float(class_counts[0]) / float(class_counts[1]) if class_counts[1] > 0 else 1.0
    weights = torch.tensor([weight_0, weight_1], dtype=torch.float32).to(device)

    # 3. Model, Criterion, Optimizer
    torch.manual_seed(42)
    model = ShadowCNN(in_features=w2v_model.vector_size, num_classes=2).to(device)
    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    # Tracking best validation accuracy checkpoint
    best_val_acc = -1.0
    best_epoch = 0
    best_model_state = None

    print(f"\n[*] Training ShadowCNN on {device} (Epochs: {epochs}, LR: {lr}, Weights: [{weight_0:.1f}, {weight_1:.2f}])...")

    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0

        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * len(by)

        epoch_loss = running_loss / len(train_df)

        # Validation evaluation
        model.eval()
        with torch.no_grad():
            val_logits = model(val_tensor_x)
            val_preds = val_logits.argmax(dim=1).cpu().numpy()
            val_acc = (val_preds == y_val).mean()

        # Checkpoint if validation accuracy improves
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_epoch = epoch
            best_model_state = copy.deepcopy(model.state_dict())

        if epoch % 5 == 0 or epoch == 1 or epoch == epochs:
            print(
                f"Epoch {epoch:2d}/{epochs:2d} | Train Loss: {epoch_loss:.4f} | "
                f"Val Accuracy: {val_acc * 100:.2f}% (Best: {best_val_acc * 100:.2f}% @ Epoch {best_epoch})"
            )

    # Load best checkpoint weights before returning
    if best_model_state is not None:
        model.load_state_dict(best_model_state)
        print(f"\n[+] Loaded best model checkpoint from Epoch {best_epoch} (Val Accuracy: {best_val_acc * 100:.2f}%)")

    return model


def evaluate_shadow(
    model: nn.Module,
    df: pd.DataFrame,
    w2v_model: Word2Vec,
    device: Optional[torch.device] = None,
) -> Dict[str, float]:
    """
    Evaluates the shadow model on a DataFrame.
    Returns:
        accuracy: (correct predictions) / total rows
        TRR: (malicious payloads where model predicts 1) / (total rows where waf_label==1)
        TAR: (benign-labeled rows i.e. waf_label==0 where model predicts 0) / (total rows where waf_label==0)
    Note: Uses waf_label as ground truth.
    """
    if device is None:
        device = next(model.parameters()).device

    X = np.stack([payload_to_vector(p, w2v_model) for p in df["payload"]])
    y = df["waf_label"].values.astype(np.int64)

    model.eval()
    with torch.no_grad():
        x_tensor = torch.tensor(X, dtype=torch.float32).to(device)
        logits = model(x_tensor)
        preds = logits.argmax(dim=1).cpu().numpy()

    total_rows = len(y)
    accuracy = (preds == y).mean() if total_rows > 0 else 0.0

    # TRR: True Rejection Rate of blocked payloads (waf_label == 1)
    blocked_mask = (y == 1)
    total_blocked = blocked_mask.sum()
    trr = ((preds[blocked_mask] == 1).sum() / total_blocked) if total_blocked > 0 else 0.0

    # TAR: True Acceptance Rate of allowed payloads (waf_label == 0)
    allowed_mask = (y == 0)
    total_allowed = allowed_mask.sum()
    tar = ((preds[allowed_mask] == 0).sum() / total_allowed) if total_allowed > 0 else 0.0

    return {
        "accuracy": float(accuracy),
        "TRR": float(trr),
        "TAR": float(tar),
    }


if __name__ == "__main__":
    train_path = "data/processed/train.csv"
    val_path = "data/processed/val.csv"
    test_path = "data/processed/test.csv"

    for p in [train_path, val_path, test_path]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Missing required dataset file: {p}. Run src/dataset.py first.")

    print("=== Step 1: Loading Processed Datasets ===")
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    print(f"Loaded: Train={len(train_df)} rows, Val={len(val_df)} rows, Test={len(test_df)} rows")

    print("\n=== Step 2: Training Word2Vec Embeddings on Train Payloads ===")
    w2v = train_word2vec(train_df["payload"].tolist(), vector_size=128)
    print(f"Word2Vec trained. Vocab size: {len(w2v.wv)} tokens, Vector size: {w2v.vector_size}")

    print("\n=== Step 3: Training ShadowCNN ===")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Compute device: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")
    # Using lr=0.003 adapted for smaller sample size (prevents gradient oscillation observed at 0.05)
    cnn_model = train_shadow_model(train_df, val_df, w2v, epochs=50, lr=0.003, batch_size=32, device=device)

    print("\n=== Step 4: Final Evaluation on Validation and Test Sets ===")
    val_metrics = evaluate_shadow(cnn_model, val_df, w2v, device=device)
    print(f"Validation Set Metrics:")
    print(f"  Accuracy: {val_metrics['accuracy'] * 100:.2f}%")
    print(f"  TRR (True Rejection Rate / Blocked): {val_metrics['TRR'] * 100:.2f}%")
    print(f"  TAR (True Acceptance Rate / Allowed): {val_metrics['TAR'] * 100:.2f}%")

    test_metrics = evaluate_shadow(cnn_model, test_df, w2v, device=device)
    print(f"\nTest Set Metrics:")
    print(f"  Accuracy: {test_metrics['accuracy'] * 100:.2f}%")
    print(f"  TRR (True Rejection Rate / Blocked): {test_metrics['TRR'] * 100:.2f}%")
    print(f"  TAR (True Acceptance Rate / Allowed): {test_metrics['TAR'] * 100:.2f}%")

    print("\n=== Step 5: Saving Models ===")
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    cnn_save_path = os.path.join(models_dir, "shadow_cnn.pt")
    w2v_save_path = os.path.join(models_dir, "word2vec.model")

    torch.save(cnn_model.state_dict(), cnn_save_path)
    w2v.save(w2v_save_path)
    print(f"ShadowCNN weights saved to: {cnn_save_path}")
    print(f"Word2Vec model saved to:     {w2v_save_path}")
