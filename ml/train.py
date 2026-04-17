"""
Train the Isolation Forest model on simulated normal HTTP traffic.
Run this once to generate model.pkl before starting the app.
"""
import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

def train_model(save_path='ml/model.pkl'):
    print("[*] Generating normal traffic training data (50,000 samples)...")
    np.random.seed(42)

    # Simulate 50,000 normal HTTP requests
    # Features: [length, specials, kw_score, freq, entropy]
    X_normal = np.column_stack([
        np.random.normal(120, 40, 50000).clip(10, 500),   # length: avg 120 bytes
        np.random.normal(2, 1, 50000).clip(0, 8),          # specials: 0-8
        np.random.choice([0, 1], 50000, p=[0.95, 0.05]),   # keywords: rarely in normal
        np.random.normal(10, 5, 50000).clip(1, 30),        # freq: ~10 req/min normal
        np.random.normal(3.5, 0.5, 50000).clip(1.5, 5.5), # entropy: moderate
    ])

    print("[*] Training Isolation Forest (n_estimators=100, contamination=0.05)...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_normal)

    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump(model, save_path)
    print(f"[+] Model trained and saved to {save_path}")
    return model


if __name__ == '__main__':
    train_model()
