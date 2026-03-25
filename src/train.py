#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xgboost_incremental_training

Incremental training of the XGBoost classifier from already labeled CSV:
- Uses only the 'label' column (0 = normal, 1 = attack).
- Filters to train only when port_state == 'abnormal'.
- Avoids data leakage: scaler is adjusted only on the training set and applied to the test.
- Maintains holdout evaluation + temporal validation (TimeSeriesSplit).
- Saves model (JSON) and scaler (PKL).
"""

import argparse
import os
import sys
from datetime import datetime

# UTF-8 no stdout 
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# === Dependencies =====
try:
    import pandas as pd
    import numpy as np
    import xgboost as xgb
    from sklearn.model_selection import train_test_split, TimeSeriesSplit
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        classification_report, confusion_matrix, accuracy_score,
        precision_score, recall_score, f1_score
    )
    import joblib
except Exception as e:
    print(f"[ERROR] Import failed: {e}")
    sys.exit(1)

# === Arguments =====
parser = argparse.ArgumentParser(description="XGBoost Incremental Training (labels prontas)")
default_csv = "output_labeled.csv"
parser.add_argument('--csv', default=default_csv, help=f'Labeled CSV path (default: {default_csv})')
parser.add_argument('--b_mbit', type=float, default=45.0, help='Bottleneck bandwidth in Mbps (default: 45)')
parser.add_argument('--test_size', type=float, default=0.25, help='Test ratio (default: 0.25)')
parser.add_argument('--random_state', type=int, default=42, help='Random seed (default: 42)')
parser.add_argument('--abnormal-only', action='store_true',
                    help="Train only with samples where port_state == 'abnormal' (recomendado).")
args = parser.parse_args()

CSV_PATH = args.csv
if not os.path.exists(CSV_PATH):
    print(f"[ERROR] CSV file not found: {CSV_PATH}")
    sys.exit(1)

# == Path ==
csv_dir = os.path.dirname(CSV_PATH) or "."
MODEL_PATH = os.path.join(csv_dir, "xgb_model.json")
SCALER_PATH = os.path.join(csv_dir, "scaler.pkl")
RESULTS_LOG = os.path.join(csv_dir, "train_results.log")

# == CSV reading ==
df = pd.read_csv(CSV_PATH, low_memory=False)
print(f"[INFO] CSV uploaded: {CSV_PATH} ({len(df)} lines)")

# == Label check 0/1 ===
if "label" not in df.columns:
    print("[ERROR] CSV does not contain a 'label' column. Generate the labeled file beforehand (0=normal, 1=attack).")
    sys.exit(1)
# força 0/1
df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
df = df[df["label"].isin([0, 1])].copy()
if len(df) == 0:
    print("[ERROR] After validating the 'label' column, no samples remained.")
    sys.exit(1)

# === Filter only 'abnormal' =====
if args.abnormal_only:
    if "port_state" in df.columns:
        before = len(df)
        df = df[df["port_state"].astype(str).str.lower() == "abnormal"].copy()
        after = len(df)
        print(f"[INFO] Filter port_state='abnormal' applied: {after} samples (removed {before - after}).")
        if after == 0:
            print("[WARNING] 0 samples after 'abnormal' filter. Aborting to avoid invalid training.")
            sys.exit(1)
    else:
        print("[WARNING] Column 'port_state' not found — '--abnormal-only' will be ignored.")

# ==== Balancing =====
num_pos = int((df["label"] == 1).sum())
num_neg = int((df["label"] == 0).sum())
perc_pos = 100 * num_pos / len(df)
perc_neg = 100 * num_neg / len(df)
print(f"[INFO] Balanced counts: attacks={num_pos} ({perc_pos:.2f}%) | normal={num_neg} ({perc_neg:.2f}%)")
USE_POS_WEIGHT = not (40.0 <= perc_pos <= 60.0)

# ==== Feature selection ====
features = [
    "mean_udp", "cv_udp", "mean_pkt_udp", "entropy_udp",
    "mean_tcp", "cv_tcp", "ratio_tcp", "entropy_tcp",
    "mean_pnf", "mean_ppnf"
]
for f in features:
    if f not in df.columns:
        df[f] = 0.0
    df[f] = pd.to_numeric(df[f], errors="coerce").fillna(0.0)

# ==== Bandwidth normalization ===
df["mean_udp"] = pd.to_numeric(df["mean_udp"], errors="coerce").fillna(0.0)
df["mean_tcp"] = pd.to_numeric(df["mean_tcp"], errors="coerce").fillna(0.0)

X = df[features].values
y = df["label"].values

# === Training/test division ===
stratify_arg = y if (len(np.unique(y)) > 1) else None
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=args.test_size, random_state=args.random_state, stratify=stratify_arg
)

# === Scaler: Adjust only during training ====
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# === Automatic class weight adjustment ======
pos_in_train = int((y_train == 1).sum())
neg_in_train = int((y_train == 0).sum())
pos_weight = (neg_in_train / pos_in_train) if pos_in_train > 0 else 1.0
if USE_POS_WEIGHT:
    print(f"[INFO] Dataset unbalanced: applying scale_pos_weight={pos_weight:.2f}")
else:
    print("[INFO] Balanced dataset: scale_pos_weight unnecessary.")

# ===== XGBoost (incremental) model ===
if os.path.exists(MODEL_PATH):
    print(f"[INFO] Loading existing model and updating it.: {MODEL_PATH}")
    model = xgb.XGBClassifier()
    model.load_model(MODEL_PATH)
	
    # Train incrementally on current data (with a new scaler!)
    model.fit(X_train_scaled, y_train, xgb_model=MODEL_PATH)
else:
    print("[INFO] No previous model found. Creating a new model.")
    model_params = dict(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=4,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.random_state
    )
    if USE_POS_WEIGHT:
        model_params["scale_pos_weight"] = pos_weight
    model = xgb.XGBClassifier(**model_params)
    model.fit(X_train_scaled, y_train)

# ===== Assessment =====
if len(np.unique(y_test)) < 2:
    print("[WARNING] Only one class is present in y_test; default metrics may not be informative.")
y_pred = model.predict(X_test_scaled)
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec  = recall_score(y_test, y_pred, zero_division=0)
f1   = f1_score(y_test, y_pred, zero_division=0)

print("\n[RESULTS - Holdout]")
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=4))
print(f"Accuracy: {acc*100:.2f}% | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

# ==== Time validation (TimeSeriesSplit) ====
# If a 'timestamp' column exists, sort it to give more temporal meaning.
X_all = X
y_all = y
if any(c for c in df.columns if "timestamp" in c.lower()):
    ts_col = [c for c in df.columns if "timestamp" in c.lower()][0]
    # sort by timestamp X_all/y_all
    tmp = df.copy()
    tmp[ts_col] = pd.to_datetime(tmp[ts_col], errors="coerce")
    tmp = tmp.sort_values(ts_col)
    X_all = tmp[features].values
    y_all = tmp["label"].values

# Adjust the scaler inside each split unit to prevent leaks:
tscv = TimeSeriesSplit(n_splits=5)
scores_acc, scores_f1 = [], []
for fold, (tr_idx, te_idx) in enumerate(tscv.split(X_all), start=1):
    Xtr, Xte = X_all[tr_idx], X_all[te_idx]
    ytr, yte = y_all[tr_idx], y_all[te_idx]

    sc = StandardScaler()
    Xtr_s = sc.fit_transform(Xtr)
    Xte_s = sc.transform(Xte)

    # If a model has already been saved, warm-start:
    if os.path.exists(MODEL_PATH):
        model_fold = xgb.XGBClassifier()
        model_fold.load_model(MODEL_PATH)
        model_fold.fit(Xtr_s, ytr, xgb_model=MODEL_PATH)
    else:
        model_fold = xgb.XGBClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=4,
            subsample=0.8, colsample_bytree=0.8,
            objective="binary:logistic", eval_metric="logloss",
            random_state=args.random_state
        )
        if USE_POS_WEIGHT:
            # recompute fold weights
            pos_tr = int((ytr == 1).sum())
            neg_tr = int((ytr == 0).sum())
            pw = (neg_tr / pos_tr) if pos_tr > 0 else 1.0
            model_fold.set_params(scale_pos_weight=pw)
        model_fold.fit(Xtr_s, ytr)

    yhat = model_fold.predict(Xte_s)
    scores_acc.append(accuracy_score(yte, yhat))
    scores_f1.append(f1_score(yte, yhat, zero_division=0))

print(f"\n[TEMPORAL VALIDATION] 5 divisions:")
print(f"  Average accuracy: {np.mean(scores_acc):.4f} ± {np.std(scores_acc):.4f}")
print(f"  Average F1: {np.mean(scores_f1):.4f} ± {np.std(scores_f1):.4f}")

# === Saving model and scaler from holdout ====
model.save_model(MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
print(f"\n[SAVED] Incremental model: {MODEL_PATH}")
print(f"[SAVED] Scaler (adjusted in holdout training): {SCALER_PATH}")

# ==== Cumulative log =====
try:
    with open(RESULTS_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"\n=== Incremental training in {datetime.now().isoformat()} ===\n")
        fh.write(f"CSV: {CSV_PATH}\n")
        fh.write(f"Samples used: {len(df)}\n")
        fh.write(f"Balancing: Attacks={perc_pos:.2f}%, Normal={perc_neg:.2f}%\n")
        fh.write(f"abnormal_only={args.abnormal_only}\n")
        fh.write(f"Accuracy: {acc*100:.2f}% | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}\n")
        fh.write(f"Temporal validation: acc={np.mean(scores_acc):.4f}±{np.std(scores_acc):.4f}, "
                 f"f1={np.mean(scores_f1):.4f}±{np.std(scores_f1):.4f}\n")
        fh.write("-"*60 + "\n")
    print(f"[LOG] Results recorded in: {RESULTS_LOG}")
except Exception as e:
    print("[WARNING] Could not save the log:", e)

print("\n[SUCCESS] Incremental training completed.")
