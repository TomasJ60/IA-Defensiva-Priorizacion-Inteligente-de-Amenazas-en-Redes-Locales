#!/usr/bin/env python3
from pathlib import Path
import json
import pickle
import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "data" / "training_set.csv"
MODEL_PATH = BASE_DIR / "data" / "modelo_alertas.joblib"
METRICS_PATH = BASE_DIR / "data" / "model_metrics.json"
FEATURES = ["severidad", "reputacion_osint", "criticidad_activo"]
TARGET_CANDIDATES = ["label", "target", "etiqueta", "es_maliciosa"]


def cargar_dataset():
    if not DATASET_PATH.exists() or DATASET_PATH.stat().st_size == 0:
        raise ValueError(
            "El dataset data/training_set.csv no existe o esta vacio. "
            "Debe contener severidad, reputacion_osint, criticidad_activo y label."
        )

    df = pd.read_csv(DATASET_PATH)
    target_col = next((col for col in TARGET_CANDIDATES if col in df.columns), None)
    if target_col is None:
        raise ValueError(
            "No se encontro la columna de etiqueta. Usa una de estas: "
            + ", ".join(TARGET_CANDIDATES)
        )

    missing = [col for col in FEATURES if col not in df.columns]
    if missing:
        raise ValueError("Faltan columnas en el dataset: " + ", ".join(missing))

    df = df[FEATURES + [target_col]].dropna().copy()
    df[target_col] = df[target_col].astype(int)
    clases = sorted(df[target_col].unique().tolist())
    if clases != [0, 1]:
        raise ValueError("La etiqueta debe tener clases 0 y 1. Encontrado: " + str(clases))

    return df, target_col


def entrenar():
    df, target_col = cargar_dataset()
    x = df[FEATURES]
    y = df[target_col]

    stratify = y if y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.3,
        random_state=42,
        stratify=stratify,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    metrics = {
        "dataset_rows": int(len(df)),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0),
    }

    artifact = {
        "model": model,
        "features": FEATURES,
        "target": target_col,
        "metrics": metrics,
    }
    with MODEL_PATH.open("wb") as fh:
        pickle.dump(artifact, fh)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("Modelo entrenado y guardado correctamente.")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    try:
        entrenar()
    except Exception as exc:
        print(f"Error de entrenamiento: {exc}")
        sys.exit(1)
