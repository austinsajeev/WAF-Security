"""
AegisAI-X — ML Anomaly Detection Worker (Phase 3)
=====================================
Trains an Isolation Forest on behavioral features (ip_features).
Runs every 15 minutes. Scores all IPs seen in the last 24h.
Stores results in ip_reputation.
Metrics: Prometheus exposed on port 8001 (scraped by Prometheus server)
"""

import os
import time
import logging
from datetime import datetime, timezone
import clickhouse_connect
import pandas as pd
import joblib
import redis
from sklearn.ensemble import IsolationForest
from prometheus_client import start_http_server, Gauge, Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("aegisai.ml_worker")

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
METRICS_PORT         = int(os.environ.get("ML_METRICS_PORT", "8001"))
ML_WORKER_UP         = Gauge("aegisai_ml_worker_up", "1 if ML worker is running")
ML_IPS_SCORED        = Gauge("aegisai_ml_ips_scored", "Number of IPs scored in last training run")
ML_OUTLIERS_DETECTED = Gauge("aegisai_ml_outliers_detected", "Number of outliers in last training run")
ML_LAST_TRAIN_TS     = Gauge("aegisai_ml_last_train_timestamp", "Unix timestamp of last successful training run")
ML_TRAIN_RUNS        = Counter("aegisai_ml_training_runs_total", "Total number of ML training runs completed")
ML_SKIPPED_RUNS      = Counter("aegisai_ml_skipped_runs_total", "Training runs skipped due to insufficient data")

CH_HOST     = os.environ.get("CH_HOST", "clickhouse")
CH_PORT     = int(os.environ.get("CH_PORT", "8123"))
CH_USER     = os.environ.get("CH_USER", "aegisai")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "aegisai_ch_pass")
CH_DB       = os.environ.get("CH_DB", "aegisai_db")
INTERVAL    = int(os.environ.get("ML_INTERVAL", "900")) # 15 min default
REDIS_URL   = os.environ.get("REDIS_URL", "redis://redis:6379/0")
MODEL_PATH  = os.environ.get("MODEL_PATH", "/app/models/anomaly_detector.joblib")

def get_clickhouse():
    return clickhouse_connect.get_client(
        host=CH_HOST, port=CH_PORT, username=CH_USER,
        password=CH_PASSWORD, database=CH_DB, secure=False
    )

def _fetch_features(ch) -> "pd.DataFrame | None":
    """Fetch IP feature vectors from ClickHouse (last 48h). Returns None if insufficient data."""
    query = """
        SELECT 
            ip,
            avg(request_rate) as request_rate,
            avg(error_rate) as error_rate,
            avg(unique_endpoints) as unique_endpoints,
            avg(attack_pct) as attack_pct
        FROM aegisai_db.ip_features
        WHERE computed_at >= now() - INTERVAL 48 HOUR
        GROUP BY ip
    """
    r = ch.query(query)
    if len(r.result_rows) < 50:
        log.warning(f"Insufficient data for ML training: {len(r.result_rows)} IPs found (require >= 50). Skipping cycle.")
        ML_SKIPPED_RUNS.inc()
        return None
    log.info(f"Training dataset ready: {len(r.result_rows)} IPs from last 48h.")
    return pd.DataFrame(r.result_rows, columns=["ip", "request_rate", "error_rate", "unique_endpoints", "attack_pct"])


def _score_and_store(model, df, ch):
    """Run inference with an already-fitted model and push results to ClickHouse + Redis."""
    X = df[["request_rate", "error_rate", "unique_endpoints", "attack_pct"]].values
    df["is_outlier"] = model.predict(X)
    df["is_outlier"] = df["is_outlier"].apply(lambda x: 1 if x == -1 else 0)
    raw_scores = model.score_samples(X)
    df["anomaly_score"] = -raw_scores

    outlier_count = int(df['is_outlier'].sum())
    log.info(f"Detected {outlier_count} outliers across {len(df)} IPs.")
    ML_IPS_SCORED.set(len(df))
    ML_OUTLIERS_DETECTED.set(outlier_count)
    ML_LAST_TRAIN_TS.set(time.time())

    now = datetime.now(timezone.utc)
    rows = []
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        pipe = redis_client.pipeline()
    except Exception as e:
        log.error(f"Failed to connect to Redis: {e}")
        redis_client = None

    for _, row in df.iterrows():
        ip = row["ip"]
        score = float(row["anomaly_score"])
        outlier = int(row["is_outlier"])
        rows.append([ip, score, outlier, now])
        if redis_client and outlier == 1:
            pipe.setex(f"aegisai:ml_score:{ip}", 3600, score)

    if redis_client:
        try:
            pipe.execute()
        except Exception as e:
            log.error(f"Failed to cache scores in Redis: {e}")

    try:
        ch.insert("ip_reputation", rows, column_names=["ip", "anomaly_score", "is_outlier", "computed_at"])
        log.info("Anomaly scores pushed to ClickHouse (ip_reputation).")
    except Exception as e:
        log.error(f"Failed to insert ML results: {e}")


def load_model_if_exists():
    """Load a previously saved model from disk. Returns the model or None."""
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            log.info(f"Loaded existing model from {MODEL_PATH} — skipping initial retrain.")
            return model
        except Exception as e:
            log.warning(f"Could not load saved model ({e}), will train fresh when data is available.")
    return None


def train_and_score():
    ch = get_clickhouse()
    df = _fetch_features(ch)
    if df is None:
        return
    
    X = df[["request_rate", "error_rate", "unique_endpoints", "attack_pct"]].values

    # Train Isolation Forest
    log.info(f"Training Isolation Forest with {len(X)} records...")
    model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
    model.fit(X)
    ML_TRAIN_RUNS.inc()

    # Persist the model so restarts can load it immediately
    try:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        log.info(f"Model saved to {MODEL_PATH}")
    except Exception as e:
        log.error(f"Failed to persist ML model: {e}")

    _score_and_store(model, df, ch)

def run():
    log.info("AegisAI-X ML Worker Started.")
    log.info("Prometheus metrics exposed on port %d", METRICS_PORT)
    start_http_server(METRICS_PORT)
    ML_WORKER_UP.set(1)

    # --- Startup: load existing model and score immediately (no retraining needed) ---
    model = load_model_if_exists()
    if model is not None:
        try:
            ch = get_clickhouse()
            df = _fetch_features(ch)
            if df is not None:
                _score_and_store(model, df, ch)
                log.info("Startup inference complete using persisted model.")
            else:
                log.warning("Persisted model loaded but insufficient data for startup inference.")
        except Exception as e:
            log.error(f"Startup inference error: {e}")
    else:
        log.info("No persisted model found — will train on first cycle.")

    # --- Main loop: full retrain + score on schedule ---
    while True:
        time.sleep(INTERVAL)
        try:
            train_and_score()
        except Exception as e:
            log.error(f"ML pipeline error: {e}")

if __name__ == "__main__":
    run()
