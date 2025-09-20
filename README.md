"""
Adaptive Honeypot + Telemetry DB (Research)
Single-file program demonstrating safe honeypot logging and clustering analysis.
"""

import psycopg
import pandas as pd
from sklearn.cluster import KMeans
from datetime import datetime

DB_URL = "postgresql://postgres:postgres@localhost:5432/honeypot_db"

SAMPLE_EVENTS = [
    {"timestamp":"2025-09-20T10:00:00","source_ip":"1.2.3.4","action":"login_attempt"},
    {"timestamp":"2025-09-20T10:05:00","source_ip":"1.2.3.4","action":"file_access"},
    {"timestamp":"2025-09-20T10:10:00","source_ip":"5.6.7.8","action":"login_attempt"}
]

def init_db():
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                source_ip TEXT,
                action TEXT
            );
            """)

def ingest_events(events):
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        with conn.cursor() as cur:
            for e in events:
                cur.execute("""
                INSERT INTO telemetry (timestamp, source_ip, action)
                VALUES (%s,%s,%s)
                """, (e["timestamp"], e["source_ip"], e["action"]))
    print(f"Ingested {len(events)} events.")

def cluster_ips():
    with psycopg.connect(DB_URL) as conn:
        df = pd.read_sql("SELECT source_ip, COUNT(*) as count FROM telemetry GROUP BY source_ip", conn)
        counts = df["count"].values.reshape(-1,1)
        if len(counts) < 2:
            print("Not enough data to cluster.")
            return
        kmeans = KMeans(n_clusters=2, random_state=42).fit(counts)
        df["cluster"] = kmeans.labels_
        print("\nClustered IPs:")
        print(df)

if __name__ == "__main__":
    init_db()
    ingest_events(SAMPLE_EVENTS)
    cluster_ips()
