"""
FedGate — Federated API Abuse Detection System
Data Generation Module (Phase 1)

=== Data Schema ===
Every CSV contains the following columns:

    request_id                  : UUID4 string — unique identifier per request
    ip_hash                     : MD5 hex string — hashed representation of source IP (no real IPs stored)
    timestamp                   : ISO-8601 datetime string — realistic time within the last 30 days
    endpoint                    : URL path string — the API endpoint hit
    http_method                 : String — HTTP verb (GET, POST, PUT, DELETE)
    response_code               : Integer — HTTP response status code
    payload_size_bytes          : Integer — size of request payload in bytes
    requests_per_min            : Float — request rate for this session/IP
    unique_endpoints_per_session: Integer — number of distinct endpoints accessed in the session
    inter_request_time_seconds  : Float — seconds since the previous request from the same IP
    hour_of_day                 : Integer (0–23) — hour extracted from the timestamp
    failed_auth_streak          : Integer — consecutive failed authentication attempts
    is_abuse                    : Binary integer (0=normal, 1=abuse) — ground-truth label

=== Node Definitions and Attack Profiles ===

  Node 0 — Login Service — Credential Stuffing
    Normal:  Low request rate, varied endpoints, human inter-arrival times.
    Abuse:   High-volume POST floods to /auth/login, near-100% 401s, very short
             inter-request times, long failed_auth_streak.

  Node 1 — Payment Service — Rate Abuse
    Normal:  Low-frequency payment transactions with natural pauses.
    Abuse:   Extreme request rate (200–500 rpm), 429 responses, millisecond
             inter-request times — classic rate-limit bypass attempts.

  Node 2 — Search Service — Scraping
    Normal:  Moderate browsing across diverse search endpoints.
    Abuse:   60–90 rpm to /search/query only, robotically consistent
             ~1.1s inter-request time — automated scraper signature.

  Node 3 — Profile Service — Parameter Tampering
    Normal:  CRUD operations spread across profile endpoints, sane payloads.
    Abuse:   Oversized payloads (5–50 KB), DELETE/PUT to admin-adjacent paths,
             mix of 400/500 errors indicating rejected malformed requests.

  Node 4 — Admin Service — Unauthorised Probing
    Normal:  Business-hours-only access (8–18h), low rate, narrow endpoints.
    Abuse:   Round-the-clock probing, 75% 403s, access to sensitive paths
             (/admin/config, /admin/reset, /admin/export).

=== Why Synthetic Data? ===
Real API gateway logs contain sensitive PII (IP addresses, user identifiers,
business transaction data) and are bound by regulatory and contractual
constraints that make sharing impossible in a research setting. Synthetic
generation lets us:
  1. Precisely control ground-truth labels — enabling rigorous evaluation
     of federated anomaly detection without label noise.
  2. Define heterogeneous node distributions — each node has a distinct
     service type and attack profile, faithfully representing the
     non-IID data reality in federated learning.
  3. Reproduce results exactly — a fixed numpy seed guarantees every
     experiment starts from identical data, eliminating run-to-run variance.
  4. Tune statistical separability — abuse features are statistically
     distinct from normal features but not trivially so; Isolation Forest
     must actually learn decision boundaries rather than fire on obvious
     outliers, giving a meaningful benchmark for the federated pipeline.
"""

import hashlib
import os
import uuid
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Global reproducibility seed
# ---------------------------------------------------------------------------
RNG_SEED = 42
rng = np.random.default_rng(RNG_SEED)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NOW = datetime(2026, 3, 26, 12, 0, 0)  # fixed reference point
THIRTY_DAYS_SECONDS = 30 * 24 * 3600

N_NORMAL = 1700
N_ABUSE = 300
N_TEST_NORMAL = 425
N_TEST_ABUSE = 75
N_REFERENCE = 100
N_NODES = 5

NORMAL_IP_POOL_SIZE = 50
ABUSE_IP_POOL_SIZE = 10

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _make_ip_pools(node_id: int) -> tuple[list[str], list[str]]:
    """Return (normal_ips, abuse_ips) as md5-hashed strings for a node."""
    normal_ips = [
        _md5(f"node{node_id}_normal_ip_{i}_{RNG_SEED}")
        for i in range(NORMAL_IP_POOL_SIZE)
    ]
    abuse_ips = [
        _md5(f"node{node_id}_abuse_ip_{i}_{RNG_SEED}")
        for i in range(ABUSE_IP_POOL_SIZE)
    ]
    return normal_ips, abuse_ips


def _sample_ips(pool: list[str], n: int) -> list[str]:
    indices = rng.integers(0, len(pool), size=n)
    return [pool[i] for i in indices]


def _normal_timestamps(n: int) -> list[str]:
    """Daytime-biased timestamps within the last 30 days."""
    base_offsets = rng.uniform(0, THIRTY_DAYS_SECONDS, size=n)
    # Bias toward daytime: draw hour from N(13,3) clipped to 0-23
    hour_bias = np.clip(rng.normal(13, 3, size=n), 0, 23).astype(int)
    # Replace the hour component in each offset
    timestamps = []
    for offset, h in zip(base_offsets, hour_bias):
        dt = NOW - timedelta(seconds=float(offset))
        dt = dt.replace(hour=int(h), minute=rng.integers(0, 60).item(),
                        second=rng.integers(0, 60).item())
        timestamps.append(dt.strftime("%Y-%m-%d %H:%M:%S"))
    return timestamps


def _abuse_timestamps(n: int) -> list[str]:
    """Uniformly distributed timestamps — abuse happens at any hour."""
    offsets = rng.uniform(0, THIRTY_DAYS_SECONDS, size=n)
    return [
        (NOW - timedelta(seconds=float(o))).strftime("%Y-%m-%d %H:%M:%S")
        for o in offsets
    ]


def _clip(arr: np.ndarray, lo: float, hi: float) -> np.ndarray:
    return np.clip(arr, lo, hi)


def _uuids(n: int) -> list[str]:
    return [str(uuid.uuid4()) for _ in range(n)]


def _add_noise(arr: np.ndarray, scale: float) -> np.ndarray:
    """Add small Gaussian noise to a float array (for realism)."""
    return arr + rng.normal(0, scale, size=len(arr))


# ---------------------------------------------------------------------------
# Node generators
# ---------------------------------------------------------------------------

def _node0_normal(n: int, normal_ips: list[str]) -> pd.DataFrame:
    """Login Service — normal traffic."""
    endpoints = ['/auth/login', '/auth/refresh', '/auth/logout']
    methods = rng.choice(['POST', 'GET'], size=n, p=[0.90, 0.10])
    ep = rng.choice(endpoints, size=n)
    rc_choices = [200, 200, 200, 200, 200, 401, 404, 500]
    rc = rng.choice(rc_choices, size=n)
    rpm = rng.uniform(1, 5, size=n)
    irt = _clip(rng.exponential(20, size=n), 5, 120)
    fas = rng.integers(0, 2, size=n)  # 0 or 1
    hod = _clip(rng.normal(13, 3, size=n), 0, 23).astype(int)
    ps = _clip(rng.normal(250, 50, size=n), 100, 600).astype(int)
    ues = rng.integers(2, 9, size=n)  # 2-8 inclusive
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(normal_ips, n),
        'timestamp': _normal_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 0.1), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(_add_noise(irt, 0.5), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 0,
    })


def _node0_abuse(n: int, abuse_ips: list[str]) -> pd.DataFrame:
    """Login Service — credential stuffing abuse."""
    rpm = rng.uniform(30, 80, size=n)
    rc = rng.choice([401, 200], size=n, p=[0.85, 0.15])
    irt = _clip(rng.normal(1.0, 0.2, size=n), 0.3, 2.5)
    fas = rng.integers(10, 51, size=n)  # 10-50 inclusive
    hod = rng.integers(0, 24, size=n)
    ps = _clip(rng.normal(230, 20, size=n), 100, 600).astype(int)
    ues = rng.integers(1, 3, size=n)  # 1-2
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(abuse_ips, n),
        'timestamp': _abuse_timestamps(n),
        'endpoint': ['/auth/login'] * n,
        'http_method': ['POST'] * n,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 1.5), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(np.abs(_add_noise(irt, 0.05)), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 1,
    })


def _node1_normal(n: int, normal_ips: list[str]) -> pd.DataFrame:
    """Payment Service — normal traffic."""
    endpoints = ['/payment/process', '/payment/status', '/payment/refund']
    ep = rng.choice(endpoints, size=n)
    methods = rng.choice(['POST', 'GET'], size=n, p=[0.80, 0.20])
    rc_choices = [200, 200, 200, 402, 500]
    rc = rng.choice(rc_choices, size=n)
    rpm = rng.uniform(1, 3, size=n)
    irt = _clip(rng.exponential(120, size=n), 30, 600)
    fas = np.zeros(n, dtype=int)
    hod = _clip(rng.normal(13, 3, size=n), 0, 23).astype(int)
    ps = _clip(rng.normal(450, 80, size=n), 300, 700).astype(int)
    ues = rng.integers(1, 5, size=n)  # 1-4
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(normal_ips, n),
        'timestamp': _normal_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 0.05), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(_add_noise(irt, 2.0), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 0,
    })


def _node1_abuse(n: int, abuse_ips: list[str]) -> pd.DataFrame:
    """Payment Service — rate abuse."""
    rpm = rng.uniform(200, 500, size=n)
    rc = rng.choice([429, 200], size=n, p=[0.60, 0.40])
    irt = rng.uniform(0.01, 0.1, size=n)
    fas = np.zeros(n, dtype=int)
    hod = rng.integers(0, 24, size=n)
    ps = _clip(rng.normal(420, 30, size=n), 300, 700).astype(int)
    ues = rng.integers(1, 3, size=n)  # 1-2
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(abuse_ips, n),
        'timestamp': _abuse_timestamps(n),
        'endpoint': ['/payment/process'] * n,
        'http_method': ['POST'] * n,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 5.0), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(np.abs(_add_noise(irt, 0.005)), 4),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 1,
    })


def _node2_normal(n: int, normal_ips: list[str]) -> pd.DataFrame:
    """Search Service — normal traffic."""
    endpoints = ['/search/query', '/search/filter', '/search/suggest',
                 '/search/results', '/search/categories']
    ep = rng.choice(endpoints, size=n)
    rc = rng.choice([200, 404], size=n, p=[0.90, 0.10])
    rpm = rng.uniform(2, 10, size=n)
    irt = _clip(rng.exponential(12, size=n), 3, 60)
    fas = np.zeros(n, dtype=int)
    hod = _clip(rng.normal(13, 4, size=n), 0, 23).astype(int)
    ps = _clip(rng.normal(80, 20, size=n), 30, 200).astype(int)
    ues = rng.integers(5, 16, size=n)  # 5-15
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(normal_ips, n),
        'timestamp': _normal_timestamps(n),
        'endpoint': ep,
        'http_method': ['GET'] * n,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 0.2), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(_add_noise(irt, 0.3), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 0,
    })


def _node2_abuse(n: int, abuse_ips: list[str]) -> pd.DataFrame:
    """Search Service — scraping abuse."""
    rpm = rng.uniform(60, 90, size=n)
    rc = rng.choice([200, 429], size=n, p=[0.95, 0.05])
    irt = _clip(rng.normal(1.1, 0.08, size=n), 0.9, 1.3)
    fas = np.zeros(n, dtype=int)
    hod = rng.integers(0, 24, size=n)
    ps = _clip(rng.normal(75, 5, size=n), 30, 200).astype(int)
    ues = rng.integers(1, 3, size=n)  # 1-2
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(abuse_ips, n),
        'timestamp': _abuse_timestamps(n),
        'endpoint': ['/search/query'] * n,
        'http_method': ['GET'] * n,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 2.0), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(np.abs(_add_noise(irt, 0.02)), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 1,
    })


def _node3_normal(n: int, normal_ips: list[str]) -> pd.DataFrame:
    """Profile Service — normal traffic."""
    endpoints = ['/profile/view', '/profile/update', '/profile/avatar',
                 '/profile/settings']
    ep = rng.choice(endpoints, size=n)
    methods = rng.choice(['GET', 'PUT', 'DELETE'], size=n, p=[0.50, 0.40, 0.10])
    rc_choices = [200, 200, 200, 404, 400]
    rc = rng.choice(rc_choices, size=n)
    rpm = rng.uniform(1, 5, size=n)
    irt = _clip(rng.exponential(30, size=n), 5, 120)
    fas = np.zeros(n, dtype=int)
    hod = _clip(rng.normal(13, 3, size=n), 0, 23).astype(int)
    ps = _clip(rng.normal(350, 80, size=n), 150, 600).astype(int)
    ues = rng.integers(2, 7, size=n)  # 2-6
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(normal_ips, n),
        'timestamp': _normal_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 0.1), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(_add_noise(irt, 1.0), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 0,
    })


def _node3_abuse(n: int, abuse_ips: list[str]) -> pd.DataFrame:
    """Profile Service — parameter tampering abuse."""
    endpoints_abuse = ['/profile/update', '/profile/delete', '/profile/admin']
    ep = rng.choice(endpoints_abuse, size=n)
    methods = rng.choice(['DELETE', 'PUT'], size=n, p=[0.50, 0.50])
    rc = rng.choice([400, 500, 200], size=n, p=[0.50, 0.40, 0.10])
    rpm = rng.uniform(5, 20, size=n)
    irt = _clip(rng.exponential(8, size=n), 1, 30)
    fas = np.zeros(n, dtype=int)
    hod = rng.integers(0, 24, size=n)
    ps = rng.integers(5000, 50001, size=n)  # large payloads
    ues = rng.integers(1, 4, size=n)  # 1-3
    # Add noise to payload size (keep large to stay separable)
    ps_noisy = np.clip(ps + rng.integers(-200, 201, size=n), 4800, 51000)
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(abuse_ips, n),
        'timestamp': _abuse_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps_noisy,
        'requests_per_min': np.round(_add_noise(rpm, 0.5), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(np.abs(_add_noise(irt, 0.3)), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 1,
    })


def _node4_normal(n: int, normal_ips: list[str]) -> pd.DataFrame:
    """Admin Service — normal traffic (business hours)."""
    endpoints = ['/admin/dashboard', '/admin/users', '/admin/logs',
                 '/admin/settings']
    ep = rng.choice(endpoints, size=n)
    methods = rng.choice(['GET', 'POST', 'DELETE'], size=n, p=[0.60, 0.30, 0.10])
    rc = rng.choice([200, 403], size=n, p=[0.95, 0.05])
    rpm = rng.uniform(0.5, 3, size=n)
    irt = _clip(rng.exponential(60, size=n), 20, 300)
    fas = np.zeros(n, dtype=int)
    # Business hours: N(11,2) clipped to 8-18
    hod = _clip(rng.normal(11, 2, size=n), 8, 18).astype(int)
    ps = _clip(rng.normal(200, 50, size=n), 100, 400).astype(int)
    ues = rng.integers(2, 6, size=n)  # 2-5
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(normal_ips, n),
        'timestamp': _normal_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 0.05), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(_add_noise(irt, 2.0), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 0,
    })


def _node4_abuse(n: int, abuse_ips: list[str]) -> pd.DataFrame:
    """Admin Service — unauthorised probing abuse."""
    endpoints_abuse = ['/admin/users', '/admin/config', '/admin/delete',
                       '/admin/reset', '/admin/export']
    ep = rng.choice(endpoints_abuse, size=n)
    methods = rng.choice(['GET', 'POST', 'DELETE'], size=n, p=[0.40, 0.30, 0.30])
    rc = rng.choice([403, 404, 200], size=n, p=[0.75, 0.20, 0.05])
    rpm = rng.uniform(10, 30, size=n)
    irt = _clip(rng.normal(2.0, 0.5, size=n), 0.5, 5)
    fas = rng.integers(5, 21, size=n)  # 5-20
    hod = rng.integers(0, 24, size=n)
    ps = _clip(rng.normal(180, 30, size=n), 100, 400).astype(int)
    ues = rng.integers(3, 9, size=n)  # 3-8
    return pd.DataFrame({
        'request_id': _uuids(n),
        'ip_hash': _sample_ips(abuse_ips, n),
        'timestamp': _abuse_timestamps(n),
        'endpoint': ep,
        'http_method': methods,
        'response_code': rc,
        'payload_size_bytes': ps,
        'requests_per_min': np.round(_add_noise(rpm, 1.0), 3),
        'unique_endpoints_per_session': ues,
        'inter_request_time_seconds': np.round(np.abs(_add_noise(irt, 0.1)), 3),
        'hour_of_day': hod,
        'failed_auth_streak': fas,
        'is_abuse': 1,
    })


# ---------------------------------------------------------------------------
# Node dispatch table
# ---------------------------------------------------------------------------

NODE_GENERATORS = [
    (_node0_normal, _node0_abuse),
    (_node1_normal, _node1_abuse),
    (_node2_normal, _node2_abuse),
    (_node3_normal, _node3_abuse),
    (_node4_normal, _node4_abuse),
]

NODE_NAMES = [
    "Login Service (Credential Stuffing)",
    "Payment Service (Rate Abuse)",
    "Search Service (Scraping)",
    "Profile Service (Parameter Tampering)",
    "Admin Service (Unauthorised Probing)",
]

# ---------------------------------------------------------------------------
# Generation pipeline
# ---------------------------------------------------------------------------

NUMERICAL_COLS = [
    'payload_size_bytes', 'requests_per_min', 'unique_endpoints_per_session',
    'inter_request_time_seconds', 'hour_of_day', 'failed_auth_streak',
]


def generate_node(node_id: int) -> pd.DataFrame:
    """Generate training data for a single node."""
    normal_ips, abuse_ips = _make_ip_pools(node_id)
    gen_normal, gen_abuse = NODE_GENERATORS[node_id]
    normal_df = gen_normal(N_NORMAL, normal_ips)
    abuse_df = gen_abuse(N_ABUSE, abuse_ips)
    df = pd.concat([normal_df, abuse_df], ignore_index=True)
    # Shuffle rows
    df = df.sample(frac=1, random_state=RNG_SEED).reset_index(drop=True)
    return df


def generate_test_set() -> pd.DataFrame:
    """Generate shared held-out evaluation set drawing from all node distributions."""
    per_node_normal = N_TEST_NORMAL // N_NODES  # 85 per node
    per_node_abuse = N_TEST_ABUSE // N_NODES    # 15 per node
    remainder_normal = N_TEST_NORMAL - per_node_normal * N_NODES
    remainder_abuse = N_TEST_ABUSE - per_node_abuse * N_NODES

    parts = []
    for node_id in range(N_NODES):
        normal_ips, abuse_ips = _make_ip_pools(node_id)
        gen_normal, gen_abuse = NODE_GENERATORS[node_id]
        n_n = per_node_normal + (1 if node_id < remainder_normal else 0)
        n_a = per_node_abuse + (1 if node_id < remainder_abuse else 0)
        parts.append(gen_normal(n_n, normal_ips))
        parts.append(gen_abuse(n_a, abuse_ips))

    df = pd.concat(parts, ignore_index=True)
    df = df.sample(frac=1, random_state=RNG_SEED).reset_index(drop=True)
    return df


def generate_node_test_set(node_id: int) -> pd.DataFrame:
    """Generate a per-node held-out test set (170 normal + 30 abuse rows).

    Uses the same statistical distributions as the training data for that node
    but draws fresh rows by temporarily seeding the global rng with
    100 + node_id. This guarantees no overlap with training data while keeping
    the distribution identical — standard held-out evaluation practice.

    The per-node test sets are used to measure each node's specialised
    detection ability on its own attack type (local F1), separately from the
    shared global test set that covers all five attack types.
    """
    global rng
    saved_rng = rng
    rng = np.random.default_rng(100 + node_id)

    normal_ips, abuse_ips = _make_ip_pools(node_id)
    gen_normal, gen_abuse = NODE_GENERATORS[node_id]
    normal_df = gen_normal(170, normal_ips)
    abuse_df = gen_abuse(30, abuse_ips)
    df = pd.concat([normal_df, abuse_df], ignore_index=True)
    df = df.sample(frac=1, random_state=100 + node_id).reset_index(drop=True)

    rng = saved_rng
    return df


def generate_reference_set() -> pd.DataFrame:
    """Generate 100-row purely normal reference set from all nodes combined."""
    per_node = N_REFERENCE // N_NODES  # 20 per node
    remainder = N_REFERENCE - per_node * N_NODES

    parts = []
    for node_id in range(N_NODES):
        normal_ips, _ = _make_ip_pools(node_id)
        gen_normal, _ = NODE_GENERATORS[node_id]
        n = per_node + (1 if node_id < remainder else 0)
        parts.append(gen_normal(n, normal_ips))

    df = pd.concat(parts, ignore_index=True)
    df = df.sample(frac=1, random_state=RNG_SEED).reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Verification summary
# ---------------------------------------------------------------------------

def print_verification_summary(node_dfs: list[pd.DataFrame],
                                test_df: pd.DataFrame,
                                ref_df: pd.DataFrame) -> None:
    """Print row counts, abuse ratios, and per-class feature means."""
    SEP = "=" * 72

    print(f"\n{SEP}")
    print("  FedGate — Data Generation Verification Summary")
    print(SEP)

    def _summary(name: str, df: pd.DataFrame) -> None:
        n_total = len(df)
        n_abuse = int(df['is_abuse'].sum())
        abuse_ratio = n_abuse / n_total
        print(f"\n{'─' * 72}")
        print(f"  {name}")
        print(f"  Rows: {n_total:,}   Abuse: {n_abuse} ({abuse_ratio:.1%})")
        print(f"{'─' * 72}")
        header = f"  {'Feature':<38} {'Normal (mean)':>14} {'Abuse (mean)':>13}"
        print(header)
        print(f"  {'─'*38} {'─'*14} {'─'*13}")
        normal = df[df['is_abuse'] == 0]
        abuse = df[df['is_abuse'] == 1]
        for col in NUMERICAL_COLS:
            n_mean = normal[col].mean()
            a_mean = abuse[col].mean() if len(abuse) > 0 else float('nan')
            print(f"  {col:<38} {n_mean:>14.3f} {a_mean:>13.3f}")

    for i, df in enumerate(node_dfs):
        _summary(f"Node {i} — {NODE_NAMES[i]}", df)

    _summary("Test Set (shared held-out)", test_df)

    # Reference set: all normal, so only print normal mean
    n_total = len(ref_df)
    print(f"\n{'─' * 72}")
    print(f"  Reference Set (normal only)")
    print(f"  Rows: {n_total:,}   Abuse: 0 (0.0%)")
    print(f"{'─' * 72}")
    print(f"  {'Feature':<38} {'Normal (mean)':>14}")
    print(f"  {'─'*38} {'─'*14}")
    for col in NUMERICAL_COLS:
        n_mean = ref_df[col].mean()
        print(f"  {col:<38} {n_mean:>14.3f}")

    print(f"\n{SEP}")
    print("  All files saved successfully.")
    print(SEP)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(output_dir: str = "data") -> None:
    """Run the full data generation pipeline and save all CSV files."""
    os.makedirs(output_dir, exist_ok=True)

    print("Generating node training data...")
    node_dfs = []
    for node_id in range(N_NODES):
        df = generate_node(node_id)
        path = os.path.join(output_dir, f"node_{node_id}.csv")
        df.to_csv(path, index=False)
        print(f"  [OK] node_{node_id}.csv — {len(df):,} rows")
        node_dfs.append(df)

    print("Generating test set...")
    test_df = generate_test_set()
    test_path = os.path.join(output_dir, "test_set.csv")
    test_df.to_csv(test_path, index=False)
    print(f"  [OK] test_set.csv — {len(test_df):,} rows")

    print("Generating reference set...")
    ref_df = generate_reference_set()
    ref_path = os.path.join(output_dir, "reference_set.csv")
    ref_df.to_csv(ref_path, index=False)
    print(f"  [OK] reference_set.csv — {len(ref_df):,} rows")

    print("Generating per-node test sets...")
    for node_id in range(N_NODES):
        df = generate_node_test_set(node_id)
        path = os.path.join(output_dir, f"test_node_{node_id}.csv")
        df.to_csv(path, index=False)
        print(f"  [OK] test_node_{node_id}.csv — {len(df):,} rows "
              f"(seed {100 + node_id})")

    print_verification_summary(node_dfs, test_df, ref_df)


if __name__ == '__main__':
    run_pipeline()
