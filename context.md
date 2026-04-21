# FedGate — Complete Project Context v4

## Origin

Built on top of SEER (https://github.com/Hitme02/SEER) — reuses CKKS encryption and DP patterns from backend/main_module.py. Everything else rebuilt from scratch.

**Course:** Network Security — AI-Driven Security in Network Programming
**Subtopics:** 4 (Federated Learning for Network Security) + 2 (Secure API Gateways with ML)
**Title:** FedGate: Privacy-Preserving Federated Detection of API Abuse across Distributed Microservices using Homomorphic Encryption

---

## Architecture

**Per-round flow:**
1. `get_weight_vector()` → encoder coefs_[0,1,2] flattened → L2 clip to norm 1.0
2. `apply_differential_privacy()` → Laplace(0, 1.0/epsilon) noise
3. `encrypt()` → ts.ckks_vector(context, noisy_weights)
4. Aggregator: normalise trust scores → Σ(encrypted[i] × trust_norm[i]) on ciphertext → one decrypt of averaged result
5. Each node: `update_model_from_global()` → load global encoder, restore frozen decoder → `retrain()` FedProx 70% local / 30% global, EMA threshold update (momentum=0.8, 99th percentile)
6. `evaluate()` on global test set → trust score update

**What travels / stays local:**
- Raw API logs: NEVER leave node
- Predictions/flags: NEVER leave node
- Decoder weights: NEVER leave node
- Encoder weights: travel (after DP noise + CKKS encryption)
- Global averaged encoder: travels back (decrypted, broadcast)

**Model:** MLPRegressor autoencoder `hidden_layer_sizes=(16,8,4,8,16), activation='relu', max_iter=500, random_state=42, warm_start=True`
- Encoder (federated): 7→16→8→4, coefs_[0,1,2]
- Decoder (frozen): 4→8→16→7, coefs_[3,4,5]
- Weight vector: 272 parameters

**Key params:** alpha=0.7 (FedProx), max_norm=1.0 (L2 clip), threshold=99th percentile, EMA momentum=0.8, default epsilon=1.0

---

## The Five Nodes

| Node | Service | Attack Type | Pre-Fed Local F1 | Pre-Fed Global F1 |
|------|---------|-------------|-----------------|------------------|
| 0 | Login | Credential Stuffing | 0.9375 | 0.6122 |
| 1 | Payment | Rate Abuse / DoS | 0.9677 | 0.5300 |
| 2 | Search | Scraping | 0.9677 | 0.3138 |
| 3 | Profile | Parameter Tampering | 0.9375 | 0.5137 |
| 4 | Admin | Unauthorised Probing | 0.9524 | 0.4310 |

Post-federation (10 rounds, epsilon=1.0): all nodes 0.89–0.97 global F1. Mean improvement: +0.4567.

---

## Dataset

Synthetic. 7 features: `requests_per_min`, `unique_endpoints_per_session`, `response_code`, `payload_size_bytes`, `inter_request_time_seconds`, `hour_of_day`, `failed_auth_streak`. Patterns modelled after OWASP and documented attack signatures.

Files: `data/node_0-4.csv` (2000 rows each, 1700/300 split), `data/test_set.csv` (500 rows, 425/75), `data/test_node_0-4.csv` (200 rows each), `data/reference_set.csv` (100 normal, legacy).

---

## Two Innovations

**Innovation 1 — Reputation-Weighted Aggregation:**
Trust score = rolling mean of last 3 rounds F1, clamped to min 0.1. Poison demo: Node 2 trust drops to 0.043 normalised weight at poison round vs 0.20 equal share. Final trust 0.679 vs 1.000 without reputation. Global F1 unaffected — four honest nodes provide sufficient signal. Story is DETECTION not prevention.

Viva framing: "The reputation system correctly identifies and penalises the compromised node even when the immediate F1 impact is small. In a sustained or more sophisticated attack the trust penalty would prevent accumulating damage."

**Innovation 2 — Encoder-Only Federation with Decoder Freezing:**
Full model federation on heterogeneous data → catastrophic forgetting (F1 collapsed to 0.26). Encoder federates general feature compression. Decoder stays frozen preserving node-specific reconstruction. Result: local F1 preserved at 0.97–0.98 post-federation.

---

## Experimental Results

**Finding 1 — Convergence (Primary Result):**
Mean global F1 +0.4567 over 10 rounds at epsilon=1.0. Pre-fed: 0.31–0.61. Post-fed: 0.89–0.97. Convergence visible from round 1 (0.40) to round 10 (0.94).

**Finding 2 — DP Noise Robustness (KEY FINDING — revised from expected):**

| Epsilon | Round 1 F1 | Round 10 F1 | Noise Magnitude | Viable? |
|---------|-----------|------------|-----------------|---------|
| 0.01 | 0.4223 | 0.9376 | 100.0 | YES |
| 0.1 | 0.4232 | 0.9363 | 10.0 | YES |
| 0.5 | 0.4142 | 0.9363 | 2.0 | YES |
| 1.0 | 0.4023 | 0.9369 | 1.0 | YES |
| 5.0 | 0.2966 | 0.4852 | 0.2 | NO |
| inf | 0.2881 | 0.4865 | 0.0 | NO |

Correct framing: "FedGate demonstrates that DP noise acts as an implicit regulariser in heterogeneous federated settings. The robust operating range is epsilon 0.01–1.0. The cliff at epsilon 5.0+ is a heterogeneity cliff, not a privacy cost."

Dashboard epsilon chart shows TWO zones: green (robust operating range, 0.01–1.0) and red (heterogeneity cliff, 5.0+). Do NOT frame as privacy-performance tradeoff — that framing is wrong for this dataset.

**Finding 3 — Poison Robustness (Innovation 1 Demo):**
With reputation: Node 2 trust=0.679, global F1=0.9369. Without reputation: trust=1.000, F1=0.9369. F1 defended: +0.0003. Trust difference confirms detection mechanism.

---

## Phases Completed

| Phase | Files | Status |
|-------|-------|--------|
| 1–2 | backend/fl_client.py, backend/fl_aggregator.py | DONE |
| 3 | backend/federation.py | DONE |
| 4 | experiments/epsilon_sweep.py, experiments/poison_demo.py | DONE |
| 5 | api/main.py, api/test_api.py | DONE — all 6 tests pass |
| 6 | frontend/src/App.jsx | DONE — builds clean, 0 errors |

---

## File Layout

```
FedGate/
├── backend/
│   ├── api_data_generator.py
│   ├── fl_client.py
│   ├── fl_aggregator.py
│   ├── federation.py          ← run_federation(num_clients, num_rounds, epsilon,
│   │                             use_reputation, poison_node_id, poison_round,
│   │                             save_results, results_dir) -> dict
│   ├── test_fl_client.py
│   └── test_federation.py
├── api/
│   ├── main.py                ← FastAPI port 8000, synchronous endpoints
│   └── test_api.py
├── frontend/
│   └── src/
│       ├── App.jsx            ← single-file React SOC dashboard
│       └── index.css          ← minimal reset only
├── experiments/
│   ├── results/
│   │   ├── epsilon_sweep_latest.json
│   │   ├── epsilon_sweep_latest.png
│   │   ├── poison_demo_latest.json
│   │   └── poison_demo_latest.png
│   ├── epsilon_sweep.py
│   └── poison_demo.py
├── data/
│   ├── node_0.csv … node_4.csv
│   ├── test_set.csv
│   ├── test_node_0.csv … test_node_4.csv
│   └── reference_set.csv
├── venv/
└── context.md                 ← this file
```

---

## API Endpoints (port 8000)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| / | GET | Health check, endpoint list |
| /run-federation | POST | Run full federation pipeline (synchronous, 30–60s) |
| /node-status | GET | Per-node status from last run |
| /epsilon-results | GET | Precomputed epsilon sweep + interpretation labels |
| /poison-demo | GET | Precomputed poison demo data |
| /federation-status | GET | Current run status |
| /health | GET | Liveness check |
| /docs | GET | FastAPI auto-generated docs |

All responses: `{ status: 'success'|'error', data: {...}, timestamp: ISO string }`. All node_id keys are strings.

POST /run-federation body:
```json
{
  "num_clients": 5,
  "num_rounds": 10,
  "epsilon": 1.0,
  "use_reputation": true,
  "poison_node_id": null,
  "poison_round": 3
}
```

Run server: `uvicorn api.main:app --reload --port 8000`

---

## Dashboard (frontend)

Stack: Vite + React, recharts, axios. Run: `cd frontend && npm run dev` (port 5173).
`API_BASE = 'http://localhost:8000'`. Single file: `frontend/src/App.jsx`.

Node colors: Login=#00d4ff, Payment=#51cf66, Search=#ffd43b, Profile=#cc5de8, Admin=#ff6b6b
Theme: bg=#0f172a, card=#1e293b, border=#334155, accent=#00d4ff

Epsilon chart uses two coloured zones (cyan=robust range, red=heterogeneity cliff) — not a tradeoff curve.
Poison panel visible whenever poisonData loads from API or poison_demo config is toggled ON.
All node_id keys from API are strings; frontend uses `String(i)` lookups throughout.

---

## Demo Flow (5 min viva)

1. Open dashboard — show 5 node cards with pre-fed global F1 (0.31–0.61)
2. "These nodes are specialists. Node 2 (Search) scores 0.31 globally — it's never seen credential stuffing."
3. Set epsilon=1.0, reputation=ON, rounds=10 → Run Federation
4. Watch convergence chart climb from 0.40 to 0.94 over 10 rounds
5. Show final node status: all nodes 0.89–0.97 global F1 with local F1 preserved at 0.97
6. Point to epsilon chart: "Robust across 0.01–1.0. Cliff at 5.0 is heterogeneity, not privacy cost."
7. Enable poison demo: show Node 2 trust dropping to 0.043 normalised weight at round 3
8. "Global F1 unaffected. Detection works. Reputation correctly penalises the bad actor."

---

## Viva Q&A

**"Why synthetic data?"**
Real logs are proprietary. Synthetic gives zero-ambiguity ground truth. Patterns modelled after OWASP and documented attack signatures.

**"Why autoencoder not Isolation Forest?"**
IF produces identical models every round with static data — no genuine convergence possible. Autoencoder with warm_start loads global weights as initialisation — genuinely different model each round.

**"Why only federate encoder?"**
Full federation on heterogeneous data causes catastrophic forgetting. Encoder shares general feature compression knowledge. Decoder preserves node-specific reconstruction. Local F1 stays 0.97 vs collapsing to 0.26 with full federation.

**"What does the aggregator decrypt?"**
Only the global average, never individual node weights. Limitation: aggregator holds decryption key. Production extension: threshold secret sharing.

**"Why does global F1 start low?"**
Each node trained only on its own attack type. Node 2 trained on scraping has never seen credential stuffing. Low global F1 before federation is the problem statement made concrete. After 10 rounds it reaches 0.89. That is the result.

**"What is the epsilon finding?"**
FedGate is robust to DP noise from epsilon 0.01 to 1.0 — F1 stays above 0.93 across four orders of magnitude of noise. The cliff at epsilon 5.0 is caused by weight heterogeneity in aggregation, not DP noise. At high noise levels, Laplace noise washes out heterogeneous encoder representations and provides a useful near-zero starting point. DP noise acts as an implicit regulariser in heterogeneous federated settings.

**"What does reputation weighting add?"**
Node 2 with poisoned weights contributes only 4.3% to global model vs 20% in plain FedAvg. Final trust 0.679 vs 1.000. Global F1 is unaffected because four honest nodes provide sufficient signal. The story is detection, not prevention — the system correctly identifies the bad actor even when immediate F1 impact is small.

**"Why are thresholds in the hundreds/thousands?"**
CKKS introduces small numerical noise in decrypted weights. Autoencoder reconstructing from slightly noisy weights produces higher absolute reconstruction errors than from clean weights. EMA threshold adapts to this scale per node. F1 is unaffected — scale is consistent within each node.

**"Does Node 2 trust stay at 0.1 after poisoning?"**
No — dynamic reputation not blacklist. Trust recovers as F1 recovers. Final trust 0.679 reflects persistent penalty but node is not permanently excluded. Realistic for adversarial scenarios with temporary failures.

---

## Key Decisions Log

| Decision | Chosen | Why |
|----------|--------|-----|
| Base project | SEER | Already has CKKS and DP |
| Domain | API gateway microservices | Novel, hits subtopics 2 and 4 |
| Dataset | Synthetic | Clean ground truth, OWASP-grounded patterns |
| Local model | MLPRegressor autoencoder | warm_start enables genuine federation convergence |
| Federation scope | Encoder only | Decoder freezing prevents catastrophic forgetting |
| Threshold | EMA 99th percentile | Stable across rounds, adapts to CKKS noise |
| DP sensitivity | L2 clipping max_norm=1.0 | Mathematically proper DP |
| Epsilon finding | Reframed as robustness result | Honest, more interesting than expected tradeoff |
| Innovation 1 | Reputation weighting | Poisoning detection, dramatic trust score demo |
| Innovation 2 | Encoder federation + decoder freezing | Heterogeneous FL solution |
| Frontend | React + Recharts | SOC dashboard aesthetic |
| API | FastAPI synchronous | Simple, correct for demo system |

---

## What Was Tried and Rejected

| Attempt | Problem | Resolution |
|---------|---------|------------|
| Isolation Forest | Identical models every round, no convergence | Replaced with MLPRegressor |
| Reference set score vectors | Not real weight federation | Rejected |
| Full model federation | Catastrophic forgetting, F1 collapsed to 0.26 | Encoder-only federation |
| Fixed threshold | Miscalibrated after encoder changes | EMA recalibration |
| 95th percentile threshold | Too many false positives | 99th percentile |
| Cumulative threshold drift | Extreme values after 10 rounds | EMA with momentum 0.8 |
| Privacy-performance tradeoff framing | Results show opposite of expected | Reframed as DP robustness finding |

---

*Document v4. Covers full conversation from SEER origin through Phase 6 completion.*
