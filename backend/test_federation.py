"""
FedGate — Phase 3 integration tests for the full federation pipeline.

Runs three tests in sequence:
  Test 1 — Standard federation with reputation weighting (10 rounds, epsilon=1.0)
  Test 2 — Plain FedAvg without reputation weighting (comparison baseline)
  Test 3 — Poison demo: Node 2 corrupted at round 3, reputation weighting active
"""

import os
import sys

_BACKEND_DIR: str = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from federation import run_federation  # noqa: E402

SEP = "=" * 60

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Test 1 — Standard federation with reputation weighting
    # ------------------------------------------------------------------
    print(SEP)
    print("TEST 1 — Standard federation with reputation weighting")
    print(SEP)
    results = run_federation(
        num_rounds=10,
        epsilon=1.0,
        use_reputation=True,
        save_results=True,
    )
    print(f'Test 1 complete — mean improvement: {results["mean_improvement"]:+.4f}\n')

    # ------------------------------------------------------------------
    # Test 2 — Plain FedAvg without reputation weighting
    # ------------------------------------------------------------------
    print(SEP)
    print("TEST 2 — Plain FedAvg without reputation weighting")
    print(SEP)
    results_no_rep = run_federation(
        num_rounds=10,
        epsilon=1.0,
        use_reputation=False,
        save_results=True,
    )
    print(
        f'Test 2 complete — mean improvement: {results_no_rep["mean_improvement"]:+.4f}\n'
    )

    # ------------------------------------------------------------------
    # Test 3 — Poison demo with reputation weighting active
    # ------------------------------------------------------------------
    print(SEP)
    print("TEST 3 — Poison demo: Node 2 corrupted at round 3, reputation weighting active")
    print(SEP)
    results_poison = run_federation(
        num_rounds=10,
        epsilon=1.0,
        use_reputation=True,
        poison_node_id=2,
        poison_round=3,
        save_results=True,
    )
    print(
        f'Test 3 complete — mean improvement: {results_poison["mean_improvement"]:+.4f}'
    )
    print(f'Final trust scores: {results_poison["final_trust_scores"]}')
    print(
        "Node 2 trust score should be 0.1 (minimum) "
        "— reputation system caught the bad actor"
    )
    print(SEP)
