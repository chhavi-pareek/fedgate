"""
FedGate — Federation Orchestration Pipeline (Phase 3)

This module wires together all FedGate components into a single callable
federation run. The pipeline proceeds as follows:

  1. Initialise FLClient instances (one per node) and one FLAggregator.
  2. Each client trains a local autoencoder on its node-specific API traffic.
  3. Pre-federation metrics are captured (local F1 and global F1 per node).
  4. Federation loop runs for num_rounds rounds:
       a. Each client extracts its encoder weight vector (L2-clipped to norm 1.0).
       b. Differential privacy noise is applied (Laplace, scale = max_norm/epsilon).
       c. Weights are encrypted with CKKS before being sent to the aggregator.
       d. The aggregator computes reputation-weighted FedAvg on ciphertext and
          decrypts only the final aggregate.
       e. Each client loads the global encoder, retrains locally with FedProx
          proximal interpolation (alpha=0.7) and EMA threshold update (momentum=0.8).
       f. Global F1 scores are collected and used to update trust scores.
  5. Post-federation metrics are captured and compared to the pre-federation baseline.
  6. Results are saved to CSV (round-by-round) and JSON (full summary).

Component connections:
  FLClient.get_weight_vector()          → raw encoder weights (272,)
  FLClient.apply_differential_privacy() → noisy weights
  FLAggregator.encrypt_weights()        → CKKSVector
  FLAggregator.aggregate()              → global weights (272,), never sees per-node plaintext
  FLClient.update_model_from_global()   → loads global encoder, increments round_number
  FLClient.retrain()                    → FedProx fine-tune + EMA threshold update
  FLAggregator.update_trust_scores()    → adjusts per-node reputation from F1 history
"""

import csv
import json
import os
import sys
from datetime import datetime
from typing import Optional

import numpy as np

# Allow imports from the backend directory regardless of working directory
_BACKEND_DIR: str = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR: str = os.path.dirname(_BACKEND_DIR)

if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from fl_aggregator import FLAggregator  # noqa: E402
from fl_client import FLClient  # noqa: E402


def run_federation(
    num_clients: int = 5,
    num_rounds: int = 10,
    epsilon: float = 1.0,
    use_reputation: bool = True,
    poison_node_id: Optional[int] = None,
    poison_round: int = 3,
    save_results: bool = True,
    results_dir: str = "experiments/results",
) -> dict:
    """
    Execute a full FedGate federation run and return structured results.

    Args:
        num_clients:    Number of FL nodes (must match available node_*.csv files).
        num_rounds:     Number of federation rounds to run.
        epsilon:        Differential privacy budget. Lower = more noise = stronger
                        privacy. Passed to each FLClient at construction time.
        use_reputation: If True, trust scores are updated from per-round F1 and
                        used to weight the FedAvg aggregate. If False, trust scores
                        are reset to equal (1.0) every round — plain FedAvg baseline.
        poison_node_id: If not None, this node's weights are corrupted by a 10x
                        multiplier at poison_round, and its trust score is set to
                        the minimum (0.1) by the aggregator.
        poison_round:   The round at which the poison injection occurs.
        save_results:   If True, write a round-by-round CSV and a full JSON summary
                        to results_dir.
        results_dir:    Directory for output files, created if it does not exist.
                        Resolved relative to the project root.

    Returns:
        Dict containing:
          run_id              — timestamp string identifying this run
          config              — parameters used for this run
          pre_federation      — per-node local_f1 and global_f1 before any federation
          post_federation     — per-node local_f1, global_f1, and improvement after
          mean_improvement    — mean (post_global_f1 - pre_global_f1) across all nodes
          final_trust_scores  — trust scores at end of last round, keyed by str(node_id)
          round_results       — list of per-round dicts with full node metrics
          aggregation_log     — list of per-round dicts from the aggregator
    """
    # ------------------------------------------------------------------
    # Step 1 — Setup
    # ------------------------------------------------------------------
    service_names: dict[int, str] = {
        0: "Login",
        1: "Payment",
        2: "Search",
        3: "Profile",
        4: "Admin",
    }

    abs_results_dir: str = os.path.join(ROOT_DIR, results_dir)
    os.makedirs(abs_results_dir, exist_ok=True)

    run_id: str = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f'\n{"=" * 60}')
    print(f"  FedGate Federation Run — {run_id}")
    print(f"  Clients: {num_clients} | Rounds: {num_rounds} | Epsilon: {epsilon}")
    print(f"  Reputation weighting: {use_reputation} | Poison node: {poison_node_id}")
    print(f'{"=" * 60}\n')

    # ------------------------------------------------------------------
    # Step 2 — Initialise clients and aggregator, train all clients
    # ------------------------------------------------------------------
    clients: list[FLClient] = [
        FLClient(node_id=i, epsilon=epsilon) for i in range(num_clients)
    ]
    aggregator = FLAggregator(num_clients=num_clients)

    print("Training local models...")
    for client in clients:
        client.train()
    print("All clients trained.\n")

    # ------------------------------------------------------------------
    # Step 3 — Record pre-federation metrics
    # ------------------------------------------------------------------
    pre_fed: dict[int, dict] = {}
    for client in clients:
        local_metrics = client.evaluate(use_local=True)
        global_metrics = client.evaluate(use_local=False)
        pre_fed[client.node_id] = {
            "service": service_names[client.node_id],
            "local_f1": round(local_metrics["f1"], 4),
            "global_f1": round(global_metrics["f1"], 4),
        }

    print("Pre-federation metrics recorded.")
    for node_id, m in pre_fed.items():
        print(
            f"  Node {node_id} ({m['service']:<8}) "
            f"Local F1: {m['local_f1']:.4f} | Global F1: {m['global_f1']:.4f}"
        )
    print()

    # ------------------------------------------------------------------
    # Step 4 — Federation loop
    # ------------------------------------------------------------------
    round_results: list[dict] = []
    print(f"Starting federation — {num_rounds} rounds\n")

    for r in range(1, num_rounds + 1):
        print(f"--- Round {r:2d} ---")

        # 4b — Poison injection
        if poison_node_id is not None and r == poison_round:
            aggregator.poison_node(poison_node_id)
            print(f"[POISON] Node {poison_node_id} weights will be down-weighted this round")

        # 4c — Extract, optionally corrupt, apply DP, encrypt
        encrypted_weights: list = []
        for client in clients:
            weights: np.ndarray = client.get_weight_vector()
            if (
                poison_node_id is not None
                and client.node_id == poison_node_id
                and r == poison_round
            ):
                weights = weights * 10.0
                print(f"[POISON] Node {poison_node_id} weights corrupted by 10x multiplier")
            noisy_weights: np.ndarray = client.apply_differential_privacy(weights)
            encrypted = aggregator.encrypt_weights(noisy_weights)
            encrypted_weights.append(encrypted)

        # 4d — Reputation-weighted FedAvg on ciphertext
        if not use_reputation:
            # Reset to equal weighting every round for plain FedAvg baseline
            for i in range(num_clients):
                aggregator.trust_scores[i] = 1.0

        global_weights: np.ndarray = aggregator.aggregate(
            encrypted_weights, round_number=r
        )

        # 4e — Distribute global weights and retrain
        for client in clients:
            client.update_model_from_global(global_weights)
        for client in clients:
            client.retrain()

        # 4f — Evaluate all clients on global test set
        round_f1: dict[int, float] = {}
        round_metrics: dict[int, dict] = {}
        for client in clients:
            metrics = client.evaluate(use_local=False)
            round_f1[client.node_id] = metrics["f1"]
            round_metrics[client.node_id] = {
                "f1": round(metrics["f1"], 4),
                "precision": round(metrics["precision"], 4),
                "recall": round(metrics["recall"], 4),
                "accuracy": round(metrics["accuracy"], 4),
                "threshold": round(client.threshold, 4),
                "weight_change": round(client.last_weight_change, 6),
                "trust_score": round(aggregator.trust_scores[client.node_id], 4),
            }

        # 4g — Update trust scores
        if use_reputation:
            aggregator.update_trust_scores(round_f1)

        # 4h — Round summary
        mean_f1: float = round(float(np.mean(list(round_f1.values()))), 4)
        f1_list: list[float] = [round(round_f1[i], 4) for i in range(num_clients)]
        trust_list: list[float] = [
            round(aggregator.trust_scores[i], 3) for i in range(num_clients)
        ]
        print(
            f"Round {r:2d} — F1: {f1_list} — Mean: {mean_f1:.4f} — Trust: {trust_list}"
        )

        # 4i — Store round results
        round_results.append(
            {
                "round": r,
                "mean_global_f1": mean_f1,
                "node_metrics": round_metrics,
                "trust_scores": dict(aggregator.trust_scores),
                "epsilon": epsilon,
                "use_reputation": use_reputation,
                "poison_active": poison_node_id is not None and r >= poison_round,
            }
        )

    # ------------------------------------------------------------------
    # Step 5 — Post-federation metrics
    # ------------------------------------------------------------------
    post_fed: dict[int, dict] = {}
    for client in clients:
        local_metrics = client.evaluate(use_local=True)
        global_metrics = client.evaluate(use_local=False)
        post_fed[client.node_id] = {
            "service": service_names[client.node_id],
            "local_f1": round(local_metrics["f1"], 4),
            "global_f1": round(global_metrics["f1"], 4),
            "improvement": round(
                global_metrics["f1"] - pre_fed[client.node_id]["global_f1"], 4
            ),
        }

    # ------------------------------------------------------------------
    # Step 6 — Print final summary
    # ------------------------------------------------------------------
    print(f'\n{"=" * 60}')
    print("  Federation Complete — Final Summary")
    print(f'{"=" * 60}')
    print(
        f'{"Node":<6} {"Service":<10} {"Pre-Fed Global":<16} '
        f'{"Post-Fed Global":<16} {"Improvement":<12}'
    )
    print(
        f'{"----":<6} {"-------":<10} {"--------------":<16} '
        f'{"---------------":<16} {"-----------":<12}'
    )
    for node_id, m in post_fed.items():
        imp_str = (
            f"+{m['improvement']:.4f}"
            if m["improvement"] >= 0
            else f"{m['improvement']:.4f}"
        )
        print(
            f"{node_id:<6} {m['service']:<10} "
            f"{pre_fed[node_id]['global_f1']:<16.4f} "
            f"{m['global_f1']:<16.4f} "
            f"{imp_str:<12}"
        )

    mean_improvement: float = float(
        np.mean([m["improvement"] for m in post_fed.values()])
    )
    print(f"\nMean global F1 improvement: {mean_improvement:+.4f}")
    print(f"Final trust scores: {dict(aggregator.trust_scores)}")
    print(f'{"=" * 60}\n')

    # ------------------------------------------------------------------
    # Step 7 — Save results
    # ------------------------------------------------------------------
    if save_results:
        csv_path: str = os.path.join(abs_results_dir, f"run_{run_id}.csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "round", "epsilon", "use_reputation", "mean_global_f1",
                    "node_0_f1", "node_1_f1", "node_2_f1", "node_3_f1", "node_4_f1",
                    "trust_0", "trust_1", "trust_2", "trust_3", "trust_4",
                    "poison_active",
                ]
            )
            for rr in round_results:
                nm = rr["node_metrics"]
                ts_scores = rr["trust_scores"]
                writer.writerow(
                    [
                        rr["round"], epsilon, use_reputation, rr["mean_global_f1"],
                        nm[0]["f1"], nm[1]["f1"], nm[2]["f1"], nm[3]["f1"], nm[4]["f1"],
                        round(ts_scores[0], 4), round(ts_scores[1], 4),
                        round(ts_scores[2], 4), round(ts_scores[3], 4),
                        round(ts_scores[4], 4),
                        rr["poison_active"],
                    ]
                )
        print(f"Results saved to {csv_path}")

        json_path: str = os.path.join(abs_results_dir, f"summary_{run_id}.json")
        summary: dict = {
            "run_id": run_id,
            "config": {
                "num_clients": num_clients,
                "num_rounds": num_rounds,
                "epsilon": epsilon,
                "use_reputation": use_reputation,
                "poison_node_id": poison_node_id,
            },
            "pre_federation": pre_fed,
            "post_federation": post_fed,
            "mean_improvement": float(mean_improvement),
            "final_trust_scores": {
                str(k): v for k, v in aggregator.trust_scores.items()
            },
            "round_results": round_results,
        }
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"Summary saved to {json_path}")

    # ------------------------------------------------------------------
    # Step 8 — Return results
    # ------------------------------------------------------------------
    return {
        "run_id": run_id,
        "config": {
            "num_clients": num_clients,
            "num_rounds": num_rounds,
            "epsilon": epsilon,
            "use_reputation": use_reputation,
            "poison_node_id": poison_node_id,
        },
        "pre_federation": pre_fed,
        "post_federation": post_fed,
        "mean_improvement": float(mean_improvement),
        "final_trust_scores": {
            str(k): v for k, v in aggregator.trust_scores.items()
        },
        "round_results": round_results,
        "aggregation_log": aggregator.get_aggregation_log(),
    }
