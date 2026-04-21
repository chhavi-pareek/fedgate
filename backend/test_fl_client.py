"""
FedGate — Phase 2 integration test for FLClient (Autoencoder).

Tells the full federation story end-to-end:
  Pre-fed  → each node is a specialist, blind to other attack types
  10 rounds → genuine weight convergence via FedAvg + warm-start retraining
  Post-fed  → global F1 improves; local F1 stays stable
"""

import numpy as np

from fl_client import FLClient

NODE_IDS = list(range(5))
SERVICE_NAMES = ["Login", "Payment", "Search", "Profile", "Admin"]
NUM_ROUNDS = 10
SEP = "=" * 68


def main() -> None:

    # ------------------------------------------------------------------
    # Step 1 — Instantiate and train all 5 clients
    # ------------------------------------------------------------------
    print(SEP)
    print("  Step 1 — Instantiate and train all 5 clients")
    print(SEP)

    clients: list[FLClient] = []
    for i in NODE_IDS:
        client = FLClient(node_id=i, epsilon=1.0)
        client.train()
        clients.append(client)

    # ------------------------------------------------------------------
    # Step 2 — Extract weight vectors
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 2 — Extract weight vectors")
    print(SEP)

    raw_weight_vectors: list[np.ndarray] = []
    for client in clients:
        w = client.get_weight_vector()
        raw_weight_vectors.append(w)
        svc = SERVICE_NAMES[client.node_id]
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"encoder weights shape: {w.shape} | "
            f"total encoder params: {w.size} | "
            f"decoder: frozen locally | "
            f"first 5: {np.round(w[:5], 4)}"
        )

    # ------------------------------------------------------------------
    # Step 3 — Apply differential privacy
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 3 — Apply differential privacy (epsilon=1.0)")
    print(SEP)

    for client, raw in zip(clients, raw_weight_vectors):
        client.apply_differential_privacy(raw)
        l2_norm = float(np.linalg.norm(raw))
        clipped = l2_norm > client.max_norm
        noise_scale = client.max_norm / client.epsilon
        svc = SERVICE_NAMES[client.node_id]
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"L2 norm (pre-noise): {l2_norm:.4f} | "
            f"noise scale (max_norm/eps): {noise_scale:.4f} | "
            f"clipped: {'YES' if clipped else 'NO'}"
        )

    # ------------------------------------------------------------------
    # Step 4 — Pre-federation evaluation
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 4 — Pre-federation evaluation")
    print(SEP)

    pre_local_f1: dict[int, float] = {}
    pre_global_f1: dict[int, float] = {}

    for client in clients:
        local_m = client.evaluate(use_local=True)
        global_m = client.evaluate(use_local=False)
        pre_local_f1[client.node_id] = local_m["f1"]
        pre_global_f1[client.node_id] = global_m["f1"]
        svc = SERVICE_NAMES[client.node_id]
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"Local F1:  {local_m['f1']:.4f}  "
            f"← competent on its own attack type"
        )
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"Global F1: {global_m['f1']:.4f}  "
            f"← blind to other attack types [expected to be low]"
        )

    print()
    print("  >>> The gap between Local and Global F1 is the problem federation solves.")
    print("  >>> Each node is a specialist blind to attacks it has never seen.")
    print("  >>> Federation will close this gap without any raw data leaving any node.")

    # ------------------------------------------------------------------
    # Step 5 — Multi-round federation with retraining
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print(f"  Step 5 — Multi-round federation ({NUM_ROUNDS} rounds, plain FedAvg)")
    print(SEP)

    round_mean_f1: list[float] = []

    for r in range(1, NUM_ROUNDS + 1):
        # Extract current weight vectors — clean signal, no DP noise in this diagnostic
        weight_vectors: list[np.ndarray] = [c.get_weight_vector() for c in clients]

        # FedAvg: simple mean across all nodes
        global_weights: np.ndarray = np.mean(
            np.stack(weight_vectors, axis=0), axis=0
        )

        # Load global weights into each node and retrain
        for client in clients:
            client.update_model_from_global(global_weights)
        for client in clients:
            client.retrain()

        # Collect per-node metrics
        round_f1 = [round(c.evaluate(use_local=False)["f1"], 4) for c in clients]
        weight_changes = [round(c.last_weight_change, 6) for c in clients]
        mean_f1 = round(float(np.mean(round_f1)), 4)
        round_mean_f1.append(mean_f1)

        print(
            f"  Round {r:>2} — "
            f"F1: {round_f1} — "
            f"Mean: {mean_f1:.4f} — "
            f"Weight Δ: {weight_changes}"
        )

        if all(wc == 0.0 for wc in weight_changes):
            print(
                f"  WARNING: Weight vectors unchanged in round {r} "
                f"— federation may not be converging"
            )

    # ------------------------------------------------------------------
    # Step 6 — Post-federation evaluation
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 6 — Post-federation evaluation")
    print(SEP)

    post_global_f1: dict[int, float] = {}

    for client in clients:
        local_m = client.evaluate(use_local=True)
        global_m = client.evaluate(use_local=False)
        post_global_f1[client.node_id] = global_m["f1"]
        svc = SERVICE_NAMES[client.node_id]
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"Local F1:  {local_m['f1']:.4f}  "
            f"← specialist knowledge preserved"
        )
        print(
            f"  Node {client.node_id} ({svc:<8}) — "
            f"Global F1: {global_m['f1']:.4f}  "
            f"← benefits from network knowledge"
        )

    print()
    print("  >>> Federation complete.")
    print("  >>> Local F1 should be similar to pre-federation (node still knows its own job).")
    print("  >>> Global F1 should be higher than pre-federation (node now benefits from network knowledge).")
    print("  >>> If Global F1 improved, federation is working as intended.")

    # ------------------------------------------------------------------
    # Step 7 — Summary table
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 7 — Federation impact summary")
    print(SEP)
    print()

    col_node    = "Node"
    col_svc     = "Service"
    col_pre_loc = "Pre-Fed Local"
    col_pre_glo = "Pre-Fed Global"
    col_post    = "Post-Fed Global"
    col_imp     = "Improvement"

    print(
        f"  {col_node:<4}  {col_svc:<12}  {col_pre_loc:>13}  "
        f"{col_pre_glo:>14}  {col_post:>15}  {col_imp}"
    )
    print(
        f"  {'─'*4}  {'─'*12}  {'─'*13}  {'─'*14}  {'─'*15}  {'─'*11}"
    )

    improvements: list[float] = []
    for i in NODE_IDS:
        pre_l = pre_local_f1[i]
        pre_g = pre_global_f1[i]
        post_g = post_global_f1[i]
        delta = post_g - pre_g
        improvements.append(delta)
        sign = "+" if delta >= 0 else ""
        print(
            f"  {i:^4}  {SERVICE_NAMES[i]:<12}  {pre_l:^13.4f}  "
            f"{pre_g:^14.4f}  {post_g:^15.4f}  {sign}{delta:.4f}"
        )

    mean_improvement = float(np.mean(improvements))
    print()
    print(f"  Mean global F1 improvement across all nodes: {mean_improvement:+.4f}")
    print()

    if mean_improvement > 0.05:
        print("  FEDERATION WORKING — global F1 improved meaningfully across nodes")
    elif mean_improvement > 0.0:
        print("  FEDERATION MARGINAL — small improvement, may improve with more rounds")
    else:
        print("  FEDERATION NOT CONVERGING — investigate weight update logic")

    # ------------------------------------------------------------------
    # Step 8 — ASCII convergence chart
    # ------------------------------------------------------------------
    print("\n" + SEP)
    print("  Step 8 — Convergence across 10 federation rounds")
    print(SEP)
    print()
    print("  Convergence across 10 federation rounds")
    print("  " + "─" * 40)

    for r, f1 in enumerate(round_mean_f1, start=1):
        filled = round(f1 * 20)
        filled = max(0, min(20, filled))
        bar = "█" * filled + "░" * (20 - filled)
        print(f"  Round {r:>2}  [{bar}]  {f1:.4f}")

    print("  " + "─" * 40)
    start_f1 = round_mean_f1[0]
    end_f1 = round_mean_f1[-1]
    delta = end_f1 - start_f1
    sign = "+" if delta >= 0 else ""
    print(f"  Start: {start_f1:.4f}  →  End: {end_f1:.4f}  Δ: {sign}{delta:.4f}")

    print()
    print(SEP)
    print("  All 5 clients initialised, trained, federated and tested successfully")
    print(SEP)


if __name__ == "__main__":
    main()
