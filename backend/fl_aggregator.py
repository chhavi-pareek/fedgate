"""
FedGate — Federated Aggregator (Phase 3)

Role of the aggregator:
    The FLAggregator is the trusted central coordinator in the FedGate federation.
    Each round it receives encrypted encoder weight vectors from all participating
    nodes, computes a reputation-weighted average on ciphertext, and returns a
    single global encoder weight vector that each node loads before retraining.

Why CKKS homomorphic encryption:
    CKKS (Cheon–Kim–Kim–Song) is an approximate HE scheme that natively supports
    floating-point arithmetic on encrypted vectors. Encoder weights are continuous
    floats, so CKKS is the right choice — it allows weighted addition of encrypted
    weight vectors without any decryption intermediate, meaning the aggregator never
    sees individual node weights in plaintext during aggregation.

What reputation weighting adds:
    Plain FedAvg gives every node equal weight regardless of whether its update
    helps or hurts global detection quality. Reputation weighting down-weights
    nodes whose per-round global F1 scores are trending downward (stale data,
    distribution shift, or active poisoning). Over successive rounds the mean F1
    of the last three rounds is used as the trust score, so a single bad round
    does not immediately marginalise a node and recovery is possible.

Trusted coordinator threat model limitation:
    The aggregator decrypts the final *aggregated* vector, which it must do to
    return a usable global model. Individual node ciphertexts are never decrypted
    individually, providing input privacy. However, this design does NOT protect
    against a compromised aggregator that could attempt to invert the aggregate.
    A fully trustless design would use secure multi-party computation or
    threshold decryption — out of scope for this prototype.
"""

import os
import sys
from typing import Optional

import numpy as np

try:
    import tenseal as ts
except ImportError:
    print(
        "\n[ERROR] TenSEAL is not installed.\n"
        "Install it with:\n"
        "    pip install tenseal\n"
        "If that fails, try the pre-release build:\n"
        "    pip install tenseal --pre\n"
        "Verify with:\n"
        "    python -c \"import tenseal as ts; print(ts.__version__)\"\n"
    )
    raise

ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FLAggregator:
    """
    Reputation-weighted federated aggregator with CKKS homomorphic encryption.

    Each round:
      1. Receives encrypted weight vectors from all nodes.
      2. Computes a trust-score-weighted sum on ciphertext.
      3. Decrypts only the final aggregate — never individual node weights.
      4. Updates per-node trust scores based on reported global F1.

    Attributes:
        num_clients:      Number of federation participants.
        context:          TenSEAL CKKS encryption context shared across this run.
        trust_scores:     Per-node reputation scores, initialised to 1.0.
        f1_history:       Rolling window of per-node global F1 scores.
        round_number:     Count of completed aggregation rounds.
        weight_size:      Exact length of the encoder weight vector (set on first call).
        aggregation_log:  Per-round stats written by aggregate() for dashboard use.
    """

    def __init__(
        self,
        num_clients: int = 5,
        poly_modulus_degree: int = 8192,
    ) -> None:
        """
        Initialise the aggregator and CKKS encryption context.

        Args:
            num_clients:         Number of participating FL nodes.
            poly_modulus_degree: CKKS polynomial ring degree. 8192 gives 128-bit
                                 security with the chosen coefficient modulus sizes
                                 and supports vectors up to ~4096 floats — enough
                                 for the 272-element encoder weight vector.
        """
        self.num_clients: int = num_clients

        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=[60, 40, 40, 60],
        )
        self.context.global_scale = 2 ** 40
        self.context.generate_galois_keys()

        self.trust_scores: dict[int, float] = {i: 1.0 for i in range(num_clients)}
        self.f1_history: dict[int, list[float]] = {i: [] for i in range(num_clients)}
        self.round_number: int = 0
        self.weight_size: Optional[int] = None
        self.aggregation_log: list[dict] = []

    def encrypt_weights(self, weights: np.ndarray) -> "ts.CKKSVector":
        """
        Encrypt a flat numpy weight vector using CKKS.

        Individual node weights are encrypted before entering the aggregator.
        The aggregator performs FedAvg arithmetic on ciphertext and never sees
        individual node weights in plaintext.

        Args:
            weights: Flat numpy array of encoder weights, shape (272,).

        Returns:
            A TenSEAL CKKSVector containing the encrypted weights.
        """
        return ts.ckks_vector(self.context, weights.tolist())

    def aggregate(
        self,
        encrypted_weights: list,
        round_number: int,
    ) -> np.ndarray:
        """
        Compute reputation-weighted FedAvg on encrypted weight vectors.

        Steps:
          1. Normalise trust scores to sum to 1.0.
          2. Compute weighted sum entirely on ciphertext.
          3. Decrypt only the final aggregate.
          4. Trim CKKS padding artefacts to the true weight vector length.
          5. Log round statistics and increment round counter.

        Args:
            encrypted_weights: List of CKKSVector objects, one per client, in
                                node_id order (index 0 = node 0, etc.).
            round_number:      The current federation round number (1-indexed).

        Returns:
            Global encoder weight vector as a flat numpy array, shape (272,).
        """
        # Set weight_size on the first call so we can trim CKKS padding later
        if self.weight_size is None:
            self.weight_size = len(encrypted_weights[0].decrypt())

        # Normalise trust scores
        total: float = sum(self.trust_scores.values())
        norm: dict[int, float] = {
            i: self.trust_scores[i] / total for i in range(self.num_clients)
        }

        # Weighted sum on ciphertext — no plaintext intermediate
        global_enc = encrypted_weights[0] * norm[0]
        for i in range(1, self.num_clients):
            global_enc = global_enc + encrypted_weights[i] * norm[i]

        # Decrypt the aggregate and trim to exact weight size
        global_weights: np.ndarray = np.array(
            global_enc.decrypt()[: self.weight_size]
        )

        mean_w: float = float(np.mean(global_weights))
        std_w: float = float(np.std(global_weights))

        # Round-trip log for dashboard / analysis
        self.aggregation_log.append(
            {
                "round": round_number,
                "trust_scores": dict(self.trust_scores),
                "global_weight_mean": mean_w,
                "global_weight_std": std_w,
            }
        )

        self.round_number += 1

        norm_rounded: dict[int, float] = {i: round(norm[i], 3) for i in norm}
        print(
            f"Aggregator round {round_number} — weights decrypted | "
            f"mean: {mean_w:.4f} std: {std_w:.4f} | "
            f"trust: {norm_rounded}"
        )

        return global_weights

    def update_trust_scores(self, node_f1_scores: dict[int, float]) -> None:
        """
        Update per-node trust scores from the latest round's global F1 values.

        Trust score = mean of the last 3 global F1 scores for that node,
        clamped to a minimum of 0.1 so no node is fully excluded.

        Args:
            node_f1_scores: Dict mapping node_id (int) to global F1 (float)
                            for the round that just completed.
        """
        for node_id, f1 in node_f1_scores.items():
            self.f1_history[node_id].append(f1)
            recent: list[float] = self.f1_history[node_id][-3:]
            score: float = max(0.1, float(np.mean(recent)))
            self.trust_scores[node_id] = score

        highest_id: int = max(self.trust_scores, key=lambda k: self.trust_scores[k])
        lowest_id: int = min(self.trust_scores, key=lambda k: self.trust_scores[k])
        print(
            f"Trust updated — highest: Node {highest_id} "
            f"({self.trust_scores[highest_id]:.3f}) | "
            f"lowest: Node {lowest_id} ({self.trust_scores[lowest_id]:.3f})"
        )

    def get_trust_scores(self) -> dict[int, float]:
        """
        Return a copy of current trust scores keyed by node_id.

        Returns:
            Dict mapping node_id (int) to trust score (float).
        """
        return dict(self.trust_scores)

    def get_aggregation_log(self) -> list[dict]:
        """
        Return a copy of the per-round aggregation log.

        Each entry contains: round, trust_scores, global_weight_mean,
        global_weight_std.

        Returns:
            List of dicts, one per completed aggregation round.
        """
        return list(self.aggregation_log)

    def poison_node(self, node_id: int) -> None:
        """
        Manually set a node's trust score to the minimum value.

        Used in the poison demo to simulate the reputation system detecting
        a compromised node and down-weighting its contribution to aggregation.

        Args:
            node_id: The node to penalise.
        """
        self.trust_scores[node_id] = 0.1
        print(
            f"POISON DEMO: Node {node_id} trust score set to minimum (0.1) "
            f"— simulating reputation system detecting compromised node"
        )
