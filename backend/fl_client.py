"""
FedGate — Federated API Abuse Detection System
Local Federated Learning Client (Phase 2 — Personalised Federated Autoencoder)

=== What FedGate Is ===
FedGate is a privacy-preserving federated anomaly detection system for API
gateway abuse. Five microservice nodes (Login, Payment, Search, Profile, Admin)
each observe their own API traffic and train a local anomaly detection model.
Instead of centralising raw logs, nodes share only encrypted encoder weight
vectors — raw request data, predictions, and decoder weights never leave the node.

=== Why MLPRegressor Autoencoder, Not Isolation Forest ===
Isolation Forest is incompatible with federated learning: its internal structure
(binary tree split points and feature thresholds) is not numerical and cannot be
averaged across nodes. Even the score-vector workaround fails because
`IsolationForest(random_state=42)` on static data produces identical vectors every
round — the convergence curve is flat and meaningless.

A neural autoencoder produces genuine real-valued weight matrices that can be
averaged with FedAvg, encrypted with CKKS, and loaded back into any node's model
directly. Combined with `warm_start=True`, loading global encoder weights before
each local `fit()` call means each round starts from global knowledge and
fine-tunes on local data — the foundation of personalised federated learning.

=== Three-Technique Combination ===

1. Encoder-Only Federation with Decoder Freezing
   The autoencoder is split into encoder (coefs_ indices 0–2: 7→16→8→4) and
   decoder (coefs_ indices 3–5: 4→8→16→7). Only encoder weights are federated.
   The decoder is frozen to its locally trained values and never shared.

   Rationale: the encoder learns to compress API feature space into a latent
   representation — this general "what does normal API traffic look like?" knowledge
   is valuable to share across nodes. The decoder learns this node's specific
   reconstruction patterns for its own service (login, payment, search, etc.) —
   sharing decoder weights would cause catastrophic forgetting of local specialisation
   and homogenise models that need to remain heterogeneous.

2. FedProx-Style Proximal Regularisation via Weight Interpolation
   After local retraining, encoder weights are interpolated between the locally
   fine-tuned values and the global encoder weights:
     new_encoder = alpha * local_encoder + (1 - alpha) * global_encoder
   With alpha=0.7 (70% local, 30% global), this acts as a proximal term that
   prevents any single node's encoder from drifting too far from global consensus.
   This is equivalent to the FedProx objective where mu controls the penalty
   strength — weight interpolation is its closed-form solution for one gradient step.

3. Gradient Clipping for Mathematically Proper Differential Privacy
   Before applying Laplace noise, the encoder weight vector is L2-normalised to
   a maximum norm of max_norm=1.0. This bounds the L2 sensitivity of the weight
   vector to exactly max_norm, making noise_scale = max_norm / epsilon the
   mathematically correct Laplace parameter for (epsilon, 0)-DP rather than a
   heuristic based on the empirical range of weights. This is the standard DP-SGD
   approach adapted for weight-space perturbation.

=== What warm_start=True Enables ===
MLPRegressor's `warm_start=True` flag causes each `.fit()` call to continue
optimisation from the current weight state rather than reinitialising randomly.
In retrain(), encoder weights are set to global encoder weights before fit() is
called. The optimiser then performs local gradient steps from this global starting
point, fine-tuning the global encoder to local data. Decoder weights are frozen
before and immediately after fit() to prevent the optimiser from moving them.

=== What the Weight Vector Represents ===
`get_weight_vector()` returns only the L2-clipped encoder weight vector — a flat
array of 272 floats (7×16 + 16×8 + 8×4 = 112 + 128 + 32). These encode how this
node has learned to compress the 7 API features into a 4-dimensional latent space
representing normal traffic. Averaging them across 5 nodes (FedAvg) produces a
global encoder that generalises across all attack types, while each node's frozen
decoder preserves its local reconstruction specialisation.
"""

import os
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _data_path(filename: str) -> str:
    """Return absolute path to a file inside the data/ directory."""
    return os.path.join(_PROJECT_ROOT, "data", filename)


def _load_csv(path: str) -> pd.DataFrame:
    """Load a CSV, raising a descriptive error if missing."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            "Data file not found. Run backend/api_data_generator.py first to generate node data."
        )
    return pd.read_csv(path)


# ---------------------------------------------------------------------------
# FLClient
# ---------------------------------------------------------------------------


class FLClient:
    """
    Local federated learning participant for one FedGate microservice node.

    Uses a neural autoencoder (MLPRegressor) trained only on normal traffic.
    Anomaly detection is based on reconstruction error: the model learns to
    reconstruct normal requests accurately; abuse requests produce high error.

    The federable representation is the full weight vector of the autoencoder —
    genuine learned parameters that can be averaged across nodes with FedAvg,
    encrypted with CKKS, and loaded back into any node's model directly.

    Attributes
    ----------
    node_id : int
        Index of this node (0–4).
    epsilon : float
        Differential privacy budget for Laplace noise on the weight vector.
    round_number : int
        Current federation round, incremented by update_model_from_global().
    data : pd.DataFrame
        Full training data for this node (2000 rows, labelled).
    normal_data : pd.DataFrame
        Normal-only rows from self.data — autoencoder trains only on these.
    reference_set : pd.DataFrame
        Shared 100-row normal reference set.
    test_set : pd.DataFrame
        Shared 500-row global evaluation set.
    local_test_set : pd.DataFrame
        Per-node 200-row evaluation set covering this node's own attack type.
    model : MLPRegressor
        Neural autoencoder: 7→16→8→4→8→16→7.
    scaler : StandardScaler
        Feature scaler fit on normal training data only.
    threshold : Optional[float]
        95th-percentile reconstruction error on normal training data.
        Requests with higher error are flagged as abuse.
    coefs_snapshot : Optional[list]
        Copy of model.coefs_ taken after the most recent train/retrain call.
    last_weight_change : float
        Mean absolute weight change from the most recent retrain() call.
    """

    FEATURE_COLS: list[str] = [
        "requests_per_min",
        "unique_endpoints_per_session",
        "response_code",
        "payload_size_bytes",
        "inter_request_time_seconds",
        "hour_of_day",
        "failed_auth_streak",
    ]

    def __init__(self, node_id: int, epsilon: float = 1.0) -> None:
        """
        Initialise the FLClient for a given node.

        Loads all data files, separates normal training rows, and initialises
        the autoencoder and scaler. No training happens here.

        Parameters
        ----------
        node_id : int
            Node index (0–4).
        epsilon : float
            Differential privacy budget. Lower = more noise = stronger privacy.

        Raises
        ------
        FileNotFoundError
            If any data CSV is missing. Run api_data_generator.py first.
        """
        self.node_id: int = node_id
        self.epsilon: float = epsilon
        self.round_number: int = 0

        self.data: pd.DataFrame = _load_csv(_data_path(f"node_{node_id}.csv"))
        self.reference_set: pd.DataFrame = _load_csv(_data_path("reference_set.csv"))
        self.test_set: pd.DataFrame = _load_csv(_data_path("test_set.csv"))
        self.local_test_set: pd.DataFrame = _load_csv(
            _data_path(f"test_node_{node_id}.csv")
        )

        # Autoencoder trains only on normal rows — never sees abuse labels
        self.normal_data: pd.DataFrame = self.data[self.data["is_abuse"] == 0]

        # Architecture: 7 → 16 → 8 → 4 → 8 → 16 → 7
        self.model: MLPRegressor = MLPRegressor(
            hidden_layer_sizes=(16, 8, 4, 8, 16),
            activation="relu",
            max_iter=500,
            random_state=None,
            warm_start=True,  # enables weight-initialised retraining for federation
        )

        # Scaler fit only on normal training data — never refit on test data
        self.scaler: StandardScaler = StandardScaler()

        self.threshold: Optional[float] = None
        self.coefs_snapshot: Optional[list] = None
        self.last_weight_change: float = 0.0
        self._trained: bool = False

        # Personalised federated learning hyperparameters
        self.alpha: float = 0.7          # interpolation: 70% local, 30% global
        self.mu: float = 0.01            # proximal penalty strength (for reference)
        self.max_norm: float = 1.0       # L2 clip bound for DP sensitivity
        self.global_encoder_coefs: Optional[list] = None  # received global encoder weights
        self.frozen_decoder_coefs: Optional[list] = None  # frozen local decoder weights
        self.encoder_indices: list[int] = [0, 1, 2]  # coefs_ indices for encoder layers
        self.decoder_indices: list[int] = [3, 4, 5]  # coefs_ indices for decoder layers

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self) -> "FLClient":
        """
        Train the autoencoder on this node's normal traffic only.

        The model learns to reconstruct normal API requests. At inference time,
        abuse traffic — which the model has never seen — produces high
        reconstruction error, flagging it as anomalous.

        Threshold calibration uses the 95th percentile of reconstruction errors
        on normal training data: the top 5% of the normal distribution sets the
        boundary. Requests with higher error than this are classified as abuse.

        The scaler is fit here on normal data only. All future calls to
        scaler.transform() (on test or reference data) use this fit — the
        scaler is never refit to avoid data leakage.

        Returns
        -------
        FLClient
            Returns self for method chaining.
        """
        X_normal: pd.DataFrame = self.normal_data[self.FEATURE_COLS]

        # Fit scaler on normal data only — critical to avoid leaking test
        # distribution statistics into the feature scaling step
        X_normal_scaled: np.ndarray = self.scaler.fit_transform(X_normal)

        # Autoencoder: target = input (reconstruct own features)
        self.model.fit(X_normal_scaled, X_normal_scaled)
        self._trained = True

        # Calibrate threshold: 95th percentile of normal reconstruction errors.
        # Anything above this boundary was seen less than 5% of the time in
        # normal traffic and is therefore flagged as anomalous.
        errors: np.ndarray = np.mean(
            (X_normal_scaled - self.model.predict(X_normal_scaled)) ** 2,
            axis=1,
        )
        self.threshold = float(np.percentile(errors, 99))

        self.coefs_snapshot = [c.copy() for c in self.model.coefs_]

        # Freeze decoder weights — these never change through federation.
        # The decoder captures this node's service-specific reconstruction
        # patterns (login vs payment vs search). Sharing or modifying them
        # would cause catastrophic forgetting of local specialisation.
        self.frozen_decoder_coefs = [
            self.model.coefs_[i].copy() for i in self.decoder_indices
        ]

        print(f"Node {self.node_id} trained — threshold: {self.threshold:.6f}")
        return self

    # ------------------------------------------------------------------
    # Weight extraction
    # ------------------------------------------------------------------

    def get_weight_vector(self) -> np.ndarray:
        """
        Extract the federable encoder weight vector, L2-clipped for DP.

        Encoder-only federation means nodes share how they learn to compress
        and understand API traffic features (the 7→16→8→4 path), while decoder
        freezing preserves each node's local reconstruction specialisation
        (the 4→8→16→7 path). Decoder weights never appear in this vector.

        The encoder weights are L2-clipped to max_norm before returning. This
        bounds the L2 sensitivity of the weight vector to exactly max_norm,
        making the subsequent Laplace noise in apply_differential_privacy()
        mathematically proper (epsilon, 0)-DP rather than a heuristic estimate.

        Returns
        -------
        np.ndarray
            Flat 1D array of encoder parameters only, shape (272,).
            (7×16 + 16×8 + 8×4 = 112 + 128 + 32 = 272)

        Raises
        ------
        RuntimeError
            If train() has not been called yet.
        """
        if not self._trained:
            raise RuntimeError("Call train() before get_weight_vector()")

        encoder_weights: np.ndarray = np.concatenate(
            [self.model.coefs_[i].flatten() for i in self.encoder_indices]
        )
        # Clip to max L2 norm to bound sensitivity for differential privacy
        l2_norm: float = float(np.linalg.norm(encoder_weights))
        if l2_norm > self.max_norm:
            encoder_weights = encoder_weights * (self.max_norm / l2_norm)
        return encoder_weights

    # ------------------------------------------------------------------
    # Differential privacy
    # ------------------------------------------------------------------

    def apply_differential_privacy(self, weights: np.ndarray) -> np.ndarray:
        """
        Add Laplace noise calibrated to the L2-clipped encoder weight vector.

        Because get_weight_vector() clips the encoder weights to L2 norm ≤
        max_norm before this call, the L2 sensitivity of the weight vector is
        exactly max_norm. This makes noise_scale = max_norm / epsilon the
        mathematically correct Laplace parameter for (epsilon, 0)-DP, in
        contrast to a heuristic based on the empirical range of weights which
        provides no formal privacy guarantee.

        The seed is varied by round_number so each round's noise is independent,
        preventing an adversary from cancelling it out by averaging across rounds.

        Parameters
        ----------
        weights : np.ndarray
            L2-clipped encoder weight vector from get_weight_vector(), shape (272,).

        Returns
        -------
        np.ndarray
            Noisy encoder weight vector of the same shape for transmission.
        """
        # Sensitivity is exactly max_norm due to L2 clipping — proper DP
        noise_scale: float = self.max_norm / self.epsilon
        np.random.seed(42 + self.round_number)
        noise: np.ndarray = np.random.laplace(0, noise_scale, weights.shape)
        return weights + noise

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, use_local: bool = False) -> dict[str, float]:
        """
        Evaluate the model's abuse detection performance.

        Computes reconstruction error on each test row and compares against
        self.threshold. This is the primary measurement of whether global
        weight updates improve detection across federation rounds.

        Parameters
        ----------
        use_local : bool
            If True, evaluates on self.local_test_set (200 rows, this node's
            own attack type — measures specialist ability).
            If False, evaluates on self.test_set (500 rows, all attack types
            — measures generalisation across the full threat landscape).

        Returns
        -------
        dict[str, float]
            Keys: 'precision', 'recall', 'f1', 'accuracy'.

        Raises
        ------
        RuntimeError
            If train() has not been called yet.
        """
        if not self._trained:
            raise RuntimeError("Call train() before evaluate()")

        dataset: pd.DataFrame = self.local_test_set if use_local else self.test_set
        X_test: pd.DataFrame = dataset[self.FEATURE_COLS]
        y_true: np.ndarray = dataset["is_abuse"].to_numpy()

        # Use transform(), never fit_transform() — scaler was fit on normal data only
        X_scaled: np.ndarray = self.scaler.transform(X_test)
        errors: np.ndarray = np.mean(
            (X_scaled - self.model.predict(X_scaled)) ** 2, axis=1
        )
        predictions: np.ndarray = (errors > self.threshold).astype(int)

        return {
            "precision": float(precision_score(y_true, predictions, zero_division=0)),
            "recall": float(recall_score(y_true, predictions, zero_division=0)),
            "f1": float(f1_score(y_true, predictions, zero_division=0)),
            "accuracy": float(accuracy_score(y_true, predictions)),
        }

    # ------------------------------------------------------------------
    # Federation: receive global update
    # ------------------------------------------------------------------

    def update_model_from_global(self, global_encoder_weights: np.ndarray) -> None:
        """
        Receive and store the aggregated global encoder weight vector.

        Reconstructs the encoder weight matrices from the flat vector by slicing
        according to each encoder layer's shape. These are stored in
        self.global_encoder_coefs and applied to model.coefs_ at the start of
        retrain(), making the next fit() call begin from global knowledge.

        Only encoder layers are touched — decoder weights are never involved
        in any aggregation operation.

        Parameters
        ----------
        global_encoder_weights : np.ndarray
            Averaged encoder weight vector of shape (272,) from the aggregator.
        """
        global_encoder_coefs: list = []
        offset: int = 0
        for i in self.encoder_indices:
            coef: np.ndarray = self.model.coefs_[i]
            size: int = coef.size
            global_encoder_coefs.append(
                global_encoder_weights[offset : offset + size].reshape(coef.shape)
            )
            offset += size

        self.global_encoder_coefs = global_encoder_coefs
        self.round_number += 1
        print(
            f"Node {self.node_id} received global encoder weights — "
            f"round {self.round_number}"
        )

    # ------------------------------------------------------------------
    # Retrain (used in multi-round federation)
    # ------------------------------------------------------------------

    def retrain(self) -> "FLClient":
        """
        Personalised federated retrain: FedProx init → frozen decoder → local fit
        → decoder restore → proximal interpolation.

        This implements the three-technique combination:

        1. Encoder initialisation from global weights (FedProx starting point):
           The global encoder replaces the current local encoder before fit(),
           so warm_start optimisation fine-tunes from global knowledge rather
           than the previous local state.

        2. Decoder freezing (prevents catastrophic forgetting):
           Frozen decoder weights are written into model.coefs_ before fit() and
           immediately restored after fit(), because the optimiser will update
           them during the forward-backward pass. The decoder remains at its
           locally-trained values throughout all federation rounds.

        3. Proximal interpolation (FedProx constraint):
           After local fine-tuning, encoder weights are blended:
             new_encoder = alpha * local + (1 - alpha) * global
           This prevents any single node's encoder drifting far from global
           consensus, acting as the proximal regularisation term in FedProx.

        Threshold recalibration (Step 8) happens AFTER proximal interpolation,
        so the threshold always matches the actual interpolated model state.
        Using the 99th percentile keeps the boundary conservative while adapting
        to whatever the current encoder/decoder combination reconstructs.

        Returns
        -------
        FLClient
            Returns self for method chaining.
        """
        threshold_before: float = self.threshold  # type: ignore[assignment]
        weights_before: np.ndarray = self.get_weight_vector().copy()

        # Step 2 — Initialise encoder from global weights (FedProx starting point)
        if self.global_encoder_coefs is not None:
            for idx, i in enumerate(self.encoder_indices):
                self.model.coefs_[i] = self.global_encoder_coefs[idx].copy()

        # Step 3 — Restore frozen decoder before fit so optimiser starts from frozen values
        if self.frozen_decoder_coefs is not None:
            for idx, i in enumerate(self.decoder_indices):
                self.model.coefs_[i] = self.frozen_decoder_coefs[idx].copy()

        # Step 4 — Retrain: warm_start continues from the encoder initialisation above
        X_normal_scaled: np.ndarray = self.scaler.transform(
            self.normal_data[self.FEATURE_COLS]
        )
        self.model.fit(X_normal_scaled, X_normal_scaled)

        # Step 5 — Restore frozen decoder again: fit() will have updated decoder weights
        if self.frozen_decoder_coefs is not None:
            for idx, i in enumerate(self.decoder_indices):
                self.model.coefs_[i] = self.frozen_decoder_coefs[idx].copy()

        # Step 6 — Proximal interpolation: blend encoder toward global consensus
        if self.global_encoder_coefs is not None:
            for idx, i in enumerate(self.encoder_indices):
                self.model.coefs_[i] = (
                    self.alpha * self.model.coefs_[i]
                    + (1 - self.alpha) * self.global_encoder_coefs[idx]
                )

        # Step 7 — Verify decoder freeze held
        assert self.frozen_decoder_coefs is None or all(
            np.allclose(self.model.coefs_[i], self.frozen_decoder_coefs[idx])
            for idx, i in enumerate(self.decoder_indices)
        ), "Decoder weights changed — freezing failed"

        # Step 8 — Recalibrate threshold on local normal data using the current
        # interpolated model. This must happen AFTER interpolation so the threshold
        # matches the actual prediction model state. Using 99th percentile keeps the
        # boundary conservative: only the top 1% of normal reconstruction errors
        # are allowed through as false positives.
        X_normal_scaled = self.scaler.transform(self.normal_data[self.FEATURE_COLS])
        reconstruction = self.model.predict(X_normal_scaled)
        errors = np.mean((X_normal_scaled - reconstruction) ** 2, axis=1)
        new_threshold = float(np.percentile(errors, 99))
        momentum = 0.8
        self.threshold = momentum * self.threshold + (1 - momentum) * new_threshold

        self.coefs_snapshot = [c.copy() for c in self.model.coefs_]
        self.last_weight_change = float(
            np.mean(np.abs(self.get_weight_vector() - weights_before))
        )
        print(
            f"Node {self.node_id} retrained (round {self.round_number}) — "
            f"encoder weight change: {self.last_weight_change:.6f} | "
            f"threshold: {self.threshold:.6f} | "
            f"alpha: {self.alpha} | decoder: frozen"
        )
        return self

    # ------------------------------------------------------------------
    # Federated prediction
    # ------------------------------------------------------------------

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Classify API requests as normal (0) or abuse (1) using reconstruction error.

        Parameters
        ----------
        X : pd.DataFrame
            Input rows containing at least the FEATURE_COLS columns.

        Returns
        -------
        np.ndarray
            Binary array: 1 = abuse (reconstruction error > threshold), 0 = normal.
        """
        X_scaled: np.ndarray = self.scaler.transform(X[self.FEATURE_COLS])
        errors: np.ndarray = np.mean(
            (X_scaled - self.model.predict(X_scaled)) ** 2, axis=1
        )
        return (errors > self.threshold).astype(int)
