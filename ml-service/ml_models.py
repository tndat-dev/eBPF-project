"""
ml_models.py
------------
LSTM Autoencoder detector + Isolation Forest diagnostic for anomaly detection.

Pipeline:
  training_data/*.npy  →  train per-pod models  →  models/*.pkl + *.pt
  FeatureVector        →  inference              →  anomaly score [0,1]

Selected production score (V5): robust-tail-calibrated LSTM error. A calibrated
LSTM/IF mixture remains load-compatible as the rejected V6 ablation, but is not
the default because IF cannot split features that are constant in baseline.
Threshold: τ = 0.80 → trigger alert
"""

import os
import pickle
import logging
import hashlib
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("ml_models")


# ─────────────────────────────────────────────
# LSTM Autoencoder
# ─────────────────────────────────────────────

class SyscallAutoencoder(nn.Module):
    """
    LSTM Autoencoder học reconstruct normal syscall frequency vectors.
    Reconstruction error cao → anomaly.

    Architecture:
      Encoder: LSTM(input_dim → hidden_dim) → FC(hidden_dim → latent_dim)
      Decoder: FC(latent_dim → hidden_dim) → LSTM(input_dim → hidden_dim) → FC(hidden_dim → input_dim)
    """

    def __init__(self, input_dim: int, hidden_dim: int = 32, latent_dim: int = 16,
                 teacher_forcing: bool = False):
        super().__init__()
        self.input_dim  = input_dim
        self.hidden_dim = hidden_dim
        self.teacher_forcing = teacher_forcing

        # Encoder
        self.encoder = nn.LSTM(
            input_dim, hidden_dim, num_layers=2,
            batch_first=True, dropout=0.2
        )
        self.enc_fc = nn.Linear(hidden_dim, latent_dim)

        # Decoder
        self.dec_fc  = nn.Linear(latent_dim, hidden_dim)
        self.decoder = nn.LSTM(
            input_dim, hidden_dim, num_layers=2,   # input_dim → hidden_dim
            batch_first=True, dropout=0.2
        )
        self.out_fc  = nn.Linear(hidden_dim, input_dim)  # project ra input_dim

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, input_dim)
        _, (h_n, _) = self.encoder(x)
        z = self.enc_fc(h_n[-1])                          # (batch, latent_dim)

        # Dùng z để khởi tạo hidden state của decoder
        h_d = self.dec_fc(z).unsqueeze(0).repeat(2, 1, 1) # (2, batch, hidden_dim)
        c_d = torch.zeros_like(h_d)
        # V1 fed x directly back into the decoder. That shortcut can learn an
        # identity mapping and reconstruct an anomaly too well. V2 decodes
        # from the latent state with a zero start token. The behavior is
        # versioned so already-deployed V1 checkpoints remain load-compatible.
        decoder_input = x if self.teacher_forcing else torch.zeros_like(x)
        dec_out, _ = self.decoder(decoder_input, (h_d, c_d))
        out = self.out_fc(dec_out)                         # (batch, seq_len, input_dim)
        return out

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """MSE per sample."""
        recon = self.forward(x)
        return torch.mean((x - recon) ** 2, dim=(1, 2))


# ─────────────────────────────────────────────
# Per-pod Model Bundle
# ─────────────────────────────────────────────

class PodModelBundle:
    """
    Gói model cho 1 pod: LSTM Autoencoder + Isolation Forest + Scaler.
    """

    ANOMALY_THRESHOLD = 0.80   # τ trong đồ án
    LSTM_WEIGHT       = 0.8  # V6 ablation only
    IF_WEIGHT         = 0.2  # V6 ablation only
    MODEL_VERSION     = 7
    NORMAL_TAIL_SCORE = 0.20
    # Frequency features move in increments of roughly 1/events_per_window.
    # A near-zero StandardScaler variance would turn one ordinary extra event
    # into dozens of standard deviations. Keep a domain-level 1% floor while
    # leaving genuinely variable features untouched.
    FEATURE_SCALE_FLOOR = 0.01
    # V7 bounds the influence of any one previously rare n-gram. Attacks still
    # affect several independent suspicious dimensions, while a single benign
    # regime transition can no longer dominate the reconstruction MSE.
    FEATURE_CLIP = 10.0

    def __init__(self, pod_key: str, input_dim: int,
                 model_version: int = MODEL_VERSION):
        self.pod_key   = pod_key
        self.input_dim = input_dim
        self.model_version = model_version
        self.feature_scale_floor = self.FEATURE_SCALE_FLOOR
        self.feature_clip = self.FEATURE_CLIP if model_version >= 7 else None
        self.device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Stable per-workload initialization makes paper results reproducible.
        self.seed = int.from_bytes(
            hashlib.sha256(pod_key.encode("utf-8")).digest()[:4], "big"
        )
        torch.manual_seed(self.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.seed)

        self.autoencoder = SyscallAutoencoder(
            input_dim,
            teacher_forcing=(model_version < 2),
        ).to(self.device)
        self.iso_forest  = IsolationForest(
            n_estimators=100,
            contamination=0.05,   # giả sử 5% data có thể noisy
            random_state=42,
        )
        self.scaler          = StandardScaler()
        self.lstm_error_mean = 0.0  # baseline error để normalize
        self.lstm_error_std  = 1.0
        self.lstm_error_limit = 0.0
        self.lstm_error_scale = 1.0
        self.if_error_limit = 0.0
        self.if_error_scale = 1.0
        self.baseline_scores = []
        self.validation_scores = []
        # Learned by train_candidate from training-only unigram frequencies.
        # The detector uses these limits as independent, workload-conditioned
        # kernel evidence; they are deliberately separate from ML scores.
        self.behavior_limits = {}
        self.is_trained      = False

    @staticmethod
    def _fit_tail_scale(errors: np.ndarray) -> Tuple[float, float]:
        """Return a robust p99 normal-tail location and positive scale."""
        values = np.asarray(errors, dtype=float)
        median = float(np.median(values))
        mad = float(np.median(np.abs(values - median))) * 1.4826
        limit = max(float(np.quantile(values, 0.99)), median + 6.0 * mad)
        scale = max(limit - median, abs(limit) * 0.10, 1e-6)
        return limit, scale

    # ── Training ─────────────────────────────

    def train(self, X: np.ndarray,
              epochs: int = 50,
              batch_size: int = 16,
              lr: float = 1e-3,
              val_ratio: float = 0.2) -> dict:
        """
        Train LSTM Autoencoder + Isolation Forest trên normal data X.

        Args:
            X: shape (n_windows, vocab_size)
        Returns:
            history dict với train_loss, val_loss
        """
        if X.ndim != 2 or X.shape[1] != self.input_dim:
            raise ValueError(
                f"[{self.pod_key}] expected X=(n,{self.input_dim}), got {X.shape}"
            )
        if len(X) < 10:
            raise ValueError(f"[{self.pod_key}] cần ít nhất 10 windows, got {len(X)}")

        logger.info(f"[{self.pod_key}] Training trên X={X.shape}, device={self.device}")

        # ── Chuẩn bị data ──
        # Preserve temporal order and keep the newest windows as a true
        # holdout. Fit every preprocessing component on train only to avoid
        # optimistic leakage into validation metrics and thresholds.
        n_val = max(3, int(round(len(X) * val_ratio)))
        n_val = min(n_val, len(X) - 2)
        n_train = len(X) - n_val
        X_train_raw = X[:n_train]
        X_val_raw = X[n_train:]
        self.scaler.fit(X_train_raw)
        self.scaler.scale_ = np.maximum(
            self.scaler.scale_, self.feature_scale_floor
        )
        self.scaler.var_ = self.scaler.scale_ ** 2
        X_train = self.scaler.transform(X_train_raw).astype(np.float32)
        X_val = self.scaler.transform(X_val_raw).astype(np.float32)
        if self.model_version >= 7:
            X_train = np.clip(X_train, -self.feature_clip, self.feature_clip)
            X_val = np.clip(X_val, -self.feature_clip, self.feature_clip)

        # LSTM cần shape (batch, seq_len=1, features)
        def to_tensor(arr):
            return torch.tensor(arr, dtype=torch.float32).unsqueeze(1).to(self.device)

        generator = torch.Generator()
        generator.manual_seed(self.seed)
        train_loader = DataLoader(
            TensorDataset(to_tensor(X_train)),
            batch_size=batch_size, shuffle=True, generator=generator
        )

        # ── Train LSTM Autoencoder ──
        optimizer = torch.optim.Adam(self.autoencoder.parameters(), lr=lr)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=5, factor=0.5
        )
        best_val_loss = float('inf')
        best_state = {
            k: v.detach().clone() for k, v in self.autoencoder.state_dict().items()
        }
        patience_count = 0
        history = {"train_loss": [], "val_loss": []}

        self.autoencoder.train()
        for epoch in range(epochs):
            # Train
            train_losses = []
            for (batch,) in train_loader:
                optimizer.zero_grad()
                recon = self.autoencoder(batch)
                loss  = nn.MSELoss()(recon, batch)
                loss.backward()
                optimizer.step()
                train_losses.append(loss.item())

            # Validation
            self.autoencoder.eval()
            with torch.no_grad():
                val_tensor = to_tensor(X_val)
                val_recon  = self.autoencoder(val_tensor)
                val_loss   = nn.MSELoss()(val_recon, val_tensor).item()
            self.autoencoder.train()

            train_loss = np.mean(train_losses)
            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)
            scheduler.step(val_loss)

            # Early stopping
            if val_loss < best_val_loss - 1e-6:
                best_val_loss = val_loss
                patience_count = 0
                # Lưu best weights
                best_state = {k: v.clone() for k, v in
                              self.autoencoder.state_dict().items()}
            else:
                patience_count += 1
                if patience_count >= 10:
                    logger.info(f"  Early stop tại epoch {epoch+1}")
                    break

            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"  Epoch {epoch+1:3d}: "
                    f"train={train_loss:.6f}, val={val_loss:.6f}"
                )

        # Restore best weights
        self.autoencoder.load_state_dict(best_state)

        # Tính baseline error statistics trên train set
        self.autoencoder.eval()
        with torch.no_grad():
            errors = self.autoencoder.reconstruction_error(
                to_tensor(X_train)
            ).cpu().numpy()
        self.lstm_error_mean = float(np.mean(errors))
        self.lstm_error_std  = float(np.std(errors)) + 1e-8
        # V1 centered score=0.5 at the mean, so ordinary upper-half variation
        # often crossed 0.8. V5 anchors the robust upper normal tail at 0.2.
        self.lstm_error_limit, self.lstm_error_scale = self._fit_tail_scale(
            errors
        )
        logger.info(
            f"  LSTM baseline error: "
            f"mean={self.lstm_error_mean:.6f}, std={self.lstm_error_std:.6f}, "
            f"tail_limit={self.lstm_error_limit:.6f}, "
            f"tail_scale={self.lstm_error_scale:.6f}"
        )

        # ── Train Isolation Forest ──
        self.iso_forest.fit(X_train)
        if_errors = -self.iso_forest.score_samples(X_train)
        self.if_error_limit, self.if_error_scale = self._fit_tail_scale(if_errors)
        logger.info(f"  Isolation Forest trained trên {len(X_train)} train samples")
        logger.info(
            f"  IF baseline tail: limit={self.if_error_limit:.6f}, "
            f"scale={self.if_error_scale:.6f}"
        )

        self.is_trained = True
        # Persist empirical normal scores so runtime EVT/POT can derive a
        # workload-specific threshold without retaining raw training vectors.
        self.baseline_scores = [self.predict(row)[0] for row in X_train_raw]
        self.validation_scores = [self.predict(row)[0] for row in X_val_raw]
        logger.info(
            f"  Holdout scores: median={np.median(self.validation_scores):.4f}, "
            f"p95={np.quantile(self.validation_scores, 0.95):.4f}, "
            f"max={np.max(self.validation_scores):.4f}"
        )
        logger.info(f"[{self.pod_key}] ✅ Training hoàn thành!")
        return history

    # ── Inference ────────────────────────────

    def predict(self, x: np.ndarray) -> Tuple[float, float, float]:
        """
        Tính anomaly score cho 1 feature vector.

        Args:
            x: shape (vocab_size,)
        Returns:
            (ensemble_score, lstm_score, if_score) trong [0, 1]
        """
        if not self.is_trained:
            raise RuntimeError(f"Model cho {self.pod_key} chưa được train!")

        x_scaled = self.scaler.transform(x.reshape(1, -1)).astype(np.float32)
        if self.model_version >= 7:
            x_scaled = np.clip(x_scaled, -self.feature_clip, self.feature_clip)

        # LSTM score
        self.autoencoder.eval()
        with torch.no_grad():
            tensor = torch.tensor(
                x_scaled, dtype=torch.float32
            ).unsqueeze(1).to(self.device)
            error = self.autoencoder.reconstruction_error(tensor).item()

        # Normalize error → [0, 1] dùng sigmoid
        if self.model_version >= 4:
            normalized = (
                (error - self.lstm_error_limit) / self.lstm_error_scale
            )
            if self.model_version >= 5:
                # Put the empirical p99 normal tail at score=0.20. Crossing
                # the 0.80 alert threshold now requires an error roughly
                # 2.77 robust tail scales beyond normal, leaving a clear
                # margin between load variation and attack profiles.
                normalized += np.log(
                    self.NORMAL_TAIL_SCORE / (1.0 - self.NORMAL_TAIL_SCORE)
                )
        else:
            normalized = (
                (error - self.lstm_error_mean) / self.lstm_error_std
            )
        normalized = np.clip(normalized, -60.0, 60.0)
        lstm_score = float(1 / (1 + np.exp(-normalized)))

        # Isolation Forest score calibrated onto the same normal-tail scale.
        raw_if = self.iso_forest.score_samples(x_scaled)[0]
        if self.model_version == 6:
            if_normalized = (
                ((-raw_if) - self.if_error_limit) / self.if_error_scale
                + np.log(
                    self.NORMAL_TAIL_SCORE / (1.0 - self.NORMAL_TAIL_SCORE)
                )
            )
            if_score = float(1 / (1 + np.exp(-np.clip(if_normalized, -60, 60))))
        else:
            if_score = float(np.clip((-raw_if - 0.0) / 0.5, 0.0, 1.0))

        # Hard routing selects this deployment bundle; calibrated experts then
        # form a small unsupervised mixture. LSTM remains dominant so a weak IF
        # cannot erase a strong sequence anomaly.
        if self.model_version == 6:
            ensemble = self.LSTM_WEIGHT * lstm_score + self.IF_WEIGHT * if_score
        else:
            ensemble = lstm_score

        return float(ensemble), float(lstm_score), float(if_score)

    def is_anomaly(self, x: np.ndarray) -> Tuple[bool, float]:
        """
        Returns:
            (is_anomaly, ensemble_score)
        """
        score, _, _ = self.predict(x)
        return score >= self.ANOMALY_THRESHOLD, score

    # ── Persistence ──────────────────────────

    def save(self, model_dir: str = "models"):
        os.makedirs(model_dir, exist_ok=True)
        safe_key = self.pod_key.replace("/", "__")

        # Lưu LSTM weights
        torch.save(
            self.autoencoder.state_dict(),
            f"{model_dir}/{safe_key}_lstm.pt"
        )
        # Lưu IF + scaler + metadata
        bundle = {
            "iso_forest":       self.iso_forest,
            "scaler":           self.scaler,
            "lstm_error_mean":  self.lstm_error_mean,
            "lstm_error_std":   self.lstm_error_std,
            "lstm_error_limit": self.lstm_error_limit,
            "lstm_error_scale": self.lstm_error_scale,
            "if_error_limit":   self.if_error_limit,
            "if_error_scale":   self.if_error_scale,
            "input_dim":        self.input_dim,
            "pod_key":          self.pod_key,
            "is_trained":       self.is_trained,
            "baseline_scores":  self.baseline_scores,
            "validation_scores": self.validation_scores,
            "model_version":    self.model_version,
            "seed":             self.seed,
            "feature_scale_floor": self.feature_scale_floor,
            "feature_clip":       self.feature_clip,
            "behavior_limits":    self.behavior_limits,
        }
        with open(f"{model_dir}/{safe_key}_bundle.pkl", "wb") as f:
            pickle.dump(bundle, f)

        logger.info(f"[{self.pod_key}] Model saved → {model_dir}/")

    @classmethod
    def load(cls, pod_key: str, model_dir: str = "models") -> "PodModelBundle":
        safe_key = pod_key.replace("/", "__")

        with open(f"{model_dir}/{safe_key}_bundle.pkl", "rb") as f:
            bundle = pickle.load(f)

        # Bundles written before model versioning used decoder teacher forcing.
        # Defaulting them to V1 preserves their inference behavior.
        obj = cls(
            pod_key=bundle["pod_key"],
            input_dim=bundle["input_dim"],
            model_version=bundle.get("model_version", 1),
        )
        obj.iso_forest       = bundle["iso_forest"]
        obj.scaler           = bundle["scaler"]
        obj.lstm_error_mean  = bundle["lstm_error_mean"]
        obj.lstm_error_std   = bundle["lstm_error_std"]
        obj.lstm_error_limit = bundle.get("lstm_error_limit", 0.0)
        obj.lstm_error_scale = bundle.get("lstm_error_scale", 1.0)
        obj.if_error_limit   = bundle.get("if_error_limit", 0.0)
        obj.if_error_scale   = bundle.get("if_error_scale", 1.0)
        obj.is_trained       = bundle["is_trained"]
        obj.baseline_scores  = bundle.get("baseline_scores", [])
        obj.validation_scores = bundle.get("validation_scores", [])
        obj.seed             = bundle.get("seed", obj.seed)
        obj.feature_scale_floor = bundle.get("feature_scale_floor", 0.0)
        obj.feature_clip       = bundle.get(
            "feature_clip",
            obj.FEATURE_CLIP if obj.model_version >= 7 else None,
        )
        obj.behavior_limits    = bundle.get("behavior_limits", {})

        obj.autoencoder.load_state_dict(
            torch.load(
                f"{model_dir}/{safe_key}_lstm.pt",
                map_location=obj.device
            )
        )
        obj.autoencoder.eval()
        logger.info(f"[{pod_key}] Model loaded từ {model_dir}/")
        return obj


# ─────────────────────────────────────────────
# ModelManager — quản lý tất cả pod models
# ─────────────────────────────────────────────

class ModelManager:
    """
    Train và quản lý PodModelBundle cho toàn bộ cluster.
    """

    def __init__(self, model_dir: str = "models", vocab_path: str = "vocab.pkl"):
        self.model_dir  = model_dir
        self.vocab_path = vocab_path
        self._models: Dict[str, PodModelBundle] = {}

        # Load vocab
        with open(vocab_path, "rb") as f:
            self.vocab = pickle.load(f)
        self.vocab_size = len(self.vocab)
        logger.info(f"ModelManager: vocab_size={self.vocab_size}")

    def train_all(self, training_data_dir: str = "training_data") -> dict:
        """
        Train model cho tất cả pod có file .npy trong training_data_dir.
        """
        results = {}
        npy_files = sorted(Path(training_data_dir).glob("*.npy"))

        if not npy_files:
            logger.error(f"Không tìm thấy file .npy trong {training_data_dir}/")
            return results

        logger.info(f"Tìm thấy {len(npy_files)} pods cần train...")

        for npy_file in npy_files:
            # Decode pod_key từ filename
            pod_key = npy_file.stem.replace("__", "/", 1)
            X = np.load(str(npy_file))

            logger.info(f"\n{'='*50}")
            logger.info(f"Training: {pod_key} | X={X.shape}")

            model = PodModelBundle(pod_key=pod_key, input_dim=X.shape[1])
            history = model.train(X, epochs=200)
            model.save(self.model_dir)

            self._models[pod_key] = model
            results[pod_key] = {
                "shape": X.shape,
                "final_val_loss": history["val_loss"][-1],
                "epochs": len(history["val_loss"]),
                "holdout_score_median": float(np.median(model.validation_scores)),
                "holdout_score_p95": float(np.quantile(model.validation_scores, .95)),
                "holdout_score_max": float(np.max(model.validation_scores)),
            }

        logger.info(f"\n{'='*50}")
        logger.info(f"✅ Training hoàn thành: {len(results)} models")
        return results

    def load_all(self):
        """Load tất cả model đã save trong model_dir."""
        os.makedirs(self.model_dir, exist_ok=True)
        bundle_files = sorted(Path(self.model_dir).glob("*_bundle.pkl"))
        if not bundle_files:
            raise RuntimeError(f"No model bundles found in {self.model_dir}")
        errors = []
        for pkl_file in bundle_files:
            pod_key = pkl_file.stem.replace("__", "/", 1).replace("_bundle", "")
            try:
                model = PodModelBundle.load(pod_key, self.model_dir)
                if model.input_dim != self.vocab_size:
                    raise ValueError(
                        f"model input_dim={model.input_dim}, "
                        f"vocab_size={self.vocab_size}"
                    )
                self._models[pod_key] = model
            except Exception as e:
                logger.error(f"Lỗi load model {pod_key}: {e}")
                errors.append(f"{pod_key}: {e}")
        if errors:
            raise RuntimeError("Invalid model release: " + "; ".join(errors))
        logger.info(f"Loaded {len(self._models)} models")

    def score(self, pod_key: str, feature_vector: np.ndarray) -> Optional[dict]:
        """
        Tính anomaly score cho 1 pod + feature vector.

        Returns:
            dict với ensemble_score, lstm_score, if_score, is_anomaly
            None nếu pod chưa có model
        """
        if pod_key not in self._models:
            logger.debug(f"Chưa có model cho pod: {pod_key}")
            return None

        model = self._models[pod_key]
        ensemble, lstm, iso = model.predict(feature_vector)
        is_anom = ensemble >= PodModelBundle.ANOMALY_THRESHOLD

        return {
            "pod_key":        pod_key,
            "ensemble_score": round(ensemble, 4),
            "lstm_score":     round(lstm, 4),
            "if_score":       round(iso, 4),
            "is_anomaly":     is_anom,
            "threshold":      PodModelBundle.ANOMALY_THRESHOLD,
            "behavior_limits": dict(model.behavior_limits),
        }

    def get_model(self, pod_key: str) -> Optional[PodModelBundle]:
        return self._models.get(pod_key)

    def list_models(self) -> list:
        return list(self._models.keys())


# ─────────────────────────────────────────────
# Train script — chạy trực tiếp
# ─────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=" * 60)
    print("Training ML Models: LSTM Autoencoder + Isolation Forest")
    print("=" * 60)

    manager = ModelManager(
        model_dir="models",
        vocab_path="vocab.pkl",
    )

    results = manager.train_all(training_data_dir="training_data")

    print("\n" + "=" * 60)
    print("TRAINING RESULTS:")
    print("=" * 60)
    for pod_key, r in results.items():
        print(f"  {pod_key}")
        print(f"    Shape:         {r['shape']}")
        print(f"    Epochs:        {r['epochs']}")
        print(f"    Val Loss:      {r['final_val_loss']:.6f}")

    # Test inference với data bình thường
    print("\n" + "=" * 60)
    print("INFERENCE TEST (normal data):")
    print("=" * 60)
    manager.load_all()

    import os
    from pathlib import Path
    for npy_file in Path("training_data").glob("*.npy"):
        pod_key = npy_file.stem.replace("__", "/", 1)
        X = np.load(str(npy_file))

        # Test 5 samples
        scores = []
        for i in range(min(5, len(X))):
            result = manager.score(pod_key, X[i])
            if result:
                scores.append(result["ensemble_score"])

        avg_score = np.mean(scores) if scores else 0
        print(f"  {pod_key}")
        print(f"    Avg score (normal): {avg_score:.4f}  "
              f"{'⚠️ HIGH FP! (>0.75)' if avg_score > 0.75 else '✅ OK (<0.75)'}")

    print("\n✅ Models saved in ./models/")
    print("Bước tiếp theo: chạy anomaly_detector.py để detect realtime")
