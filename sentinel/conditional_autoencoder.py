"""Research prototype: one encoder with workload-conditioned normalization.

It is intentionally not wired into the live detector yet. Train/evaluate it
against the existing per-workload models before claiming an improvement.
"""
import torch
import torch.nn as nn

class ConditionalAutoencoder(nn.Module):
    def __init__(self, input_dim, num_workload_types, hidden_dim=32, latent_dim=16):
        super().__init__()
        self.norm = nn.ModuleList([nn.LayerNorm(input_dim) for _ in range(num_workload_types)])
        self.encoder = nn.LSTM(input_dim, hidden_dim, num_layers=2, batch_first=True)
        self.to_latent = nn.Linear(hidden_dim, latent_dim)
        self.from_latent = nn.Linear(latent_dim, hidden_dim)
        self.decoder = nn.LSTM(input_dim, hidden_dim, num_layers=2, batch_first=True)
        self.output = nn.Linear(hidden_dim, input_dim)

    def forward(self, x, workload_id):
        if x.ndim == 2: x = x.unsqueeze(1)
        x = self.norm[workload_id](x)
        _, (h, _) = self.encoder(x)
        z = self.to_latent(h[-1])
        h0 = self.from_latent(z).unsqueeze(0).repeat(2, 1, 1)
        c0 = torch.zeros_like(h0)
        y, _ = self.decoder(x, (h0, c0))
        return self.output(y), z

    def anomaly_score(self, x, workload_id):
        y, _ = self.forward(x, workload_id)
        if x.ndim == 2: x = x.unsqueeze(1)
        return ((x - y) ** 2).mean(dim=(1, 2))
