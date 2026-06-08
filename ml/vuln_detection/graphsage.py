"""
GraphSAGE binary classifier for graph-level vulnerability detection.

Architecture:
    SAGEConv(in, 64) → BN → ReLU → Dropout
    SAGEConv(64, 64) → BN → ReLU
    global_mean_pool ‖ global_max_pool  →  [128]
    Linear(128, 64)  → ReLU → Dropout
    Linear(64, 2)
"""

import torch
import torch.nn.functional as F
from torch import nn
from torch_geometric.nn import SAGEConv, global_mean_pool, global_max_pool


class GraphSAGEClassifier(nn.Module):
    def __init__(self, in_channels: int, hidden: int = 64, dropout: float = 0.3):
        super().__init__()

        self.conv1 = SAGEConv(in_channels, hidden)
        self.bn1   = nn.BatchNorm1d(hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.bn2   = nn.BatchNorm1d(hidden)

        self.head = nn.Sequential(
            nn.Linear(hidden * 2, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

        self.dropout = dropout

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.relu(x)

        # Readout: concatenate mean and max pooling
        x = torch.cat([global_mean_pool(x, batch),
                        global_max_pool(x, batch)], dim=1)

        return self.head(x)
