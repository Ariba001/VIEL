"""
GraphSAGE node classifier for function-level vulnerability localization.

Unlike GraphSAGEClassifier (graph-level: "is this binary vulnerable?"),
this model scores every function node independently: "is THIS function
the vulnerable one?". No pooling — the call-graph topology (who calls
strcpy, who calls whom) still informs each node's embedding via message
passing, but the readout is per-node.

Architecture:
    SAGEConv(in, 64) → BN → ReLU → Dropout
    SAGEConv(64, 64) → BN → ReLU → Dropout
    SAGEConv(64, 64) → BN → ReLU
    Linear(64, 32) → ReLU → Dropout → Linear(32, 2)   (per-node logits)
"""

import torch.nn.functional as F
from torch import nn
from torch_geometric.nn import SAGEConv


class GraphSAGENodeClassifier(nn.Module):
    def __init__(self, in_channels: int, hidden: int = 64, dropout: float = 0.3):
        super().__init__()

        self.conv1 = SAGEConv(in_channels, hidden)
        self.bn1   = nn.BatchNorm1d(hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.bn2   = nn.BatchNorm1d(hidden)
        self.conv3 = SAGEConv(hidden, hidden)
        self.bn3   = nn.BatchNorm1d(hidden)

        self.head = nn.Sequential(
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, 2),
        )

        self.dropout = dropout

    def forward(self, x, edge_index):
        x = F.relu(self.bn1(self.conv1(x, edge_index)))
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = F.relu(self.bn2(self.conv2(x, edge_index)))
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = F.relu(self.bn3(self.conv3(x, edge_index)))

        return self.head(x)  # [N, 2] per-node logits
