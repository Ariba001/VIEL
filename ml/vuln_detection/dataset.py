import pandas as pd
import torch
from torch_geometric.data import Data, Dataset

class ProgramGraphDataset(Dataset):
    def __init__(self, node_csv, edge_csv):
        super().__init__()
        self.nodes = pd.read_csv(node_csv)
        self.edges = pd.read_csv(edge_csv)
        self.graph_ids = self.nodes["graph_id"].unique()

    def len(self):
        return len(self.graph_ids)

    def get(self, idx):
        gid = self.graph_ids[idx]

        node_df = self.nodes[self.nodes.graph_id == gid]
        edge_df = self.edges[self.edges.graph_id == gid]

        node_map = {name: i for i, name in enumerate(node_df.node_id)}

        FEATURES = [
            "num_blocks",
            "num_calls",
            "alloca", "load", "store", "br", "icmp",
            "dangerous_calls"
        ]

        x = torch.tensor(
            node_df[FEATURES].values,
            dtype=torch.float
        )

        edge_index = []
        for _, row in edge_df.iterrows():
            if row.src in node_map and row.dst in node_map:
                edge_index.append([
                    node_map[row.src],
                    node_map[row.dst]
                ])

        if len(edge_index) == 0:
            edge_index = torch.empty((2, 0), dtype=torch.long)
        else:
            edge_index = torch.tensor(edge_index).t().contiguous()

        y = torch.tensor([node_df.label.iloc[0]], dtype=torch.long)

        return Data(x=x, edge_index=edge_index, y=y)
