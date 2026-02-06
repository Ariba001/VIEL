import torch
from torch_geometric.loader import DataLoader
from dataset import ProgramGraphDataset
from graphsage import GraphSAGEClassifier
from gssplit import split_graphs

dataset = ProgramGraphDataset("csv/nodes.csv", "csv/edges.csv")
train_idx, val_idx, test_idx = split_graphs(dataset)

train_loader = DataLoader(dataset[train_idx], batch_size=16, shuffle=True)
val_loader = DataLoader(dataset[val_idx], batch_size=16)
test_loader = DataLoader(dataset[test_idx], batch_size=16)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

model = GraphSAGEClassifier(in_channels=2).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
criterion = torch.nn.CrossEntropyLoss()

def run_epoch(loader, train=False):
    total_loss = 0
    correct = 0
    total = 0

    model.train() if train else model.eval()

    for data in loader:
        data = data.to(device)

        if train:
            optimizer.zero_grad()

        out = model(data)
        loss = criterion(out, data.y)

        if train:
            loss.backward()
            optimizer.step()

        total_loss += loss.item()
        pred = out.argmax(dim=1)
        correct += (pred == data.y).sum().item()
        total += data.y.size(0)

    return total_loss / len(loader), correct / total

for epoch in range(1, 31):
    train_loss, train_acc = run_epoch(train_loader, train=True)
    val_loss, val_acc = run_epoch(val_loader)

    print(
        f"Epoch {epoch:02d} | "
        f"Train Acc: {train_acc:.3f} | "
        f"Val Acc: {val_acc:.3f}"
    )

test_loss, test_acc = run_epoch(test_loader)
print(f"\nTest Accuracy: {test_acc:.3f}")
