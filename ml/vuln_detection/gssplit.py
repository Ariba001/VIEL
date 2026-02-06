from sklearn.model_selection import train_test_split

def split_graphs(dataset, test_size=0.2, val_size=0.1):
    indices = list(range(len(dataset)))

    train_idx, test_idx = train_test_split(
        indices, test_size=test_size, random_state=42
    )

    train_idx, val_idx = train_test_split(
        train_idx, test_size=val_size, random_state=42
    )

    return train_idx, val_idx, test_idx
