import torch
from torch import nn


class Classifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(128, 2)

    def forward(self, x):
        return self.fc(x)


def evaluate(model: Classifier, batch: torch.Tensor) -> torch.Tensor:
    model.eval()
    with torch.no_grad():
        return model(batch).argmax(dim=-1)
