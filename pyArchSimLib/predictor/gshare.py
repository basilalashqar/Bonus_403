# File: pyArchSimLib/predictor/gshare.py
# --------------------------------------------------------------------
# A simple GShare branch predictor with 2-bit saturating counters.
#
# 
# Date  \ 23 May 2025

class GSharePredictor:
    def __init__(self, history_bits=10):
        self.H = history_bits
        self.table_size = 1 << self.H
        # 2-bit counters, init to weakly taken (2)
        self.counters = [2] * self.table_size
        self.history  = 0
        self.mask     = self.table_size - 1

        # Stats
        self.predictions    = 0
        self.mispredictions = 0

    def predict(self, pc: int) -> bool:
        idx = ((pc >> 2) ^ self.history) & self.mask
        return self.counters[idx] >= 2

    def update(self, pc: int, taken: bool):
        idx = ((pc >> 2) ^ self.history) & self.mask
        # adjust counter
        if taken:
            if self.counters[idx] < 3: self.counters[idx] += 1
        else:
            if self.counters[idx] > 0: self.counters[idx] -= 1
        # update history
        self.history = ((self.history << 1) | int(taken)) & self.mask

    def report(self) -> str:
        if self.predictions == 0:
            return "GShare: no branches predicted"
        correct = self.predictions - self.mispredictions
        acc = 100.0 * correct / self.predictions
        return f"GShare: {correct}/{self.predictions} correct ({acc:.2f}% accuracy)"
