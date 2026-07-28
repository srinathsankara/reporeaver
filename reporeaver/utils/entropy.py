# SPDX-License-Identifier: MIT
import math
from typing import Dict


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())
