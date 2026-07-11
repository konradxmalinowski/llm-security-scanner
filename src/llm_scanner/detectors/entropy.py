from __future__ import annotations

import math
from collections import Counter

__all__ = ["shannon_entropy"]


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of *data* in bits per character.

    Implemented by hand (the stack is frozen — no numpy/scipy). This is the classic
    ``H = -sum(p * log2(p))`` over the observed symbol distribution of the string itself.

    Used as a gate on secret-pattern candidates: a random base64/hex credential scores
    high (roughly 3.5-5.0 bits/char), whereas a quoted pattern shape or a repeated-
    character placeholder such as ``sk-aaaaaaaaaaaaaaaaaaaa`` scores well below the gate,
    which is exactly the false-positive population we want to drop. An empty string has
    zero entropy by definition.
    """
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in Counter(data).values()
    )
