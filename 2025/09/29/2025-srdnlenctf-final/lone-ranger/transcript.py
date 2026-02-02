from ecc import r, G1, G2
import hashlib

__all__ = ["Transcript"]


class Transcript:
    def __init__(self, label: str, separator: str = "") -> None:
        self.label = label
        self.separator = separator
        self.data = []

    def append(self, *args) -> None:
        for arg in args:
            if isinstance(arg, (G1, G2)):
                self.data.append(repr(arg))
            else:
                self.data.append(str(arg))

    def challenge(self) -> int:
        data_str = self.label + self.separator.join(self.data)
        digest = hashlib.sha256(data_str.encode()).hexdigest()
        return int(digest, 16) % r
