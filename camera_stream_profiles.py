"""Fixed remaining image partitions; historical geometry is rechecked live."""
from dataclasses import dataclass

CHUNK_BYTES = 8388608


@dataclass(frozen=True)
class RemainingProfile:
    name: str
    minor: int
    size: int
    tiny_size: int

    @property
    def target(self):
        return self.name, self.minor, self.size

    @property
    def chunks(self):
        return (self.size + CHUNK_BYTES - 1) // CHUNK_BYTES


PROFILES = (
    RemainingProfile("cnflasha4", 132, 12582912, 10240),
    RemainingProfile("cnflasha8", 136, 67108864, 12288),
    RemainingProfile("cnflasha3", 131, 78643200, 9728),
    RemainingProfile("cnflasha5", 133, 314572800, 10240),
    RemainingProfile("cnflasha15", 143, 681574400, 9216),
    RemainingProfile("cnflasha10", 138, 12582912, 10240),
    RemainingProfile("cnflasha18", 146, 20971520, 10240),
    RemainingProfile("cnflasha23", 151, 67108864, 12288),
)


def profile(name):
    matches = [p for p in PROFILES if p.name == name]
    if len(matches) != 1:
        raise ValueError("Only fixed planned backup partitions are admitted")
    return matches[0]
