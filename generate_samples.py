"""Generate the public, entirely synthetic known-file pairs."""
from pathlib import Path
import hashlib

TAG = hashlib.shake_256(b"public synthetic WStop marker").digest(265)
KEY = hashlib.shake_256(b"public synthetic stream; never used by malware").digest(2**21)


def scramble(data: bytes, large: bool = False) -> bytes:
    result = bytearray(data)
    if large:
        for start in (0, len(data) // 2, len(data) - 65536):
            result[start:start + 65536] = bytes(
                a ^ b for a, b in zip(result[start:start + 65536], KEY[:65536], strict=True)
            )
        return bytes(result) + TAG
    return TAG + bytes(a ^ b for a, b in zip(data, KEY[:len(data)], strict=True))


if __name__ == "__main__":
    directory = Path(__file__).with_name("samples")
    directory.mkdir(exist_ok=True)
    for name, data in (
        ("pair-a.txt", b"Sample A: these contents were created for this repository.\n" * 5),
        ("pair-b.txt", b"Sample B: a different original verifies the recovered stream.\n" * 8),
        ("target.txt", b"Sample target: compare the reconstructed file with this original.\n" * 4),
    ):
        (directory / name).write_bytes(data)
        (directory / (name + ".wstop")).write_bytes(scramble(data))
