"""Reconstruct files for one observed WStop layout from known file pairs."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import sys
import tempfile

MARKER_BYTES = 265
BLOCK_BYTES = 65536
SUFFIX = re.compile(r"\.\[\[[a-z0-9]{8}\]\]\.\[\[[^\]]+@[^\]]+\]\]\.wstop$", re.I)


class RescueError(ValueError):
    """The input is outside the verified recovery model."""


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def positions(length: int) -> tuple[int, int, int]:
    return 0, length // 2, length - BLOCK_BYTES


@dataclass(frozen=True)
class Model:
    marker: bytes
    stream: bytes


def learn_pair(original: Path, damaged: Path) -> tuple[str, Model]:
    size = original.stat().st_size
    if size < 64 or damaged.stat().st_size != size + MARKER_BYTES:
        raise RescueError(f"Invalid pair sizes: {original.name}")
    with original.open("rb") as plain, damaged.open("rb") as cipher:
        if size >= 3 * BLOCK_BYTES:
            count = BLOCK_BYTES
            stream = xor(plain.read(count), cipher.read(count))
            valid = any(stream)
            previous = count
            for offset in positions(size)[1:]:
                if offset < previous:
                    valid = False
                    break
                while valid and previous < offset:
                    count = min(1024 * 1024, offset - previous)
                    valid = plain.read(count) == cipher.read(count)
                    previous += count
                valid = valid and xor(plain.read(BLOCK_BYTES), cipher.read(BLOCK_BYTES)) == stream
                previous = offset + BLOCK_BYTES
            if valid:
                return "three blocks", Model(cipher.read(MARKER_BYTES), stream)
        if size > 2 * 1024 * 1024:
            raise RescueError(f"Unsupported layout: {damaged.name}")
        plain.seek(0)
        cipher.seek(0)
        marker = cipher.read(MARKER_BYTES)
        stream = xor(plain.read(), cipher.read())
        if not any(stream):
            raise RescueError(f"Pair yielded no keystream: {damaged.name}")
        return "prefixed", Model(marker, stream)


def learn(pairs: list[tuple[Path, Path]]) -> Model:
    if len({p.resolve() for p, _ in pairs}) < 2 or len({q.resolve() for _, q in pairs}) < 2:
        raise RescueError("Provide at least two distinct original/encrypted pairs.")
    observations = [learn_pair(p, q) for p, q in pairs]
    best = max((model for _, model in observations), key=lambda model: len(model.stream))
    for (original, _), (layout, model) in zip(pairs, observations, strict=True):
        if model.marker != best.marker or model.stream != best.stream[:len(model.stream)]:
            raise RescueError(f"Pair does not match marker and keystream: {original.name}")
        print(f"{original.name}: {layout}, {len(model.stream):,} matching keystream bytes")
    return best


def recover_file(source: Path, target: Path, model: Model) -> str:
    length = source.stat().st_size - MARKER_BYTES
    if length < 0:
        raise RescueError("Input is too short.")
    if target.exists():
        raise RescueError("Output already exists.")
    with source.open("rb") as src:
        prefix = src.read(MARKER_BYTES)
        src.seek(length)
        trailer = src.read(MARKER_BYTES)
        if length == 0 and prefix == model.marker:
            mode = "empty original"
        elif prefix == model.marker and trailer != model.marker:
            if length > len(model.stream):
                raise RescueError(f"Needs {length:,} keystream bytes; have {len(model.stream):,}.")
            mode = "prefixed"
        elif trailer == model.marker and prefix != model.marker:
            if length < 4 * BLOCK_BYTES or len(model.stream) < BLOCK_BYTES:
                raise RescueError("Three-block layout or keystream length could not be verified.")
            mode = "three blocks"
        else:
            raise RescueError("Unrecognized or ambiguous marker.")
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as temp:
            temporary = Path(temp.name)
            try:
                if mode == "three blocks":
                    src.seek(0)
                    cursor = 0
                    for offset in positions(length):
                        remaining = offset - cursor
                        while remaining:
                            data = src.read(min(1024 * 1024, remaining))
                            if not data:
                                raise RescueError("Unexpected end of input.")
                            temp.write(data)
                            remaining -= len(data)
                        temp.write(xor(src.read(BLOCK_BYTES), model.stream[:BLOCK_BYTES]))
                        cursor = offset + BLOCK_BYTES
                elif mode == "prefixed":
                    src.seek(MARKER_BYTES)
                    temp.write(xor(src.read(length), model.stream[:length]))
                if temp.tell() != length:
                    raise RescueError("Reconstructed size does not match.")
                temp.close()
                # Exclusive creation also prevents overwrites on POSIX.
                created = False
                try:
                    with target.open("xb") as out, temporary.open("rb") as data:
                        created = True
                        shutil.copyfileobj(data, out)
                except OSError:
                    if created:
                        target.unlink(missing_ok=True)
                    raise
            finally:
                temp.close()
                temporary.unlink(missing_ok=True)
    return mode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("compare", "recover"))
    parser.add_argument("--pair", nargs=2, action="append", metavar=("ORIGINAL", "ENCRYPTED"), required=True)
    parser.add_argument("--input", type=Path, help="One .wstop file or a directory to scan")
    parser.add_argument("--output", type=Path, help="New directory for recovered copies")
    args = parser.parse_args(argv)
    try:
        model = learn([(Path(p), Path(q)) for p, q in args.pair])
        if args.mode == "compare":
            print(f"Verified common marker; longest matching stream: {len(model.stream):,} bytes.")
            return 0
        if args.input is None or args.output is None or not args.input.exists():
            raise RescueError("Recovery needs an existing --input and a new --output directory.")
        source_root = args.input.resolve()
        output = args.output.resolve()
        if source_root.is_dir() and output.is_relative_to(source_root):
            raise RescueError("Output must be outside the input tree.")
        args.output.mkdir(parents=True, exist_ok=False)
        candidates = sorted(source_root.rglob("*")) if source_root.is_dir() else [source_root]
        root = source_root if source_root.is_dir() else source_root.parent
        count = skipped = 0
        for source in candidates:
            if not source.is_file() or source.is_symlink() or source.suffix.lower() != ".wstop":
                continue
            relative = source.relative_to(root)
            name = SUFFIX.sub("", source.name)
            if name == source.name:
                name = source.stem
            destination = output / relative.with_name(name)
            try:
                if not source.resolve().is_relative_to(root) or not destination.resolve().is_relative_to(output):
                    raise RescueError("Path escapes the selected directory.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                layout = recover_file(source, destination, model)
                count += 1
                print(f"RECOVERED {relative} [{layout}]")
            except (OSError, ValueError) as error:
                skipped += 1
                print(f"SKIPPED {relative}: {error}", file=sys.stderr)
        print(f"Recovered: {count}; skipped: {skipped}. Validate output before replacing anything.")
        return 1 if skipped or not count else 0
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
