from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from generate_samples import KEY, TAG, scramble
from wstop_rescue import RescueError, learn, load_stream, recover_file


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def pair(self, name, data, large=False):
        original = self.root / name
        encrypted = self.root / (name + ".wstop")
        original.write_bytes(data)
        encrypted.write_bytes(scramble(data, large))
        return original, encrypted

    def test_independent_pairs_and_both_layouts(self):
        big = hashlib.shake_256(b"large sample").digest(2**21 + 5)
        small = hashlib.shake_256(b"small sample").digest(100000)
        sample = self.pair("a", big, large=True)
        second = self.pair("b", small)
        with redirect_stdout(StringIO()):
            model = learn([sample, second])
        for kind, original, size, mode in (
            ("small", small[:77777], False, "prefixed"),
            ("large", big[::-1], True, "three blocks"),
        ):
            _, encoded = self.pair(kind, original, size)
            out = self.root / (kind + ".restored")
            self.assertEqual(recover_file(encoded, out, model), mode)
            self.assertEqual(out.read_bytes(), original)
            with self.assertRaises(RescueError):
                recover_file(encoded, out, model)

    def test_rejects_mismatched_original_and_key_limit(self):
        a = self.pair("a", b"A" * 128)
        b = self.pair("b", b"B" * 300)
        with redirect_stdout(StringIO()):
            model = learn([a, b])
        _, encrypted = self.pair("c", b"C" * 301)
        with self.assertRaises(RescueError):
            recover_file(encrypted, self.root / "output", model)
        b[0].write_bytes(b"C" * 300)
        with self.assertRaises(RescueError), redirect_stdout(StringIO()):
            learn([a, b])

    def test_stream_manifest_and_marker_checks(self):
        metadata = self.root / "public.json"
        stream = KEY[:200]
        data = metadata.with_suffix(".bin")
        data.write_bytes(stream)
        metadata.write_text(json.dumps({
            "format": "wstop-stream-v1",
            "marker_sha256": hashlib.sha256(TAG).hexdigest(),
            "stream_bytes": len(stream),
            "stream_sha256": hashlib.sha256(stream).hexdigest(),
        }), encoding="utf-8")
        model = load_stream(metadata)
        original, encoded = self.pair("target", b"P" * 128)
        out = self.root / "restored"
        recover_file(encoded, out, model)
        self.assertEqual(out.read_bytes(), original.read_bytes())
        encoded.write_bytes(b"X" + encoded.read_bytes()[1:])
        with self.assertRaises(RescueError):
            recover_file(encoded, self.root / "wrong-marker", model)
        data.write_bytes(b"X" + stream[1:])
        with self.assertRaises(RescueError):
            load_stream(metadata)


if __name__ == "__main__":
    unittest.main()
