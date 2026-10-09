import os
import shutil
import tempfile
import unittest

from ztz import attested, guard, UntrustedPayloadError
from ztz.core.crypto import ZTZSigner, generate_keypair
from ztz.core.file_pin import FD_BINDING


class TestSdk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.keys = os.path.join(self.tmp, "keys")
        priv, _ = generate_keypair(out_dir=self.keys, name="root")
        self.model = os.path.join(self.tmp, "model.onnx")
        with open(self.model, "wb") as f:
            f.write(b"\x08\x07onnx-ish payload")
        ZTZSigner(priv).sign_file(self.model)
        self.unsigned = os.path.join(self.tmp, "rogue.onnx")
        with open(self.unsigned, "wb") as f:
            f.write(b"rogue")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_attested_yields_for_signed_file(self):
        with attested(self.model, trust_store=self.keys) as paths:
            self.assertEqual(len(paths), 1)
            if FD_BINDING:
                self.assertTrue(paths[0].startswith("/proc/self/fd/"))
            else:
                self.assertEqual(paths, [self.model])

    def test_attested_rejects_unsigned_before_block_runs(self):
        ran = False
        with self.assertRaises(UntrustedPayloadError):
            with attested(self.model, self.unsigned, trust_store=self.keys):
                ran = True
        self.assertFalse(ran)

    def test_attested_rejects_tampered_file(self):
        with open(self.model, "ab") as f:
            f.write(b"backdoor")
        with self.assertRaises(UntrustedPayloadError):
            with attested(self.model, trust_store=self.keys):
                pass

    def test_guard_checks_named_argument(self):
        @guard(trust_store=self.keys, targets=["path"])
        def load(path, other=None):
            with open(path, "rb") as f:
                return f.read()

        self.assertTrue(load(self.model).startswith(b"\x08\x07"))
        with self.assertRaises(UntrustedPayloadError):
            load(path=self.unsigned)

    @unittest.skipUnless(os.name == "nt", "mandatory pinning is Windows-specific")
    def test_file_pinned_during_block_and_released_after(self):
        @guard(trust_store=self.keys, targets=["path"])
        def load(path):
            with self.assertRaises(PermissionError):
                open(path, "ab")
            with open(path, "rb") as f:
                return f.read()

        load(self.model)
        with attested(self.model, trust_store=self.keys):
            with self.assertRaises(PermissionError):
                os.remove(self.model)
        with open(self.model, "ab"):
            pass

    @unittest.skipUnless(os.name == "nt", "mandatory pinning is Windows-specific")
    def test_open_writer_is_refused(self):
        with open(self.model, "ab"):
            with self.assertRaises(UntrustedPayloadError):
                with attested(self.model, trust_store=self.keys):
                    pass

    @unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")
    def test_yielded_path_survives_swap_of_original(self):
        with open(self.model, "rb") as f:
            original = f.read()
        with attested(self.model, trust_store=self.keys) as (load,):
            os.replace(self.unsigned, self.model)
            with open(load, "rb") as f:
                self.assertEqual(f.read(), original)

    @unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")
    def test_guard_passes_descriptor_to_function(self):
        @guard(trust_store=self.keys, targets=["path"])
        def load(path):
            return path

        self.assertTrue(load(self.model).startswith("/proc/self/fd/"))

    @unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")
    def test_keep_names_yields_named_link_to_descriptor(self):
        with open(self.model, "rb") as f:
            original = f.read()
        with attested(self.model, trust_store=self.keys, keep_names=True) as (load,):
            self.assertEqual(os.path.basename(load), "model.onnx")
            self.assertNotEqual(load, self.model)
            self.assertTrue(os.readlink(load).startswith("/proc/self/fd/"))
            os.replace(self.unsigned, self.model)
            with open(load, "rb") as f:
                self.assertEqual(f.read(), original)
        self.assertFalse(os.path.exists(os.path.dirname(load)), "link dir must be removed")

    @unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")
    def test_keep_names_separates_same_name_files(self):
        other_dir = os.path.join(self.tmp, "other")
        os.mkdir(other_dir)
        twin = os.path.join(other_dir, "model.onnx")
        shutil.copy(self.model, twin)
        shutil.copy(self.model + ".sig", twin + ".sig")
        with attested(self.model, twin, trust_store=self.keys, keep_names=True) as (a, b):
            self.assertEqual(os.path.basename(a), os.path.basename(b))
            self.assertNotEqual(a, b)

    @unittest.skipUnless(FD_BINDING, "descriptor binding is Linux-specific")
    def test_guard_keep_names(self):
        @guard(trust_store=self.keys, targets=["path"], keep_names=True)
        def load(path):
            return path

        self.assertTrue(load(self.model).endswith("/model.onnx"))

    @unittest.skipIf(FD_BINDING, "off Linux keep_names is a no-op")
    def test_keep_names_is_noop_without_descriptor_binding(self):
        with attested(self.model, trust_store=self.keys, keep_names=True) as paths:
            self.assertEqual(paths, [self.model])


if __name__ == "__main__":
    unittest.main()
