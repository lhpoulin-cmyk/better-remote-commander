"""Regression tests for UUID-bound HELIX-BIOS device-tree validation."""

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).parents[1] / "src/core/helix-bios-install-toolkit-v1.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("helix_bios_installer", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def fixture_tree(*, partition_uuid=installer.USB_UUID, partition_label=installer.USB_LABEL,
                 partition_fstype=installer.USB_FSTYPE, model="Cruzer Pop", disk_uuid=None):
    partition = {
        "name": "sdh1", "path": "/dev/sdh1", "type": "part",
        "uuid": partition_uuid, "label": partition_label, "fstype": partition_fstype,
        "size": 8_000_000_000, "model": None, "children": [],
    }
    disk = {
        "name": "sdh", "path": "/dev/sdh", "type": "disk",
        "uuid": disk_uuid, "label": None, "fstype": None,
        "size": 8_000_000_000, "model": model, "children": [partition],
    }
    return {"blockdevices": [disk]}


class DeviceTreeTests(unittest.TestCase):
    def test_pinned_baseline_hashes_are_full_sha256_values(self):
        for value in (installer.MANIFEST_SHA256, installer.PROCEDURE_SHA256,
                      installer.README_SHA256):
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_filesystem_fields_come_from_partition_and_hardware_from_parent(self):
        disk, partition = installer.select_usb_device(fixture_tree())
        self.assertEqual(disk["model"], "Cruzer Pop")
        self.assertEqual(disk["type"], "disk")
        self.assertIsNone(disk["uuid"])
        self.assertEqual(partition["type"], "part")
        self.assertEqual(partition["uuid"], installer.USB_UUID)
        self.assertEqual(partition["label"], "HELIX-BIOS")
        self.assertEqual(partition["fstype"], "vfat")

    def test_null_uuid_nodes_are_ignored_without_crashing(self):
        tree = fixture_tree(partition_uuid=None)
        with self.assertRaisesRegex(installer.DeploymentError, "resolved to 0 block entries"):
            installer.select_usb_device(tree)

    def test_parent_model_or_partition_filesystem_mismatch_is_refused(self):
        with self.assertRaisesRegex(installer.DeploymentError, "parent disk"):
            installer.select_usb_device(fixture_tree(model="Unrecognized USB"))
        with self.assertRaisesRegex(installer.DeploymentError, "USB partition"):
            installer.select_usb_device(fixture_tree(partition_fstype="ntfs"))

    def test_mount_mask_normalization_accepts_equivalent_fat_permissions(self):
        self.assertTrue(installer.has_private_fat_masks({"fmask=0077", "dmask=0077"}))
        self.assertTrue(installer.has_private_fat_masks({"umask=077"}))
        self.assertFalse(installer.has_private_fat_masks({"fmask=0022", "dmask=0022"}))
        self.assertFalse(installer.has_private_fat_masks({"fmask=0077"}))

    def test_duplicate_uuid_partitions_are_refused(self):
        tree = fixture_tree()
        duplicate = dict(tree["blockdevices"][0]["children"][0])
        duplicate["name"] = "sdh2"
        duplicate["path"] = "/dev/sdh2"
        tree["blockdevices"][0]["children"].append(duplicate)
        with self.assertRaisesRegex(installer.DeploymentError, "resolved to 2 block entries"):
            installer.select_usb_device(tree)


if __name__ == "__main__":
    unittest.main()
