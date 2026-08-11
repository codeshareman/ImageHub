from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

VALID_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAn/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AL+AA//Z"
)

MODULE_PATH = Path(__file__).with_name("validate_public_assets.py")
SPEC = importlib.util.spec_from_file_location("validate_public_assets", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load validate_public_assets")
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class JPEGValidationTests(unittest.TestCase):
    def write_asset(self, root: Path, contents: bytes) -> tuple[Path, str]:
        sha256 = hashlib.sha256(contents).hexdigest()
        asset_path = root / "mrzzz/photos/objects/sha256" / sha256[:2] / f"{sha256}.jpg"
        asset_path.parent.mkdir(parents=True)
        asset_path.write_bytes(contents)
        return asset_path, sha256

    def validate_contents(self, contents: bytes, *, width: int = 1, height: int = 1) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repo_root = Path(temporary_directory)
            asset_path, sha256 = self.write_asset(repo_root, contents)
            ref = validator.VariantRef(
                photo_id="fixture",
                variant_name="card",
                asset_path=asset_path.relative_to(repo_root).as_posix(),
                sha256=sha256,
                width=width,
                height=height,
            )
            return validator.validate_object_file(repo_root, ref)

    def test_known_decodable_jpeg_has_expected_structural_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            asset_path = Path(temporary_directory) / "fixture.jpg"
            asset_path.write_bytes(VALID_JPEG)

            inspection = validator.inspect_jpeg(asset_path)

        self.assertEqual(inspection.width, 1)
        self.assertEqual(inspection.height, 1)
        self.assertFalse(inspection.has_metadata_segments)
        self.assertEqual(inspection.errors, ())

    def test_app1_metadata_segment_is_rejected_by_publish_gate(self) -> None:
        contents = VALID_JPEG[:2] + b"\xff\xe1\x00\x04xx" + VALID_JPEG[2:]

        errors = self.validate_contents(contents)

        self.assertEqual(len(errors), 1)
        self.assertIn("jpeg asset still contains APP1/APP13 metadata segments", errors[0])

    def test_app13_metadata_segment_is_rejected_by_publish_gate(self) -> None:
        contents = VALID_JPEG[:2] + b"\xff\xed\x00\x04xx" + VALID_JPEG[2:]

        errors = self.validate_contents(contents)

        self.assertEqual(len(errors), 1)
        self.assertIn("jpeg asset still contains APP1/APP13 metadata segments", errors[0])

    def test_truncated_jpeg_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            asset_path = Path(temporary_directory) / "truncated.jpg"
            asset_path.write_bytes(VALID_JPEG[:-2])

            inspection = validator.inspect_jpeg(asset_path)

        self.assertIn("missing EOI marker", inspection.errors)

    def test_zero_component_sof_is_rejected_by_publish_gate(self) -> None:
        sof_index = VALID_JPEG.index(b"\xff\xc0")
        contents = bytearray(VALID_JPEG)
        contents[sof_index + 9] = 0

        errors = self.validate_contents(bytes(contents))

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("SOF marker 0xc0 has an invalid component table", errors[0])

    def test_duplicate_sof_component_ids_are_rejected_by_publish_gate(self) -> None:
        contents = b"\xff\xd8\xff\xc0\x00\x0e\x08\x00\x01\x00\x01\x02\x01\x11\x00\x01\x11\x00\xff\xd9"

        errors = self.validate_contents(contents)

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("SOF marker 0xc0 contains duplicate component IDs", errors[0])

    def test_duplicate_sos_component_ids_are_rejected_by_publish_gate(self) -> None:
        contents = (
            b"\xff\xd8"
            b"\xff\xc0\x00\x0e\x08\x00\x01\x00\x01\x02\x01\x11\x00\x02\x11\x00"
            b"\xff\xda\x00\x0a\x02\x01\x00\x01\x00\x00\x3f\x00\xff\xd9"
        )

        errors = self.validate_contents(contents)

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("SOS marker references invalid SOF components", errors[0])

    def test_short_sos_header_is_rejected_without_crashing(self) -> None:
        sos_index = VALID_JPEG.index(b"\xff\xda")
        contents = VALID_JPEG[:sos_index] + b"\xff\xda\x00\x03\xff\xff\xd9"

        errors = self.validate_contents(contents)

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("SOS marker has an invalid scan header", errors[0])

    def test_second_sof_is_rejected_by_publish_gate(self) -> None:
        sof_index = VALID_JPEG.index(b"\xff\xc0")
        sof_length = int.from_bytes(VALID_JPEG[sof_index + 2:sof_index + 4], "big")
        sof_segment = VALID_JPEG[sof_index:sof_index + 2 + sof_length]
        sos_index = VALID_JPEG.index(b"\xff\xda")
        contents = VALID_JPEG[:sos_index] + sof_segment + VALID_JPEG[sos_index:]

        errors = self.validate_contents(contents)

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("multiple SOF markers are not permitted", errors[0])

    def test_empty_sos_header_is_rejected_by_publish_gate(self) -> None:
        sos_index = VALID_JPEG.index(b"\xff\xda")
        contents = VALID_JPEG[:sos_index] + b"\xff\xda\x00\x02\xff\xd9"

        errors = self.validate_contents(contents)

        self.assertIn("invalid JPEG structure", errors[0])
        self.assertIn("SOS marker has no component count", errors[0])

    def test_trailing_payload_is_rejected_by_publish_gate(self) -> None:
        errors = self.validate_contents(VALID_JPEG + b"private-canary")

        self.assertEqual(len(errors), 1)
        self.assertIn("trailing data after EOI marker", errors[0])

    def test_manifest_dimensions_must_match_sof_dimensions(self) -> None:
        errors = self.validate_contents(VALID_JPEG, width=2)

        self.assertEqual(len(errors), 1)
        self.assertIn("declared dimensions do not match JPEG SOF dimensions", errors[0])


if __name__ == "__main__":
    unittest.main()
