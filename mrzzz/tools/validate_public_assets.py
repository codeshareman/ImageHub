from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

JPEG_SUFFIXES = {".jpg", ".jpeg"}
FORBIDDEN_SUFFIXES = {".heic", ".heif"}
OBJECT_ROOT = Path("mrzzz/photos/objects")
MANIFEST_PATH = Path("mrzzz/photos/manifests/photos.manifest.json")
TOP_LEVEL_REQUIRED_KEYS = {"schemaVersion", "assetProvider", "featuredCollections", "albums", "photos"}
ASSET_PROVIDER_REQUIRED_KEYS = {
    "type",
    "repo",
    "branch",
    "manifestPath",
    "assetPathPrefix",
    "ingressPathPrefix",
}
ALBUM_REQUIRED_KEYS = {"id", "title", "order", "coverPhotoId"}
ALBUM_OPTIONAL_KEYS = {"summary"}
PHOTO_REQUIRED_KEYS = {"id", "title", "takenAt", "albumIds", "variants"}
PHOTO_OPTIONAL_KEYS = {"caption"}
VARIANT_REQUIRED_KEYS = {"assetPath", "sha256", "mediaType", "width", "height"}
FEATURED_COLLECTION_REQUIRED_KEYS = {"title", "createdAt", "effectiveFrom", "photoIds"}
FEATURED_COLLECTION_OPTIONAL_KEYS = {"description", "tags"}
REPO_RE = re.compile(r"^[^/]+/[^/]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_PATH_RE = re.compile(r"^mrzzz/photos/objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})\.(jpe?g)$")
SOF_MARKERS = {
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
}


@dataclass(frozen=True)
class VariantRef:
    photo_id: str
    variant_name: str
    asset_path: str
    sha256: str
    width: int
    height: int


@dataclass(frozen=True)
class JPEGInspection:
    width: int | None
    height: int | None
    has_metadata_segments: bool
    errors: tuple[str, ...]


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_jpeg(path: Path) -> JPEGInspection:
    data = path.read_bytes()
    errors: list[str] = []
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return JPEGInspection(width=None, height=None, has_metadata_segments=False, errors=("missing SOI marker",))

    width: int | None = None
    height: int | None = None
    has_metadata_segments = False
    found_sof = False
    found_sos = False
    sof_component_ids: set[int] = set()
    found_eoi = False
    index = 2

    while index < len(data):
        if data[index] != 0xFF:
            errors.append(f"invalid marker alignment at byte {index}")
            break
        while index < len(data) and data[index] == 0xFF:
            index += 1
        if index >= len(data):
            errors.append("truncated marker after fill bytes")
            break
        marker = data[index]
        index += 1

        if marker == 0xD9:
            found_eoi = True
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if index + 2 > len(data):
            errors.append(f"truncated length for marker 0x{marker:02x}")
            break

        length = int.from_bytes(data[index:index + 2], "big")
        if length < 2:
            errors.append(f"invalid length {length} for marker 0x{marker:02x}")
            break
        segment_start = index + 2
        segment_end = index + length
        if segment_end > len(data):
            errors.append(f"segment 0x{marker:02x} overruns file length")
            break
        segment = data[segment_start:segment_end]

        if marker in {0xE1, 0xED}:
            has_metadata_segments = True

        if marker in SOF_MARKERS:
            if found_sof:
                errors.append("multiple SOF markers are not permitted")
                break
            if len(segment) < 6:
                errors.append(f"SOF marker 0x{marker:02x} too short")
                break
            component_count = segment[5]
            expected_segment_length = 6 + 3 * component_count
            if component_count < 1 or len(segment) != expected_segment_length:
                errors.append(f"SOF marker 0x{marker:02x} has an invalid component table")
                break
            component_ids = {segment[offset] for offset in range(6, len(segment), 3)}
            if len(component_ids) != component_count:
                errors.append(f"SOF marker 0x{marker:02x} contains duplicate component IDs")
                break
            parsed_height = int.from_bytes(segment[1:3], "big")
            parsed_width = int.from_bytes(segment[3:5], "big")
            if parsed_width < 1 or parsed_height < 1:
                errors.append(f"invalid SOF dimensions {parsed_width}x{parsed_height}")
                break
            width = parsed_width
            height = parsed_height
            sof_component_ids = component_ids
            found_sof = True

        if marker == 0xDA:
            if not found_sof:
                errors.append("SOS marker occurs before SOF marker")
                break
            if not segment:
                errors.append("SOS marker has no component count")
                break
            component_count = segment[0]
            expected_segment_length = 1 + 2 * component_count + 3
            if component_count < 1 or len(segment) != expected_segment_length:
                errors.append("SOS marker has an invalid scan header")
                break
            component_ids = {segment[offset] for offset in range(1, 1 + 2 * component_count, 2)}
            if len(component_ids) != component_count or not component_ids <= sof_component_ids:
                errors.append("SOS marker references invalid SOF components")
                break
            found_sos = True
            index = segment_end
            while index < len(data):
                if data[index] != 0xFF:
                    index += 1
                    continue
                if index + 1 >= len(data):
                    errors.append("truncated entropy-coded data marker")
                    index = len(data)
                    break
                next_byte = data[index + 1]
                if next_byte == 0x00 or 0xD0 <= next_byte <= 0xD7:
                    index += 2
                    continue
                if next_byte == 0xD9:
                    found_eoi = True
                    index += 2
                    break
                break
            if found_eoi:
                break
            continue

        index = segment_end

    if not found_sof:
        errors.append("missing SOF marker")
    if not found_sos:
        errors.append("missing SOS marker")
    if not found_eoi:
        errors.append("missing EOI marker")
    if found_eoi and index != len(data):
        errors.append("trailing data after EOI marker")

    return JPEGInspection(width=width, height=height, has_metadata_segments=has_metadata_segments, errors=tuple(errors))


def is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def is_rfc3339_datetime(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_exact_keys(label: str, payload: Any, required: set[str], optional: set[str] | None = None) -> list[str]:
    if not isinstance(payload, dict):
        return [f"{label} must be an object"]
    allowed = required | (optional or set())
    errors: list[str] = []
    for key in sorted(required - payload.keys()):
        errors.append(f"{label} missing required property {key}")
    for key in sorted(payload.keys() - allowed):
        errors.append(f"{label} has unexpected property {key}")
    return errors


def validate_manifest_shape(manifest: dict[str, Any]) -> list[str]:
    errors = validate_exact_keys("manifest", manifest, TOP_LEVEL_REQUIRED_KEYS)
    if errors:
        return errors
    if manifest.get("schemaVersion") != 1:
        errors.append("schemaVersion must equal 1")

    asset_provider = manifest["assetProvider"]
    errors.extend(validate_exact_keys("assetProvider", asset_provider, ASSET_PROVIDER_REQUIRED_KEYS))
    if isinstance(asset_provider, dict):
        if asset_provider.get("type") != "github-repo":
            errors.append("assetProvider.type must equal github-repo")
        repo = asset_provider.get("repo")
        if not isinstance(repo, str) or REPO_RE.fullmatch(repo) is None:
            errors.append("assetProvider.repo must be owner/repo")
        branch = asset_provider.get("branch")
        if not isinstance(branch, str) or not branch:
            errors.append("assetProvider.branch must be a non-empty string")
        if asset_provider.get("manifestPath") != str(MANIFEST_PATH):
            errors.append("assetProvider.manifestPath must point to mrzzz/photos/manifests/photos.manifest.json")
        if asset_provider.get("assetPathPrefix") != "mrzzz/photos/objects/":
            errors.append("assetProvider.assetPathPrefix must equal mrzzz/photos/objects/")
        if asset_provider.get("ingressPathPrefix") != "mrzzz/photos/inbox/":
            errors.append("assetProvider.ingressPathPrefix must equal mrzzz/photos/inbox/")

    featured_collections = manifest["featuredCollections"]
    if not isinstance(featured_collections, dict):
        errors.append("featuredCollections must be an object")
    else:
        for collection_name, collection in featured_collections.items():
            label = f"featuredCollections.{collection_name}"
            errors.extend(
                validate_exact_keys(
                    label,
                    collection,
                    FEATURED_COLLECTION_REQUIRED_KEYS,
                    FEATURED_COLLECTION_OPTIONAL_KEYS,
                )
            )
            if not isinstance(collection, dict):
                continue
            if not isinstance(collection.get("title"), str) or not collection["title"]:
                errors.append(f"{label}.title must be a non-empty string")
            if "description" in collection and not isinstance(collection.get("description"), str):
                errors.append(f"{label}.description must be a string")
            tags = collection.get("tags")
            if "tags" in collection:
                if not isinstance(tags, list):
                    errors.append(f"{label}.tags must be an array")
                else:
                    seen_tags: set[str] = set()
                    for tag in tags:
                        if not isinstance(tag, str) or not tag:
                            errors.append(f"{label}.tags entries must be non-empty strings")
                            continue
                        if tag in seen_tags:
                            errors.append(f"{label}.tags contains duplicate {tag}")
                        seen_tags.add(tag)
            if not is_rfc3339_datetime(collection.get("createdAt")):
                errors.append(f"{label}.createdAt must be an RFC3339 date-time string")
            if not is_rfc3339_datetime(collection.get("effectiveFrom")):
                errors.append(f"{label}.effectiveFrom must be an RFC3339 date-time string")
            photo_ids = collection.get("photoIds")
            if not isinstance(photo_ids, list):
                errors.append(f"{label}.photoIds must be an array")
                continue
            seen_photo_ids: set[str] = set()
            for photo_id in photo_ids:
                if not isinstance(photo_id, str) or not photo_id:
                    errors.append(f"{label}.photoIds entries must be non-empty strings")
                    continue
                if photo_id in seen_photo_ids:
                    errors.append(f"{label}.photoIds contains duplicate photo {photo_id}")
                seen_photo_ids.add(photo_id)

    albums = manifest["albums"]
    if not isinstance(albums, list):
        errors.append("albums must be an array")
    else:
        for index, album in enumerate(albums):
            label = f"albums[{index}]"
            errors.extend(validate_exact_keys(label, album, ALBUM_REQUIRED_KEYS, ALBUM_OPTIONAL_KEYS))
            if not isinstance(album, dict):
                continue
            if not isinstance(album.get("id"), str) or not album["id"]:
                errors.append(f"{label}.id must be a non-empty string")
            if not isinstance(album.get("title"), str) or not album["title"]:
                errors.append(f"{label}.title must be a non-empty string")
            if "summary" in album and not isinstance(album.get("summary"), str):
                errors.append(f"{label}.summary must be a string")
            if not is_non_negative_int(album.get("order")):
                errors.append(f"{label}.order must be a non-negative integer")
            if not isinstance(album.get("coverPhotoId"), str) or not album["coverPhotoId"]:
                errors.append(f"{label}.coverPhotoId must be a non-empty string")

    photos = manifest["photos"]
    if not isinstance(photos, list):
        errors.append("photos must be an array")
    else:
        for photo_index, photo in enumerate(photos):
            photo_label = f"photos[{photo_index}]"
            errors.extend(validate_exact_keys(photo_label, photo, PHOTO_REQUIRED_KEYS, PHOTO_OPTIONAL_KEYS))
            if not isinstance(photo, dict):
                continue
            if not isinstance(photo.get("id"), str) or not photo["id"]:
                errors.append(f"{photo_label}.id must be a non-empty string")
            if not isinstance(photo.get("title"), str) or not photo["title"]:
                errors.append(f"{photo_label}.title must be a non-empty string")
            if "caption" in photo and not isinstance(photo.get("caption"), str):
                errors.append(f"{photo_label}.caption must be a string")
            if not is_rfc3339_datetime(photo.get("takenAt")):
                errors.append(f"{photo_label}.takenAt must be an RFC3339 date-time string")
            album_ids = photo.get("albumIds")
            if not isinstance(album_ids, list):
                errors.append(f"{photo_label}.albumIds must be an array")
            else:
                seen_album_ids: set[str] = set()
                for album_id in album_ids:
                    if not isinstance(album_id, str) or not album_id:
                        errors.append(f"{photo_label}.albumIds entries must be non-empty strings")
                        continue
                    if album_id in seen_album_ids:
                        errors.append(f"{photo_label}.albumIds contains duplicate {album_id}")
                    seen_album_ids.add(album_id)
            variants = photo.get("variants")
            if not isinstance(variants, dict) or not variants:
                errors.append(f"{photo_label}.variants must be a non-empty object")
                continue
            for variant_name, variant in variants.items():
                variant_label = f"{photo_label}.variants.{variant_name}"
                errors.extend(validate_exact_keys(variant_label, variant, VARIANT_REQUIRED_KEYS))
                if not isinstance(variant, dict):
                    continue
                asset_path = variant.get("assetPath")
                if not isinstance(asset_path, str) or ASSET_PATH_RE.fullmatch(asset_path) is None:
                    errors.append(f"{variant_label}.assetPath must match mrzzz/photos/objects/sha256/<sha-prefix>/<sha256>.jpg")
                sha256 = variant.get("sha256")
                if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
                    errors.append(f"{variant_label}.sha256 must be 64 lowercase hex chars")
                if variant.get("mediaType") != "image/jpeg":
                    errors.append(f"{variant_label}.mediaType must equal image/jpeg")
                if not is_positive_int(variant.get("width")):
                    errors.append(f"{variant_label}.width must be a positive integer")
                if not is_positive_int(variant.get("height")):
                    errors.append(f"{variant_label}.height must be a positive integer")
    return errors


def collect_variant_refs(manifest: dict[str, Any]) -> tuple[list[VariantRef], list[str]]:
    errors: list[str] = []
    refs: list[VariantRef] = []
    album_ids = {album["id"] for album in manifest["albums"]}
    photo_ids: set[str] = set()
    for photo in manifest["photos"]:
        photo_id = photo["id"]
        if photo_id in photo_ids:
            errors.append(f"duplicate photo id: {photo_id}")
        photo_ids.add(photo_id)
        for album_id in photo["albumIds"]:
            if album_id not in album_ids:
                errors.append(f"photo {photo_id} references missing album {album_id}")
        for variant_name, variant in photo["variants"].items():
            asset_match = ASSET_PATH_RE.fullmatch(variant["assetPath"])
            if asset_match is None:
                continue
            path_prefix, path_sha256, _path_extension = asset_match.groups()
            sha256 = variant["sha256"]
            if path_prefix != sha256[:2] or path_sha256 != sha256:
                errors.append(
                    f"photo {photo_id} variant {variant_name} assetPath must embed the declared sha256 in both directory prefix and basename"
                )
                continue
            refs.append(
                VariantRef(
                    photo_id=photo_id,
                    variant_name=variant_name,
                    asset_path=variant["assetPath"],
                    sha256=sha256,
                    width=variant["width"],
                    height=variant["height"],
                )
            )

    for album in manifest["albums"]:
        if album["coverPhotoId"] not in photo_ids:
            errors.append(f"album {album['id']} references missing cover photo {album['coverPhotoId']}")

    for collection_name, collection in manifest["featuredCollections"].items():
        for photo_id in collection["photoIds"]:
            if photo_id not in photo_ids:
                errors.append(f"featured collection {collection_name} references missing photo {photo_id}")
    return refs, errors


def validate_object_file(repo_root: Path, ref: VariantRef) -> list[str]:
    errors: list[str] = []
    asset_path = repo_root / ref.asset_path
    if not asset_path.exists():
        return [f"missing asset file for photo {ref.photo_id} variant {ref.variant_name}: {ref.asset_path}"]
    if not asset_path.is_file():
        return [f"asset path is not a file for photo {ref.photo_id} variant {ref.variant_name}: {ref.asset_path}"]
    suffix = asset_path.suffix.lower()
    if suffix in FORBIDDEN_SUFFIXES:
        errors.append(f"forbidden public asset suffix {suffix}: {ref.asset_path}")
    if suffix not in JPEG_SUFFIXES:
        errors.append(
            f"unsupported public asset suffix {suffix}: {ref.asset_path}; only sanitized JPEG derivatives are publishable until non-JPEG metadata scanning exists"
        )
    actual_sha256 = compute_sha256(asset_path)
    if actual_sha256 != ref.sha256:
        errors.append(f"sha256 mismatch for {ref.asset_path}: manifest={ref.sha256} actual={actual_sha256}")
    if asset_path.parent.name != ref.sha256[:2] or asset_path.stem != ref.sha256:
        errors.append(f"asset path does not match sha256-derived location: {ref.asset_path}")

    inspection = inspect_jpeg(asset_path)
    for detail in inspection.errors:
        errors.append(f"invalid JPEG structure for {ref.asset_path}: {detail}")
    if inspection.width is not None and inspection.height is not None:
        if inspection.width != ref.width or inspection.height != ref.height:
            errors.append(
                f"declared dimensions do not match JPEG SOF dimensions for {ref.asset_path}: manifest={ref.width}x{ref.height} actual={inspection.width}x{inspection.height}"
            )
    if inspection.has_metadata_segments:
        errors.append(f"jpeg asset still contains APP1/APP13 metadata segments: {ref.asset_path}")
    return errors


def validate_unreferenced_assets(repo_root: Path, refs: list[VariantRef]) -> list[str]:
    errors: list[str] = []
    referenced = {ref.asset_path for ref in refs}
    for path in (repo_root / OBJECT_ROOT).rglob("*"):
        if path.name == ".gitkeep":
            continue
        if path.is_dir():
            continue
        relative = path.relative_to(repo_root).as_posix()
        if relative not in referenced:
            errors.append(f"unreferenced object asset: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MRZZZ public photo assets in ImageHub.")
    parser.add_argument("--repo-root", default=".", help="Path to the ImageHub repository root")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    manifest_path = repo_root / MANIFEST_PATH
    if not manifest_path.exists():
        print(f"missing manifest: {manifest_path}")
        return 1

    manifest = load_manifest(manifest_path)
    errors = validate_manifest_shape(manifest)
    if errors:
        for error in errors:
            print(error)
        return 1

    refs, ref_errors = collect_variant_refs(manifest)
    errors.extend(ref_errors)
    for ref in refs:
        errors.extend(validate_object_file(repo_root, ref))
    errors.extend(validate_unreferenced_assets(repo_root, refs))

    if errors:
        for error in errors:
            print(error)
        return 1

    print("ok: MRZZZ public photo assets validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
