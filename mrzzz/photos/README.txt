MRZZZ photo assets in ImageHub

Scope
- This tree is an asset-only publish source for MRZZZ photo content.
- It is consumed at build time from a public manifest.
- This repository does not implement MRZZZ backend adapters, sync jobs, or publishing logic.

Directories
- inbox/: PicGo upload landing zone only. Files here are not publishable.
- objects/sha256/: publishable public derivatives only. Each file path must be content-addressed as mrzzz/photos/objects/sha256/<sha-prefix>/<sha256>.jpg
- manifests/photos.manifest.json: public metadata source of truth for albums, featured collections, and photo variants.
- manifests/photos.manifest.schema.json: schema for the public manifest.

Publish rules
- Do not publish from legacy images/.
- Do not treat repository discovery as publication. Only files listed by photos.manifest.json are public.
- Published assets must be sanitized JPEG derivatives with no APP1 or APP13 metadata segments remaining.
- The manifest records relative asset paths only. It must not declare its own commit SHA.
- Build consumers must resolve one observed repository commit first, then fetch both the manifest and every referenced object from that same SHA, never from `main`.
- Commit-pinned URLs are produced later by the build-time consumer after resolving the observed repository commit.
- Once an object path is referenced by a released manifest snapshot, do not overwrite it. A new derivative must publish at a new sha256-derived path.

Validation
- Run: python3 mrzzz/tools/validate_public_assets.py --repo-root .
- The validator enforces the manifest schema shape in code, then checks cross-references, sha256/path binding, referenced-object allowlist, JPEG marker/segment structure, declared SOF dimensions, and JPEG metadata stripping requirements.
- It is intentionally stdlib-only. Decoder-based validation is an additional local check, not a publish-gate dependency.
