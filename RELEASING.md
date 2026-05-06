# Releasing VectorPin

Cutting a release ships an updated Python wheel to PyPI and an updated
Rust crate to crates.io. Both ports must remain byte-for-byte compatible
with the published `testvectors/v1.json`, so the release is gated on
the cross-language test suite passing.

## Versioning

We follow semver. The protocol-version field (`v: 1` in the wire
format) is independent from the package version:

- **Protocol major bump** — incompatible wire format. v1 verifiers
  must reject v2 pins. Triggers a `vectorpin` major-version bump.
- **Protocol minor bump** — additive changes (new optional fields,
  new dtype identifiers, new signature algorithms with new
  identifiers). Old verifiers continue to verify old pins. Triggers
  a `vectorpin` minor-version bump.
- **Package patch bump** — bug fixes, dependency updates, doc-only
  changes. No protocol change.

## Pre-release checklist

Run all of these and only proceed when each is clean.

```bash
# 1. Python: lint + tests
source venv/bin/activate
ruff check .
pytest -v

# 2. Rust: fmt + clippy + tests
cd rust
cargo fmt --all -- --check
cargo clippy -j2 --all-targets -- -D warnings
cargo test -j2 --workspace
cd ..

# 3. Regenerate cross-language test vectors and confirm no drift
python scripts/generate_test_vectors.py
git diff --quiet testvectors/  # must be silent
```

## Cutting a release

1. **Update the version field in three places.** Bump
   `pyproject.toml` `[project] version`,
   `rust/Cargo.toml` `[workspace.package] version`, and the
   `version:` field in `CITATION.cff`. They must match.

2. **Update `CHANGELOG.md`.** Add a section for the new version
   describing what changed since the previous release. Include the
   release date in `YYYY-MM-DD` form.

3. **Commit the version bump as a single commit.**
   ```
   git commit -am "Release vX.Y.Z"
   ```

4. **Tag the commit.**
   ```
   git tag -a vX.Y.Z -m "VectorPin vX.Y.Z"
   git push origin main vX.Y.Z
   ```

5. **Build and publish the Python package.**
   ```
   pip install --upgrade build twine
   python -m build           # produces dist/vectorpin-X.Y.Z-*.whl and *.tar.gz
   twine check dist/*
   twine upload dist/*
   ```

6. **Publish the Rust crate.**
   ```
   cd rust/vectorpin
   cargo publish --dry-run   # verify it would publish cleanly
   cargo publish
   cd ../..
   ```

7. **Create the GitHub release.** The tag from step 4 will appear in
   the GitHub UI; convert it to a release with the changelog entry as
   the release notes. Attach `dist/vectorpin-X.Y.Z.tar.gz` for users
   who want a self-contained source archive.

8. **Update the companion preprint's `refs.bib`** to reference the
   tagged release if the paper is being revised.

## Post-release

- Watch for PyPI / crates.io install issues for ~24 hours.
- Open follow-up issues for any planned next-version work that this
  release deferred.
- If the protocol changed, tag the corresponding `testvectors/`
  release on the same git SHA so external implementations can fetch
  the correct fixtures.

## Yanking a release

If a published version contains a security or correctness bug:

```
# PyPI
twine yank vectorpin --version X.Y.Z --reason "<short reason>"

# crates.io
cargo yank --version X.Y.Z
```

Yanked versions remain installable via exact pin (so existing
deployments don't break), but new resolutions skip them. Always
release a fixed `X.Y.Z+1` immediately and update the changelog with
the yank notice.
