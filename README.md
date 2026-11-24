# KeenProxy presets

Source recipes and versioned routing data for [KeenProxy](https://github.com/ordo-systems/keen-proxy). This repository publishes independently built presets and selected additions to older app presets. It does not republish the app's historical catalog. If a published ID matches an older app preset, the app adds only the published domains and retains the original metadata.

Edit `tools/presets/recipe.yaml` or the attributed seed files in `tools/presets/data/`. Domain entries are suffix rules: never add a shared CDN or public registration zone to represent one host. `only` limits a source part to exact entries, `exclude` removes exact entries, and `exclude_subtrees` removes an entire suffix tree. Filter names must be canonical lowercase DNS names.

```sh
go test ./...
go run ./tools/presets -dns
go run ./tools/presets -offline -check
```

The optional DNS check uses two public resolvers; it accepts `NODATA` for names used as wildcard suffixes. Generated output goes to `dist/`. Source archive and license hashes are checked before use. A preserved input snapshot is reviewed with recipe changes; see [third-party notices](THIRD_PARTY_NOTICES.md).

GitHub Actions builds on PRs and `main` without writing to branches. Push a reviewed `vX.Y.Z` tag to publish `presets.json`, `PRESET_SOURCES.md`, the source lock, the notices archive and `SHA256SUMS`. The publisher verifies hashes and does not overwrite an existing release. Consumers should pin the tag and checksum, not fetch `latest` at runtime.

Generator code and project-authored seed files use GPL-3.0-only. The preserved upstream data retains its own [licenses](LICENSES/).

The normal build and release do not depend on live DNS. Run the `Catalog` workflow manually to request a separate live DNS audit.
