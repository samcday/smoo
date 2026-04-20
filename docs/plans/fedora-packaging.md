# Fedora Packaging Plan (smoo + supplemental Rust crates)

## Goal

Make non-vendored Fedora builds of `smoo` reliable by temporarily carrying missing Rust crate packages in-repo (under `copr/`), then upstreaming those crates to Fedora steadily until the local carry set is empty.


## Current State Survey (2026-02-26)

### What phrog does today

- `~/src/phrog/copr/` contains one directory per carried crate package.
- Typical crate directory contents are `rust2rpm.toml`, `*.spec`, and optional patch/changelog files.
- `~/src/phrog/copr/README.md` tracks crate build order for COPR chain builds.

### What smoo does today

- `smoo.spec` already has vendor/non-vendor toggles (`%bcond_without vendor`) but defaults to vendoring.
- `.packit.yaml` currently runs vendored builds (PR jobs explicitly pass `with_opts: [vendor]`; other jobs inherit vendored default from spec).
- There is no `copr/` crate-carry directory in `smoo` yet.

### Dependency gap snapshot (Fedora 43 + updates repos)

Scope used: external normal/build deps in the closure of `smoo-gadget-cli` + `smoo-host-cli`.

- 196 external crate names in scope.
- Crates missing entirely from Fedora repos:
  - `dma-heap`
  - `is_terminal_polyfill`
  - `macaddr`
  - `mmap`
  - `tempdir`
  - `usb-gadget`
- Missing needed compatibility stream:
  - `io-uring` `0.7.x` (Fedora currently has `0.6.x` and `0.5.x`)
- Practical impact:
  - `smoo-host-cli` is blocked only by `is_terminal_polyfill`.
  - `smoo-gadget-cli` is blocked by `dma-heap`, `io-uring 0.7`, `macaddr`, `mmap`, `tempdir`, `usb-gadget`, and also `is_terminal_polyfill`.

## Plan

## Phase 0: Make non-vendor path testable first

Before adding crate carry, ensure `smoo.spec` can be exercised in non-vendor mode in current Fedora macro environments.

- Verify and fix any macro incompatibilities in `%generate_buildrequires`, `%build`, and `%check`.
- Add a local validation command set for packaging work:
  - `rpmspec -q --buildrequires smoo.spec`
  - `mock --rebuild --without vendor <srpm>`

Exit criteria:

- Non-vendor buildrequires generation runs successfully.
- A non-vendor mock build fails only on missing crate packages (not spec/macro syntax).

## Phase 1: Add `copr/` carry tree to smoo

Create an in-repo carry area modeled on phrog:

- `copr/.gitignore` (at minimum ignore `**/*.crate` and `**/*.src.rpm`).
- `copr/README.md` with:
  - crate inventory
  - build order
  - generation/build commands
  - upstreaming status per crate

Initial crate carry set:

- `rust-is_terminal_polyfill`
- `rust-tempdir`
- `rust-mmap`
- `rust-macaddr`
- `rust-usb-gadget`
- `rust-dma-heap`
- `rust-io-uring0.7` (compat package stream)

Dependency-driven build order:

1. `rust-is_terminal_polyfill`
2. `rust-tempdir`
3. `rust-mmap` (depends on `tempdir`)
4. `rust-macaddr`
5. `rust-usb-gadget` (depends on `macaddr`)
6. `rust-dma-heap`
7. `rust-io-uring0.7`

## Phase 2: Wire COPR + Packit for iterative builds

- Stand up a dedicated dependency COPR project (recommended: `samcday/smoo-rust-deps`).
- Chain-build the carried crates in README order.
- Update smoo Packit jobs to consume the deps COPR via `additional_repos`.
- Add/enable at least one non-vendor PR build target (keep vendored build as fallback until stable).

Exit criteria:

- Packit PR build passes in non-vendor mode with only Fedora repos + `smoo-rust-deps` COPR.
- Vendored mode remains available as emergency fallback during migration.

## Phase 3: Upstream crates to Fedora steadily

For each carried crate:

- Open Fedora review request.
- Address review feedback and land in dist-git.
- Wait for build to appear in target Fedora releases used by smoo.
- Remove the crate from `smoo` `copr/` carry list and deps COPR once Fedora provides it.

Recommended upstream order (to unblock fastest):

1. `is_terminal_polyfill` (unblocks both host and gadget)
2. `tempdir` -> `mmap`
3. `macaddr` -> `usb-gadget`
4. `dma-heap`
5. `io-uring 0.7` compat

## Phase 4: De-vendor by default

Once dependency carry is stable and mostly upstreamed:

- Flip spec/Packit defaults to non-vendor builds.
- Keep vendored mode as explicit opt-in escape hatch only.
- Document policy in `README.md` (Fedora section) and `copr/README.md`.

Exit criteria:

- `smoo` builds in Fedora/COPR without vendoring by default.
- Carry set trends to zero as crates land upstream.

## Risks and Mitigations

- Macro behavior drift across Fedora versions: validate with `mock` for each target release before changing defaults.
- Feature-specific crate subpackages missing (not just base crate): validate non-vendor `buildrequires` output after every dependency bump.
- Stale carry set: require every carried crate to have an upstream tracking link/status in `copr/README.md`.

## Definition of Done

- Non-vendored `smoo` COPR/Packit builds pass on target Fedora arches.
- All carried crates have upstream review tickets filed.
- `copr/README.md` is the single source of truth for carry status and retirement.
