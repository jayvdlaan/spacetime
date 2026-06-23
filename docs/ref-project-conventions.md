# Project Conventions Reference

This document defines the complete structural, naming, and organizational conventions used across the Airspace ecosystem. Any agent or contributor adding files, directories, crates, configs, Docker infrastructure, documentation, or tooling to a project based on this runtime must follow these rules.

This is the authoritative reference. When in doubt, match existing structure exactly.

---

## Table of Contents

- [Repository Layout](#repository-layout)
- [Super Project Structure](#super-project-structure)
- [Subproject Layering](#subproject-layering)
- [Directory Naming](#directory-naming)
- [Crate Organization](#crate-organization)
- [Crate Naming](#crate-naming)
- [Cargo.toml Conventions](#cargotoml-conventions)
- [Versioning](#versioning)
- [Release Readiness](#release-readiness)
- [Source Code Structure](#source-code-structure)
- [Module Organization](#module-organization)
- [Test Structure](#test-structure)
- [Documentation](#documentation)
- [Configuration Files](#configuration-files)
- [Docker](#docker)
- [IDE and Tooling](#ide-and-tooling)
- [Git](#git)
- [Environment Files](#environment-files)
- [Feature Flags](#feature-flags)
- [Licensing](#licensing)
- [Anti-Patterns](#anti-patterns)

---

## Repository Layout

The repository is organized as a **super project** — a top-level repo that aggregates subprojects as git submodules and provides shared infrastructure. See [Super Project Structure](#super-project-structure) for the full directory layout, rules, and rationale.

At a glance, the repo contains:

- **Subprojects** (git submodules) — self-contained with their own workspaces
- **Root-level directories** — `crates/`, `tools/`, `third-party/`, `external/`, `configs/`, `docker/`, `docs/`, `scripts/`
- **Root-level files** — `Cargo.toml`, `justfile`, `CLAUDE.md`, `README.md`, `.env`, `.gitmodules`
- **Dev container** — `.devcontainer/` for reproducible build environments

---

## Super Project Structure

A **super project** is the top-level repository that aggregates subprojects (git submodules) and provides shared infrastructure for building, testing, and deploying them together. Airspace is a super project.

### Directory layout

```
super-project/
├── crates/                # Workspace-level crates (glue, integration, shared types)
├── tools/                 # Developer tooling (build helpers, code generators, linters)
├── third-party/           # Vendored or forked third-party dependencies
├── external/              # First-party crates already owned by another super project
├── configs/               # Runtime configuration templates
│   ├── docker/            # Configs mounted into containers
│   │   ├── dev/
│   │   ├── int/
│   │   ├── test/
│   │   └── prod/
│   └── local/             # Configs for bare-metal local development
├── docker/                # Docker Compose orchestration
│   └── compose/
│       ├── dev/
│       ├── int/
│       ├── test/
│       └── prod/
├── docs/                  # Cross-project documentation
├── scripts/               # Shell scripts (prefer Justfiles at root)
├── subproject-a/          # Git submodule (framework, library, etc.)
├── subproject-b/          # Git submodule (service, application, etc.)
├── .cargo/                # Cargo aliases and build config
│   └── config.toml
├── .devcontainer/         # Dev container definition
│   └── devcontainer.json
├── .run/                  # IDE run configurations (IntelliJ)
├── Cargo.toml             # Workspace root (minimal members)
├── Cargo.lock             # Locked dependency set (committed)
├── justfile               # Task runner (preferred over scripts/)
├── .env                   # Environment variables (Docker BuildKit, etc.)
├── .gitmodules            # Submodule definitions
├── .gitignore             # Ignore rules
├── CLAUDE.md              # AI assistant instructions
└── README.md              # Project overview and quickstart
```

### Directory purposes

| Directory | Purpose |
|-----------|---------|
| `crates/` | Crates that exist at the super project level — integration glue, shared types, or workspace-wide utilities that don't belong in any single subproject. |
| `tools/` | Developer-facing tooling: build helpers, code generators, workspace linters. These are build-time aids, not runtime dependencies. May contain git submodules. |
| `third-party/` | Vendored or forked external dependencies that cannot be consumed from a registry as-is (patched forks, unreleased versions, license-isolated code). May contain git submodules (e.g., forked repos). |
| `external/` | First-party crates that are already part of another super project but are needed here. Referenced via path or registry, never duplicated. May contain git submodules pointing to the owning super project's repos. |
| `configs/` | Runtime configuration templates, organized by deployment tier. |
| `docker/` | Docker Compose orchestration files only. Dockerfiles live in the subproject they build. |
| `docs/` | Cross-project documentation (architecture, guides, ADRs). |
| `scripts/` | Shell scripts for tasks that cannot be expressed as just recipes. Prefer Justfiles over scripts where possible. |

### Dependency management with dev containers

Super projects use **dev containers** (`.devcontainer/`) to declare and manage host-level dependencies (compilers, system libraries, CLI tools). This ensures every contributor and CI runner works against the same toolchain without manual setup.

- The dev container definition is the single source of truth for build prerequisites.
- `README.md` points to the dev container as the primary setup path.
- Bare-metal setup instructions are secondary and must not diverge from what the container provides.

### Workspace package registry

Each super project maintains access to a **workspace package registry** for storing first-party crate artifacts. Subprojects publish to and consume from this registry for cross-super-project dependencies.

- Crates in `external/` reference artifacts from another super project's registry.
- The registry URL is configured in `.cargo/config.toml`.
- Only tagged releases (beta and stable) are published to the registry; dev builds are not.

### Super project documentation

Every super project provides project-level documentation at the root:

- **`CLAUDE.md`** — AI assistant instructions scoped to the super project. Describes the project structure, security model, build commands, and key conventions.
- **`README.md`** — Project overview, quickstart, and dev container setup.
- **`docs/`** — Cross-project documentation using the standard naming prefixes (`arch-*`, `guide-*`, `ref-*`, `plan-*`, `adr-*`).

Subprojects have their own `CLAUDE.md`, `README.md`, and `docs/` — the super project level covers concerns that span multiple subprojects.

### Rules

- **No loose source files at root.** All Rust code lives inside subprojects or `crates/`.
- **No build artifacts at root.** `target/` is gitignored.
- **Subprojects are self-contained.** Each has its own workspace, README, docs, and CLAUDE.md.
- **Shared infrastructure lives at root.** `crates/`, `tools/`, `third-party/`, `external/`, `configs/`, `docker/`, `docs/`, `scripts/`.
- **Dockerfiles live in the subproject** they build, not in `docker/`.
- **Prefer Justfiles over scripts.** Use `scripts/` only when a task requires a standalone shell script. Simple automation belongs in the root `justfile`.
- **Dev containers are mandatory.** The `.devcontainer/` definition must be kept in sync with actual build requirements.
- **`external/` is read-only in spirit.** Crates there are owned by another super project — local patches should be upstreamed, not maintained as forks.

---

## Subproject Layering

Subprojects in the repository form a dependency stack. Dependencies must only point downward — a subproject at layer N may depend on layers < N but never on layers > N.

```
Applications (nanopass, etc.)       — Layer 3: Services
         ↓
      nanokey                       — Layer 2: Crypto boundary
         ↓
   framework extensions (airframe-srv)  — Layer 1b: Framework extensions
         ↓
      airframe                      — Layer 1a: Core framework
         ↓
      spacetime                     — Layer 0: Platform abstraction
```

### Extension layer

Framework extension projects sit between the core framework and the services that consume them. They provide reusable server infrastructure (sessions, rate limiting, caching) without bloating the core framework.

Extension projects:

- **Depend downward only.** May depend on the parent framework and spacetime, never on services.
- **Are library-only.** No binaries, no Dockerfiles, no configs. They exist to be consumed by service projects.
- **Inherit the parent's conventions.** Naming, edition, resolver, and license match the parent framework.
- **Are separate git submodules.** Even though they extend the parent framework, they are independent repositories registered as submodules in the root workspace.

### Rules

- **No upward dependencies.** A framework crate must never depend on a service crate.
- **No lateral dependencies between services** at the same layer (nanopass does not depend on nanokey directly for types — use shared extension crates instead).
- **When a crate is reusable across services**, migrate it to an extension project rather than leaving it in a service subproject.

---

## Directory Naming

| Context | Convention | Examples |
|---------|-----------|----------|
| Super project infrastructure dirs | Lowercase, plural | `crates/`, `tools/`, `third-party/`, `external/`, `configs/`, `docker/`, `docs/`, `scripts/` |
| Environment tiers | Lowercase, abbreviated | `dev/`, `int/`, `test/`, `prod/` |
| Crate directories (kebab projects) | `kebab-case` | `spacetime-core/`, `spacetime-logging/` |
| Crate directories (snake projects) | `snake_case` | `airframe_core/`, `airframe_http/` |
| Source subdirectories | `snake_case` | `src/http/`, `src/services/`, `src/bus/` |
| Documentation dirs | Lowercase | `docs/`, `docs/adr/` |

### Environment tier order

When tiers appear as subdirectories, use this fixed set and order:

1. `dev` — Local Docker development (relaxed settings, debug logging)
2. `int` — Integration environment
3. `test` — Automated test environment (CI, compose-driven test suites)
4. `prod` — Production (hardened, minimal logging)

Do not invent additional tiers. If you need a variant within a tier, use compose overlays or config file suffixes (see [Configuration Files](#configuration-files)).

---

## Crate Organization

Every subproject uses the `crates/` directory to house its member crates. There is no code at the subproject root — only metadata.

```
subproject/
├── Cargo.toml             # Workspace definition (members list)
├── Cargo.lock             # May or may not be committed (see Git section)
├── justfile               # Subproject task runner (optional)
├── README.md              # Project overview
├── CLAUDE.md              # AI assistant instructions
├── IMPLEMENTATION_PLAN.md # Roadmap (optional)
├── crates/
│   ├── project-core/      # Core types, traits, no_std primitives
│   ├── project-module/    # Module system integration
│   ├── project-macros/    # Procedural macros (separate crate, always)
│   ├── libproject/        # Shared types (for service projects)
│   ├── project/           # Main binary / server crate
│   ├── project_cli/       # CLI tool
│   └── project_client/    # HTTP client SDK
├── docs/                  # Project-specific documentation
└── Dockerfile             # Container build (if deployable)
```

### Subproject justfiles

Subprojects may include their own `justfile` for standalone development. Subproject justfiles provide recipes relevant to that subproject's workflow (build, test, run, lint). The super project root justfile orchestrates across subprojects; subproject justfiles are for working within a single subproject.

Standard recipes for subproject justfiles:

| Recipe | Description |
|--------|-------------|
| `build` | `cargo build --workspace` |
| `test` | `cargo test --workspace` |
| `clippy` | `cargo clippy --workspace` |
| `fmt` | `cargo fmt --all` |
| `fmt-check` | `cargo fmt --all -- --check` |
| `run` | Run the main binary (service subprojects only) |
| `doc` | `cargo doc --workspace --no-deps` |

Subproject justfiles are optional — contributors can always use `cargo` directly or use the super project root justfile. They are most valuable for service subprojects (nanokey, nanopass) where the run command has flags and environment setup.

### Extension projects

When a framework accumulates crates that are reusable across services but don't belong in the core framework (e.g., server-specific concerns like sessions, rate limiting, secret caching), extract them into a **framework extension** subproject rather than expanding the parent framework.

```
parent-framework/          # Core framework (e.g., airframe)
parent-framework-ext/      # Extension project (e.g., airframe-srv)
├── Cargo.toml             # Own workspace
├── crates/
│   ├── parent_ext_component_a/
│   └── parent_ext_component_b/
└── ...
```

The extension project name is `{parent}-{scope}` (kebab-case directory), where `{scope}` describes the domain (e.g., `srv` for server extensions). Crate names use the pattern `{parent}_{scope}_{component}` following the parent's naming convention.

**When to create an extension project vs. adding crates to the parent:**

- The parent framework is `no_std`-capable or has strict layering — the new crates would violate those constraints.
- The crates have dependencies (e.g., `zeroize`, `serde`) that shouldn't become transitive deps of the core framework.
- Multiple services will depend on the crates but they aren't universally needed by all framework consumers.

### Rules

- **All crates under `crates/`.** Never place crate directories at the subproject root.
- **One concern per crate.** Do not combine the server binary with the shared types library.
- **Service projects** use `lib{project}` for shared types, `{project}` for the server, `{project}_cli` for CLI, `{project}_client` for client SDK.
- **Framework/library projects** use `{project}_{component}` naming for all crates.
- **Framework extension projects** use `{parent}_{scope}_{component}` naming. The extension follows the parent's naming convention (snake_case if parent is snake_case).
- **Proc-macro crates** are always separate. Name them `{project}-macros` or `{project}_macros`.

---

## Crate Naming

Crate names follow the naming convention of their parent project. Pick one convention per project and apply it uniformly.

| Project type | Convention | Pattern | Examples |
|-------------|-----------|---------|----------|
| Platform/runtime libraries | `kebab-case` | `{project}-{component}` | `spacetime-core`, `spacetime-logging` |
| Application frameworks | `snake_case` | `{project}_{component}` | `airframe_core`, `airframe_http` |
| Framework extensions | `snake_case` | `{parent}_{scope}_{component}` | `airframe_srv_sessions`, `airframe_srv_ratelimit` |
| Game-specific isolates | `snake_case` | `{parent}_{engine}_{component}` | `afterburner_rage_client`, `jetfuel_red_core` |
| Services (shared types) | `snake_case` | `lib{project}` | `libnanokey`, `libnanopass` |
| Services (binary) | `snake_case` | `{project}` | `nanokey`, `nanopass` |
| Services (CLI) | `snake_case` | `{project}_cli` | `nanokey_cli`, `nanopass_cli` |
| Services (client SDK) | `snake_case` | `{project}_client` | `nanokey_client`, `nanopass_client` |

### Rules

- **Never mix** kebab-case and snake_case crate names within the same project.
- **Crate directory name must match** the crate name in `Cargo.toml` (with hyphens for kebab, underscores for snake).
- **Prefer short, descriptive component names.** `http` not `http_server_module`. `kv` not `key_value_store`.
- **When scope matches the component, use `core`.** Extension crates that wrap the engine itself use `{parent}_{scope}_core` — never repeat the scope. Example: `afterburner_red_core` not `afterburner_red_red`.

---

## Cargo.toml Conventions

### Workspace root (repo-level)

```toml
[workspace]
members = [
    # Only include crates that must be testable from repo root.
    # Subprojects with their own workspace are included selectively.
    "subproject-a/crates/main_crate",
]
resolver = "2"

[workspace.package]
edition = "2021"
license = "Apache-2.0 OR MIT"
homepage = "https://github.com/org"
repository = "https://github.com/org/project"
documentation = "https://github.com/org/project"
```

### Subproject workspace

```toml
[workspace]
members = [
    "crates/project-core",
    "crates/project-module",
    # ... all crates in dependency order
]
resolver = "2"

[workspace.package]
version = "0.1.0-beta"
license = "MIT"
repository = "https://git.vdlaan.io/core/project"
homepage = "https://git.vdlaan.io/core/project"
documentation = "https://git.vdlaan.io/core/project#readme"
```

### Individual crate

```toml
[package]
name = "project-component"
version.workspace = true        # Inherit from workspace
edition.workspace = true        # Inherit from workspace
license.workspace = true        # Inherit from workspace

[dependencies]
# Internal deps use relative paths
sibling-crate = { path = "../sibling-crate" }
# Cross-subproject deps use relative paths from crate to target
framework_crate = { path = "../../../framework/crates/framework_crate" }

[features]
default = []
alloc = []
std = ["alloc"]
```

### Rules

- **Workspace resolver**: Use `"3"` for new projects using edition 2024. Legacy projects on edition 2021 use `"2"`. Match the resolver of the parent framework when creating extension projects.
- **Edition**: Use `2024` for new projects. Legacy projects on `2021` may stay until a coordinated migration.
- **Version**: Inherit from workspace via `version.workspace = true`. The version is defined once in `[workspace.package]`. See [Versioning](#versioning) for lifecycle rules.
- **License and metadata**: Inherit from workspace via `.workspace = true`.
- **Internal dependencies**: Always use relative `path` references, never crates.io versions for workspace-local crates.
- **Cross-subproject dependencies**: Use relative paths (`../../../other/crates/crate`).
- **Patch directives**: Use `[patch.crates-io]` in subproject workspace roots to resolve local paths during monorepo development. Extension projects must duplicate any patch entries from their parent framework that their crates transitively depend on (e.g., if airframe patches `spacetime-core`, `airframe-srv` must also patch `spacetime-core`).

---

## Versioning

All crates within a subproject share a single version, defined in the subproject workspace root and inherited by member crates via `version.workspace = true`.

### Workspace version inheritance

The version is defined once in the subproject's `Cargo.toml`:

```toml
[workspace.package]
version = "0.7.0-beta"
```

Each member crate inherits it:

```toml
[package]
name = "project-component"
version.workspace = true
```

Dependency version specifiers in `[dependencies]` sections are **not** changed — they remain explicit strings (e.g., `version = "0.7.0-beta"`).

### Version lifecycle

Versions follow a three-phase lifecycle using SemVer pre-release suffixes:

```
0.7.0                  ← stable release
    │
0.7.1-dev.1            ← development (not for external use)
0.7.1-dev.2
    │
0.7.1-beta.1           ← stabilization (feature-complete, testing)
0.7.1-beta.2
    │
0.7.1                  ← stable release
```

| Phase | Suffix | Purpose |
|-------|--------|---------|
| Development | `-dev.N` | Active work, breaking changes expected |
| Beta | `-beta.N` | Feature-complete, bug fixes only |
| Release | (none) | Stable, published to registry |

The numeric suffix (`.N`) increments with each registry publish within that phase.

### Starting a new release

When beginning work on a new release, the scope is often unclear. Start with the minimum version bump (patch) and adjust upward as scope becomes clear:

```
0.7.0                  ← current release
    │
0.7.1-dev.1            ← start with patch assumption
0.7.1-dev.2
    │                   ← scope grows — breaking changes needed
0.8.0-dev.1            ← bump to minor (one-line change in workspace root)
0.8.0-dev.2
    │
0.8.0-beta.1           ← stabilize
0.8.0                  ← release
```

This works because:

- Pre-release versions are never matched by normal SemVer ranges (`^0.7` will not resolve to `0.7.1-dev.1`).
- The version number can be freely changed during development since `-dev.N` builds are internal.
- Old dev builds remain in the registry as historical artifacts but nothing depends on them.
- With `version.workspace = true`, changing the version triplet is a one-line edit.

### Registry publishing

Crates are published to the private Forgejo registry at `git.vdlaan.io` (sparse index). The existing `publish-all.sh` script handles phased publishing in dependency order.

Pre-release versions (`-dev.N`, `-beta.N`) are valid SemVer and can be published to the registry. They will not be picked up by consumers using standard `^x.y.z` requirements.

### Git tagging

Tags are per-subproject using the format `{subproject}/v{version}`:

```
spacetime/v0.2.0
airframe/v0.5.0
nanokey/v0.7.0-beta.1
```

Tags are created for beta and stable releases, not for dev builds.

### Rules

- **One version per subproject.** All crates within a subproject share the same version via `version.workspace = true`.
- **Start small, bump up.** Begin new development with a patch bump (`-dev.1`). Increase to minor or major when scope is known.
- **Never skip beta.** All releases pass through `-beta.N` before becoming stable.
- **Increment the suffix, not the triplet.** Within a phase, go from `-dev.1` to `-dev.2`, not from `-dev.1` to a new triplet.
- **Tag betas and releases.** Use `{subproject}/v{version}` format.

---

## Release Readiness

Every spacetime-based project progresses through four maturity phases before it is considered production-ready.

> For the end-to-end process of taking a project from development to a public
> release on crates.io (with a history-truncated mirror), see the
> [Release Runbook](guide-release.md) — an agent-executable runbook with
> drop-in templates in [`docs/templates/`](templates/).

### Maturity phases

| Phase | Version suffix | Description |
|-------|---------------|-------------|
| **Alpha** | `-dev.N` | Active exploration and prototyping. APIs are unstable, features are incomplete, and breaking changes are expected between any two builds. Not suitable for any use outside of the development team. |
| **Beta** | `-beta.N` | Core functionality works end-to-end. APIs are stabilising but may still change based on testing feedback. Suitable for internal integration testing but not for production workloads. |
| **Pre-release** | `-rc.N` | Functionality is frozen. No new features are added. Only cleanup, polish, documentation improvements, and addition of tooling (scripts, CI, Docker infrastructure) are permitted. Bug fixes are accepted only for issues discovered during final validation. |
| **Stable** | (none) | The release is production-ready. All requirements below are met, the version carries no pre-release suffix, and the release is tagged and published. |

### Release requirements

A project may only move from pre-release to stable when **all** of the following conditions are satisfied:

1. **No compiler warnings.** `cargo build --workspace` and `cargo clippy --workspace` produce zero warnings across all subprojects.
2. **Conventions compliance.** The project follows all conventions defined in this document (ref-project-conventions.md).
3. **No monoliths.** Concerns are properly separated into distinct crates following the crate organisation rules. No single crate bundles unrelated responsibilities.
4. **Documentation is complete and up to date.** All crate READMEs, cross-project docs, and architecture documents accurately reflect the current state of the code.
5. **Unit test coverage at 80%.** Measured across all subprojects. Every crate meets or exceeds 80% line coverage.
6. **No dead code.** No legacy code paths, completed migrations, orphaned modules, or otherwise unreachable code may remain. All test data and fixtures from earlier phases are invalidated — no backwards compatibility with pre-release artefacts is maintained.
7. **Integration tests provided.** Integration tests must be present for all crates where cross-boundary testing is feasible.
8. **Docker Compose for all environments.** The four standard tiers (`dev`, `int`, `test`, `prod`) each have Docker Compose files suited for their purpose, following the layout defined in the [Docker](#docker) section.
9. **Docker dev container.** A development container is provided so contributors can work without installing the full toolchain on their host.
10. **Clean-room buildable.** The project must build successfully on a fresh installation (or container) using only the instructions provided in the project's `README.md`. No implicit host dependencies or undocumented setup steps.

---

## Source Code Structure

### Standard crate layout

```
crate-name/
├── Cargo.toml
├── README.md              # Always present
├── build.rs               # Only if needed
├── src/
│   ├── lib.rs             # Library entry point (most crates)
│   ├── main.rs            # Binary entry point (server/CLI crates only)
│   ├── module.rs          # ModuleDescriptor (if framework-integrated)
│   ├── error.rs           # Error types
│   ├── {domain}.rs        # Domain logic files (auth.rs, users.rs, vaults.rs)
│   ├── http/              # HTTP handlers and route models (if applicable)
│   │   ├── mod.rs
│   │   └── {resource}.rs
│   └── services/          # Service implementations (if applicable)
│       ├── mod.rs
│       └── {service}.rs
├── tests/                 # Integration tests
│   └── {test_name}.rs
└── examples/              # Runnable examples
    └── {example_name}.rs
```

### Rules

- **`lib.rs` is the default entry point.** Binary crates also have `main.rs`.
- **Flat `src/` preferred.** Use individual `.rs` files, not deeply nested directories.
- **Subdirectories only for thematic grouping.** `http/`, `services/`, `bus/` — when there are 3+ related files.
- **Subdirectories use `mod.rs`** as their entry point.
- **One file per concern.** `error.rs` for errors, `module.rs` for the module descriptor, domain files for domain logic.
- **File names are `snake_case`.** Always. No exceptions.
- **Large files are acceptable.** Consolidation of related logic in a single file (e.g., all routes) is preferred over excessive fragmentation.

---

## Module Organization

### File-per-module pattern (preferred)

```rust
// src/lib.rs
pub mod auth;
pub mod error;
pub mod module;
pub mod users;
pub mod vaults;
```

Each module is a single file in `src/`:

```
src/
├── lib.rs
├── auth.rs
├── error.rs
├── module.rs
├── users.rs
└── vaults.rs
```

### Directory module pattern (for thematic groups)

When a group has 3+ closely related files:

```
src/
├── lib.rs
├── http/
│   ├── mod.rs
│   ├── handlers.rs
│   └── models.rs
└── services/
    ├── mod.rs
    ├── auth_service.rs
    └── vault_service.rs
```

### Rules

- **Do not nest deeper than one subdirectory.** `src/http/handlers.rs` is fine. `src/http/v1/handlers/auth.rs` is not.
- **Never create a directory for a single file.** If `http/` would only contain `mod.rs`, use `http.rs` instead.
- **Inline unit tests** via `#[cfg(test)]` modules within the source file they test.

---

## Test Structure

### Unit tests

Inline in source files:

```rust
// src/auth.rs
pub fn verify_token(token: &str) -> bool { /* ... */ }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_valid_token() { /* ... */ }
}
```

### Integration tests

In `tests/` directory at the crate root:

```
crate-name/
├── src/
├── tests/
│   ├── session_lifecycle.rs
│   └── keystore_operations.rs
```

### Examples

In `examples/` directory at the crate root:

```
crate-name/
├── src/
├── examples/
│   ├── basic_app.rs
│   └── full_stack.rs
```

### Rules

- **Unit tests are always inline.** Never in separate files.
- **Integration tests use descriptive names.** `session_lifecycle.rs`, not `test1.rs`.
- **Examples are runnable.** Each must have a `main()` function and a clear run command in the crate README.
- **Feature-gate tests and examples** that require `std` or other optional features.
- **Test file names are `snake_case`.**

---

## Documentation

### Cross-project docs (`/docs`)

Files in the shared `docs/` directory **must** use a category prefix:

| Prefix | Category | Purpose |
|--------|----------|---------|
| `arch-` | Architecture | System design, security model, data structures, component relationships |
| `guide-` | Guide | How-to tutorials, operational runbooks, step-by-step instructions |
| `ref-` | Reference | Configuration options, API parameters, lookup tables, conventions |
| `plan-` | Planning | Roadmaps, implementation plans, design proposals (include status header) |
| `adr-` | ADR | Architecture Decision Records (in `docs/adr/` subdirectory) |

### File naming

| Rule | Good | Bad |
|------|------|-----|
| Kebab-case, all lowercase | `arch-security-model.md` | `ARCHITECTURE.md` |
| Category prefix in `/docs` | `guide-key-rotation.md` | `key-rotation.md` |
| No abbreviations (exceptions: `api`, `cli`, `adr`, `ux`) | `guide-auto-unseal.md` | `guide-auto-uns.md` |
| `README.md` keeps standard casing | `README.md` | `readme.md` |
| `CLAUDE.md` keeps standard casing | `CLAUDE.md` | `claude.md` |

### Project-specific docs (`subproject/docs/`)

Files in a subproject's `docs/` directory do **not** need category prefixes because the directory provides context:

```
subproject/docs/
├── api.md                 # HTTP API reference
├── cli.md                 # CLI command reference
├── configuration.md       # Config options
├── architecture.md        # Internal architecture
├── security.md            # Security considerations
└── getting-started.md     # Quick start guide
```

### Document structure

```markdown
# Document Title

One-line description or purpose statement.

## Section

Content with code blocks (always specify language):

    ```rust
    fn example() {}
    ```

    ```bash
    cargo build
    ```

    ```toml
    [section]
    key = "value"
    ```

## Related Documents

- [Link to related doc](relative-path.md)
```

### Planning documents

Must include a status header:

```markdown
# Feature Plan

> **STATUS: IN PROGRESS**
> Phase 1 complete. Phase 2 in development.
> Last updated: 2026-01-28
```

Status values: `PLANNING`, `IN PROGRESS`, `COMPLETE`, `SUPERSEDED`.

### Crate READMEs

Every crate has a `README.md` with:

1. One-line description
2. Overview section
3. Dependencies / prerequisites
4. Usage and examples (with run commands)
5. Status (if not yet stable)
6. License link

### ADR format

```markdown
# ADR-NNN: Title

## Status
Accepted | Proposed | Deprecated | Superseded by ADR-XXX

## Context
What is the issue we're addressing?

## Decision
What is the change we're making?

## Consequences
What are the positive and negative results?
```

### Rules

- **ATX-style headers only.** Use `#` prefix, not underlines.
- **One H1 per document.**
- **Relative links for internal docs.** `[Security Model](arch-security-model.md)`.
- **Always specify language on code blocks.**
- **Tables for structured data.**
- **New docs in `/docs` must be added to `/docs/README.md` index.**

---

## Configuration Files

### Layout

```
configs/
├── docker/
│   ├── dev/               # Docker dev configs
│   │   ├── nanokey.base.toml
│   │   └── nanokey.factors.toml
│   ├── int/
│   │   └── nanokey.base.toml
│   ├── test/
│   │   ├── nanokey.base.toml
│   │   ├── nanokey.factors.toml
│   │   ├── nanokey.policies.json
│   │   ├── nanopass.base.toml
│   │   └── nanopass.binding.toml
│   └── prod/
│       ├── nanokey.base.toml
│       ├── nanokey.hardened.toml
│       └── nanopass.base.toml
└── local/
    └── nanopass_app.toml   # Bare-metal local dev configs
```

### Config file naming

Pattern: `{service}.{variant}.{ext}`

| Component | Convention | Examples |
|-----------|-----------|----------|
| Service name | Lowercase, matches crate name | `nanokey`, `nanopass` |
| Variant | Lowercase, describes the overlay | `base`, `factors`, `hardened`, `binding`, `ssr` |
| Extension | Matches format | `.toml`, `.json`, `.yaml` |

### Rules

- **TOML is the default format** for application configuration.
- **JSON only when required** by the consuming system (e.g., policy files).
- **`base` is the foundational config** for each service in each tier. Every service must have a `{service}.base.toml`.
- **Variants are overlays.** They extend or override the base config for specific scenarios (factors, hardened, binding, ssr, auto-unseal).
- **Config paths are set via environment variable.** `AIRFRAME_CONFIG_PATH=/configs/docker/test/nanokey.base.toml`. Multiple files colon-separated: `path1.toml:path2.toml`.
- **Local configs go in `configs/local/`.** These are for bare-metal `cargo run` development without Docker.
- **Never commit secrets in config files.** Use environment variables for sensitive values (keys, passwords, tokens).
- **Docker configs are read-only mounted.** Volumes mount `configs/` as `:ro`.

---

## Docker

### Dockerfile placement

Dockerfiles live in the subproject they build:

```
nanokey/Dockerfile              # Builds the nanokey server
nanopass/Dockerfile             # Builds the nanopass server
nanopass/crates/nanopass_web/Dockerfile  # Builds the web frontend
```

### Dockerfile conventions

```dockerfile
# syntax=docker/dockerfile:1

# --- cargo-chef: plan stage ---
FROM rustlang/rust:<version>-bookworm AS chef
# ... dependency planning

# --- cargo-chef: deps stage ---
FROM rustlang/rust:<version>-bookworm AS deps
# ... dependency caching with cargo-chef

# --- Build stage ---
FROM rustlang/rust:<version>-bookworm AS builder
# ... full build

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN useradd -m -u 10001 appuser
# ... minimal runtime
USER appuser
ENTRYPOINT ["/usr/local/bin/{binary}"]
CMD ["--bind", "0.0.0.0:{port}"]
```

### Rules

- **Multi-stage builds always.** Plan, deps, build, runtime.
- **Use cargo-chef** for dependency caching.
- **Runtime image is `debian:bookworm-slim`.** Minimal base.
- **Non-root user** (`appuser`, UID 10001) for the runtime stage.
- **State directories** created and owned by appuser: `/var/lib/{service}`, `/home/appuser/{service}-data`.
- **BuildKit cache mounts** for cargo registry, git, and target.
- **ENTRYPOINT is the binary.** CMD provides default arguments.
- **Build context is always the repo root** (so cross-subproject dependencies resolve).

### Docker Compose layout

```
docker/compose/
├── dev/
│   ├── base.yml           # Foundational service definitions
│   ├── ephemeral.yml      # Overlay: tmpfs state, wiped on restart
│   └── factors.yml        # Overlay: factor authentication enabled
├── int/
│   ├── base.yml
│   └── ephemeral.yml
├── test/
│   ├── base.yml           # Full stack for automated tests
│   ├── ephemeral.yml
│   ├── factors.yml
│   ├── binding.yml
│   ├── ssr.yml
│   └── auto-unseal.yml
└── prod/
    ├── base.yml           # Production-ready definitions
    ├── hardened.yml        # Overlay: TLS, security hardening
    └── multi.yml           # Overlay: multi-node deployment
```

### Compose file naming

Pattern: `{variant}.yml`

- `base.yml` is **always present** in each tier. It defines the foundational services.
- Overlay files **extend or override** base definitions for specific scenarios.
- Compose project name: `airspace-{tier}` (e.g., `name: airspace-dev`).
- Overlay project name: `airspace-{tier}-{variant}` (e.g., `name: airspace-dev-factors`).

### Compose conventions

```yaml
name: airspace-{tier}
services:
  {service}:
    build:
      context: ../../..          # Always repo root
      dockerfile: {subproject}/Dockerfile
    image: airspace/{service}:{tier}
    container_name: {service}-{tier}
    environment:
      - RUST_LOG=${SERVICE_RUST_LOG:-info}
      - AIRFRAME_CONFIG_PATH=/configs/docker/{tier}/{service}.base.toml
    volumes:
      - ../../../configs:/configs:ro
    ports:
      - "{host_port}:{container_port}"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:{port}/health | grep -Eq '^(ok|healthy)$'"]
      interval: 5s
      timeout: 3s
      retries: 20
      start_period: 5s

networks: {}
volumes: {}
```

### Rules

- **Image tag matches tier.** `airspace/nanokey:dev`, `airspace/nanokey:test`, `airspace/nanokey:prod`.
- **Container name is `{service}-{tier}`.** `nanokey-dev`, `nanopass-test`.
- **Config path via env var.** `AIRFRAME_CONFIG_PATH` points to the config inside the mounted volume.
- **`depends_on` with `condition: service_healthy`** for service ordering.
- **`restart: unless-stopped`** for test and prod tiers, omitted for dev.
- **Health check on every service.** Use `/health` endpoint.
- **Volumes section** declared at bottom, even if empty.
- **Overlays only override what they change.** Do not repeat base definitions.

---

## IDE and Tooling

### IntelliJ / RustRover run configurations

Stored in `.run/` at the repo root. Naming:

| Type | Pattern | Examples |
|------|---------|----------|
| Server run | `{service} [profile].run.xml` | `nanokey [local].run.xml` |
| Test suite | `test-{subproject}.run.xml` | `test-airframe.run.xml`, `test-spacetime.run.xml` |

### Cargo aliases

Defined in `.cargo/config.toml` at the repo root:

```toml
[alias]
web-dev = "run -p nanopass_web --features leptos-ssr"
```

Use aliases for frequently used multi-flag commands. Keep them descriptive.

### Rules

- **Run configs live at repo root** in `.run/`, not per-subproject.
- **One run config per server profile** and one per test suite.
- **Working directory** in run configs points to the subproject directory.
- **Environment variables** set per run config, not globally.

---

## Git

### Submodules

Each subproject is a git submodule defined in `.gitmodules`:

```ini
[submodule "subproject"]
    path = subproject
    url = ssh://git@host/org/subproject.git
```

### Branching

- **`master`** — Stable release branch. PR target.
- **`develop`** — Active development branch.

### .gitignore

Minimal, at repo root:

```
target/*
*.lock
```

Note: `Cargo.lock` is committed despite the `*.lock` pattern (git tracks already-added files).

### Tagging

Tags use a per-subproject format: `{subproject}/v{version}`. See [Versioning](#versioning) for which versions get tagged.

```
spacetime/v0.2.0
airframe/v0.5.0
nanokey/v0.7.0-beta.1
```

### Rules

- **Subprojects are submodules.** Never copy code into the repo.
- **`.gitignore` is minimal.** Only build artifacts and lock files.
- **No IDE-specific ignores** in `.gitignore` (use global gitignore for personal IDE files; `.run/` is committed intentionally).
- **Commit `Cargo.lock` at the repo root** for reproducible builds.
- **Tag betas and releases.** Use `{subproject}/v{version}` format. Do not tag dev builds.

---

## Environment Files

### `.env` at repo root

Contains build-time and tooling environment variables:

```bash
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1
```

### Runtime environment variables

Set in Docker Compose files or IDE run configurations, never in `.env`:

| Variable | Purpose | Example |
|----------|---------|---------|
| `RUST_LOG` | Log level filter | `info,nanokey=debug` |
| `AIRFRAME_CONFIG_PATH` | Config file path(s), colon-separated | `/configs/docker/test/nanokey.base.toml` |
| `AIRFRAME_CONFIG__{SECTION}__{KEY}` | Config override via env | `AIRFRAME_CONFIG__STORAGE__KV__DRIVER=filesystem` |
| `{SERVICE}_SECRETS_KEY_HEX` | Secret key (dev/test only) | `0123456789abcdef...` |

### Rules

- **`.env` is for build tooling only** (Docker BuildKit, Compose CLI).
- **Never put secrets in `.env`.** Secrets go in compose env vars or secret mounts.
- **Config overrides use double-underscore nesting.** `AIRFRAME_CONFIG__{SECTION}__{KEY}`.
- **Service-specific env var prefixes** use the service name in uppercase: `NANOKEY_`, `NANOPASS_`.

---

## Feature Flags

### Standard feature flag set

For `no_std`-first crates:

```toml
[features]
default = []       # no_std by default
alloc = []         # Heap allocation for no_std with allocator
std = ["alloc"]    # Standard library (implies alloc)
```

### Application feature flags

For service/application crates:

```toml
[features]
default = []
kv-fs = ["airframe_kv/filesystem"]   # Filesystem KV backend
dev = []                              # Development helpers
```

### Rules

- **`default = []` always.** No features enabled by default.
- **`std` implies `alloc`.** `std = ["alloc"]` in the features table.
- **Feature names are `kebab-case`.** `kv-fs`, not `kv_fs` or `kvFs`.
- **Gate platform-specific code** behind `std` or `alloc`.
- **Gate optional integrations** behind descriptive feature names.
- **Document the feature matrix** in the project's dev guide.

---

## Licensing

```toml
license = "MIT"
```

Permissively licensed under MIT. Set in `[workspace.package]` and inherited via `license.workspace = true` in individual crates.

---

## Anti-Patterns

These patterns are explicitly prohibited:

| Anti-pattern | Correct approach |
|-------------|-----------------|
| Source files at subproject root | All code under `crates/` |
| Deeply nested module directories (`src/a/b/c/d.rs`) | Max one subdirectory level (`src/a/b.rs`) |
| Mixed naming conventions within a project | One convention per project, applied uniformly |
| Secrets in config files or `.env` | Environment variables in compose, secret mounts |
| Dockerfile in `docker/` directory | Dockerfile in the subproject it builds |
| Config files without tier separation | Always `configs/{context}/{tier}/` |
| Standalone test files outside `tests/` | Integration tests in `tests/`, unit tests inline |
| Documentation without category prefix in `/docs` | Always use `arch-`, `guide-`, `ref-`, `plan-`, `adr-` |
| `README.md` in `docs/` named with prefix | Index file stays `README.md` |
| Features enabled by default | `default = []` always |
| Abbreviations in file names | Spell out (exceptions: `api`, `cli`, `adr`, `ux`) |
| `CamelCase` or `UPPERCASE` file names | `kebab-case` for docs, `snake_case` for source (exceptions: `README.md`, `CLAUDE.md`) |
| Creating directories for single files | Use a flat file until 3+ related files justify a directory |
| Reusable crates left in a service project | Migrate to a framework extension project when multiple services need them |
| Extension project depending on a service | Extension projects depend downward only (framework, spacetime) |
| Manual host dependency setup | Use dev containers; document in `.devcontainer/` |
| Forking external crates into a subproject | Vendor in `third-party/`; upstream patches |
| Duplicating first-party crates from another super project | Reference via `external/` and the workspace package registry |
| Complex shell scripts for simple tasks | Use `justfile` recipes; reserve `scripts/` for truly standalone scripts |
