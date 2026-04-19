# AI Coding Instructions

This document defines coding standards and maintenance practices for the sys-rs project.
Update this file when project practices change or guidelines become outdated.

## Code Style

### Comments
- Do not add comments to explain what code does — the code should be clear enough to read on its own
- Only add a comment when there is a specific reason to believe the logic will not be self-evident to a reader (e.g. a non-obvious algorithm, an intentional workaround, or an external constraint)
- Never add boilerplate or redundant comments such as `// initialize`, `// return result`, or anything that merely restates the code

### Functional over Imperative
- Prefer functional style over imperative
- Avoid using `return` statements — use expression-based returns instead
- Use `match`, `if let`, `map`, `and_then`, `unwrap_or_else` over early returns
- Prefer iterator methods (`map`, `filter`, `fold`) over `for` loops with mutation

### Error Handling
- Use `diag::Result` for error handling throughout the crate
- Use `?` operator — avoid `.unwrap()` except in tests
- Prefer `ok_or_else` / `map_err` over `match` for Option/Result conversions
- Do not introduce external error-handling crates (e.g. `anyhow`, `thiserror`)

### Formatting & Linting
- Run `cargo fmt` after every code change
- Run `cargo clippy` and fix all warnings — clippy lints `all`, `cargo`, and `pedantic` are set to `deny`
- Follow standard Rust formatting conventions

## Maintenance & Synchronization

### Version Management
- This project requires nightly Rust (uses `#![feature(trait_alias)]`)
- When bumping the nightly toolchain, verify CI still passes
- When updating dependencies in `Cargo.toml`, run `cargo build` and `cargo test` to confirm no regressions

### README.md Synchronization
- When adding/removing binaries in `Cargo.toml`, update the corresponding section in README.md
- Binary descriptions in README.md must reflect the actual tool behaviour
- Build instructions in README.md must remain accurate

### Library Documentation
- Module doc comments in `src/lib.rs` must be single-line descriptions
- Public functions/methods must document: `# Arguments`, `# Returns`, and `# Errors` sections
- Public structs/enums must have doc comments describing their purpose
- Public fields must have inline doc comments explaining their role
- Follow the existing documentation style

### Dependency Management
- Review dependencies periodically for updates
- Upgrading `nix`, `libunwind-rs`, or `goblin` may require coordinated changes across multiple modules
- Do not add dependencies that duplicate capabilities already provided by existing ones

### CI/CD Workflow
- The CI workflow (`.github/workflows/ci.yml`) runs: format check, build, clippy, and tests
- CI runs on Debian 12 with nightly Rust
- All clippy warnings are denied — fix them before committing
- Tests use `serial_test` for serialization since ptrace operations are exclusive; do not run ptrace tests in parallel

### Architecture Constraints
- This project targets **x86_64 Linux only** — do not introduce architecture-specific code for other targets
- DWARF support is limited to versions 2, 3, and 4 — DWARF 5 is not yet supported
- ptrace operations require Linux — do not add platform-conditional code for other OSes
- Test artifacts (static and PIE binaries) live in `.keep/` — do not modify them

### Adding New Tools
- Each new tool gets a binary in `src/bin/`, a test file in `tests/`, and a section in README.md
- Reuse existing library modules (`trace`, `process`, `progress`, etc.) rather than duplicating logic
- Add a `[[bin]]` entry in `Cargo.toml` and a corresponding CI matrix entry if needed
