# Repository Guidelines

## Project Structure & Module Organization
- Main source: `vless_cascade.py` (single entrypoint script with menu actions, validation, routing profiles, backups, and logging).
- Documentation: `README.md` (usage and operational flow), `hosting.txt` (provider notes/reference data).
- Generated artifacts: `__pycache__/` (do not edit or commit manually).
- Runtime-managed files on target servers are referenced in code (for example `/etc/vless-cascade/routes.json`, `/var/log/vless-cascade.log`) but are not part of this repository.

## Build, Test, and Development Commands
- Run locally (standard mode): `sudo python3 vless_cascade.py`
- Run locally (safe mode, no auto-install): `sudo python3 vless_cascade.py --safe`
- Syntax check before commit: `python3 -m py_compile vless_cascade.py`
- Optional quick check for style drift: `python3 -m pip install ruff && ruff check vless_cascade.py`

Use Ubuntu when validating behavior, since the script interacts with system paths, `apt`, and `xray/3x-ui` binaries.

## Coding Style & Naming Conventions
- Follow Python 3 conventions with 4-space indentation.
- Store all text files in `UTF-8` **without BOM** (including `.py`, `.md`, `.json`); do not use `cp1251` or mixed encodings.
- Use `snake_case` for functions/variables, `UPPER_SNAKE_CASE` for constants, and concise verb-based function names (`load_settings`, `apply_ru_config` style).
- Keep menu actions isolated in small functions; avoid large inline blocks in the menu loop.
- Prefer standard library modules already used in this project; add dependencies only when necessary.

## Testing Guidelines
- There is currently no automated test suite in-repo.
- Minimum validation for every change:
  - `python3 -m py_compile vless_cascade.py`
  - Manual smoke run of relevant menu paths in a disposable Ubuntu VM.
- If you add tests, use `pytest` with files named `test_*.py` under `tests/`.

## Commit & Pull Request Guidelines
- Commit messages in this repo follow short imperative summaries (examples: `Add menu log viewer...`, `Fix UTC deprecation...`).
- Keep commits focused on one change set.
- PRs should include:
  - what changed and why,
  - risk/rollback notes (important for server-side config edits),
  - manual validation steps performed,
  - screenshots or terminal snippets for menu/log UX changes.
