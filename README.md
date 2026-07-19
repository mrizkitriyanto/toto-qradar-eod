# QRadar OCSF Offense Reporting

A single-file Python CLI that fetches QRadar offenses (OCSF format, `GET /siem/offenses_ocsf`) by offense ID range, and can turn them into a ready-to-read Excel report — with severity filtering and a SQLite-backed knowledge base for Deskripsi/Rekomendasi columns.

Everything lives in one script: **[qradar_ocsf_offenses_by_id_range.py](qradar_ocsf_offenses_by_id_range.py)**. No server, no framework — just Python's standard library, plus one optional package (`openpyxl`) for Excel/KB-import features.

## Why it works the way it does

`/siem/offenses_ocsf` only supports positional pagination (`Range: items=0-99`) — there's no `filter`/`sort` query parameter to ask for "offense ID 5001-5005" directly. The script handles this with a two-strategy approach:

1. **Smart fetch** (default): probes the first offense to learn the ID-to-position relationship, estimates the position window that should contain your requested ID range, fetches it with a safety buffer, and **verifies** the edges to confirm nothing was missed. If verification fails (ID gaps, non-ID-ordered list), the buffer expands and retries.
2. **Full scan** (`--full-scan`, or automatic fallback if verification keeps failing): scans the entire offense list and filters client-side. Slower, but always correct.

This means a fast path when the ID/position assumption holds, and a correctness guarantee when it doesn't — the assumption is never silently trusted.

## Features

- Fetch offenses by offense ID range (`finding_info.uid`), with automatic correctness verification and fallback.
- Output as raw JSON (default, stdout) or as a formatted **Excel report** (`--output-xlsx`) — bold header, frozen pane, auto-filter table, auto-fit columns.
- **Severity filter** (`--severity High,Critical`) applied to the final result set.
- **Knowledge base (SQLite)** lookup for the Deskripsi/Rekomendasi columns, matched by keyword-in-title (longest match wins), fully manageable from the CLI — no server, no extra service.
- **Confirmation guard** before fetching more than 500 offense IDs, safe for both interactive and non-interactive (cron/CI) use.
- Retries with backoff on HTTP 5xx / connection errors; clear errors on 401/403.

## Requirements

- Python 3.9+ (uses `tuple[list, dict]`-style built-in generic type hints and the `:=` operator).
- `sqlite3` — standard library, no install needed (used for the knowledge base).
- `openpyxl` — **only** required for `--output-xlsx` and `--kb-import`. Everything else (JSON output, `--kb-list`/`--kb-add`/`--kb-update`/`--kb-delete`) needs no third-party package.

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Raw JSON to stdout (default)
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5005 -u username

# Excel report, auto-named file in the current directory
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5005 -u username --output-xlsx

# Self-signed / lab QRadar console
python3 qradar_ocsf_offenses_by_id_range.py --host 192.168.100.55 --start-id 5001 --end-id 5005 -u username --insecure
```

You'll be prompted for your password securely (`getpass`) unless you pass `--password` (not recommended — it can leak via shell history).

## Excel Report

Pass `--output-xlsx` to get a formatted `.xlsx` instead of JSON:

```bash
# Default filename (Daily_QRadar_ddmmyyyy-hh-mm-ss.xlsx) in the current directory
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5005 -u username --output-xlsx

# Explicit path
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5005 -u username --output-xlsx C:\Reports\offense_5001-5005.xlsx

# Only High/Critical offenses
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5999 -u username --severity High,Critical --output-xlsx
```

Report columns: **Offense ID, Offense Name, Severity, Log Source, Src IP, Dst IP, Offense Source, Username, Deskripsi, Rekomendasi, Action, Timestamp**.

The full OCSF-field-to-column mapping, normalization rules, and design rationale are documented in **[QRadar Offense Report - Excel Output Spec.md](QRadar%20Offense%20Report%20-%20Excel%20Output%20Spec.md)** — read that if you're modifying `transform_to_rows()` or adding a column.

## Knowledge Base (SQLite)

Deskripsi and Rekomendasi are filled from a local SQLite knowledge base, matched against each offense's title (longest keyword match wins). No server required — it's a single `.sqlite3` file next to the script (`kb.sqlite3` by default, override with `--kb-db`).

```bash
# Import/refresh the KB from an Excel file (columns: ID, Offense Name, Deskripsi, Rekomendasi)
# Idempotent -- safe to re-run any time the source file changes.
python3 qradar_ocsf_offenses_by_id_range.py --kb-import Offense_QRadar_Deskripsi_Rekomendasi.xlsx

# List all KB entries
python3 qradar_ocsf_offenses_by_id_range.py --kb-list

# Add a single entry manually
python3 qradar_ocsf_offenses_by_id_range.py --kb-add --kb-keyword "Some Offense Pattern" --kb-deskripsi "..." --kb-rekomendasi "..."

# Update / delete by id (id shown in --kb-list)
python3 qradar_ocsf_offenses_by_id_range.py --kb-update 42 --kb-deskripsi "revised text"
python3 qradar_ocsf_offenses_by_id_range.py --kb-delete 42

# Generate a report without touching the KB (falls back to finding_info.desc / "N/A")
python3 qradar_ocsf_offenses_by_id_range.py --host qradar.example.com --start-id 5001 --end-id 5005 -u username --output-xlsx --no-kb
```

KB management flags don't require `--host`/`--start-id`/`--end-id`/`--username` — they run standalone and exit. See the spec doc's **Knowledge Base (SQLite)** section for the matching algorithm and known limitations (e.g. avoid overly generic keywords).

## Large Request Confirmation

Requesting more than **500** offense IDs triggers a warning and confirmation:

- Interactive terminal: prompts `Continue fetching N offense IDs? [y/N]` — anything but `y`/`yes` aborts.
- Non-interactive (cron/CI/piped) without `--yes`: exits immediately with an error instead of hanging.
- Pass `--yes`/`-y` to skip the prompt (the warning still prints).

## CLI Reference

Run `--help` for the full, current list — it's always the source of truth:

```bash
python3 qradar_ocsf_offenses_by_id_range.py --help
```

| Flag | Purpose |
|---|---|
| `--host`, `--start-id`, `--end-id`, `--username`/`-u` | Required for a report run (not required for `--kb-*` management flags). |
| `--password`/`-p` | Omit to be prompted securely. |
| `--yes`/`-y` | Skip the >500-offense confirmation prompt. |
| `--severity LEVEL[,LEVEL...]` | Filter the result set, case-insensitive, comma-separated. |
| `--output-xlsx [PATH]` | Write an Excel report instead of printing JSON. |
| `--full-scan` | Force the guaranteed-correct linear scan strategy. |
| `--insecure` | Skip TLS verification (lab/self-signed only). |
| `--kb-db`, `--no-kb` | KB database path / disable KB lookup for this run. |
| `--kb-import`, `--kb-list`, `--kb-add`, `--kb-update`, `--kb-delete` | KB management (standalone, exits after running). |
| `--api-version`, `--page-size`, `--buffer`, `--max-expand`, `--timeout`, `--retries` | Tuning knobs for the fetch strategy and HTTP behavior — sane defaults, rarely need changing. |


## Notes

- Passwords are never written to disk or logged; use the secure prompt rather than `--password` where possible.
- `--insecure` disables TLS certificate verification — only use it against lab/self-signed QRadar consoles you trust.
