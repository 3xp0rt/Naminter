# CLI Reference

Naminter provides a feature-rich command-line interface for username enumeration across hundreds of websites.

## Quick Start

```bash
# Search for a single username
naminter -u john_doe

# Search for multiple usernames
naminter -u user1 -u user2 -u user3

# Show version info
naminter --version

# Show help
naminter --help
```

---

## Commands

### `naminter` (main)

The default command runs username enumeration.

```bash
naminter [OPTIONS]
```

### `naminter validate`

Validate a local WhatsMyName JSON data file against its schema.

```bash
naminter validate --local-schema wmn-data-schema.json --local-data wmn-data.json
```

Both `--local-schema` and `--local-data` are **required**.

### `naminter format`

Format a WhatsMyName JSON data file according to schema ordering and sorting rules. Use `--output-data` and `--output-schema` to write to separate paths; if omitted, the data and schema files are overwritten in place.

```bash
# Format in-place (overwrites both files)
naminter format --local-schema wmn-data-schema.json --local-data wmn-data.json

# Format both to separate output files
naminter format --local-schema wmn-data-schema.json --local-data wmn-data.json \
    --output-data formatted-data.json --output-schema formatted-schema.json
```

---

## Options Reference

### Input

| Option | Short | Description |
|---|---|---|
| `--username` | `-u` | Username(s) to search. Repeatable. Required unless `--test`. |
| `--site` | `-s` | Limit search to specific site(s). Repeatable. |

```bash
# Single username, specific sites
naminter -u john_doe -s GitHub -s "X"

# Multiple usernames across all sites
naminter -u alice -u bob
```

### Data Sources

By default, Naminter fetches the WhatsMyName dataset and schema from GitHub. Override with local or custom remote files.

| Option | Description |
|---|---|
| `--local-data` | Path to a local WMN JSON data file. |
| `--local-schema` | Path to a local WMN JSON schema file. |
| `--remote-data` | URL to fetch remote WMN data. |
| `--remote-schema` | URL to fetch remote WMN schema. |

```bash
# Use local data file
naminter -u john_doe --local-data ./wmn-data.json

# Use both local data and schema
naminter -u john_doe --local-data ./wmn-data.json --local-schema ./wmn-data-schema.json

# Use a custom remote source
naminter -u john_doe --remote-data https://example.com/wmn-data.json
```

!!! warning
    You cannot combine `--local-data` with `--remote-data`, or `--local-schema` with a custom `--remote-schema`.

### Category Filtering

Filter which site categories are included or excluded from enumeration.

| Option | Description |
|---|---|
| `--include-categories` | Only include sites from these categories. Repeatable. |
| `--exclude-categories` | Exclude sites from these categories. Repeatable. |

```bash
# Only check social media and coding platforms
naminter -u john_doe --include-categories social --include-categories coding

# Skip adult and gaming sites
naminter -u john_doe --exclude-categories adult --exclude-categories gaming
```

### Result Filtering

Control which result statuses appear in the output. If no filter is set, `--filter-exists` is applied by default.

| Option | Description |
|---|---|
| `--filter-all` | Show all results regardless of status. |
| `--filter-exists` | Show results where the username exists. **(default)** |
| `--filter-partial` | Show partial match results. |
| `--filter-conflicting` | Show conflicting results. |
| `--filter-unknown` | Show unknown status results. |
| `--filter-missing` | Show results where the username is missing. |
| `--filter-not-valid` | Show results for sites marked as not valid. |
| `--filter-errors` | Show results that encountered errors. |

```bash
# Show everything
naminter -u john_doe --filter-all

# Show only found + errors for debugging
naminter -u john_doe --filter-exists --filter-errors

# Show only missing accounts
naminter -u john_doe --filter-missing
```

**Status symbols** (used in console and progress output):

| Symbol | Status | Meaning |
|--------|--------|--------|
| `+` | exists | Username found on the site. |
| `-` | missing | Username not found on the site. |
| `~+` / `~-` | partial exists / partial missing | Only some detection criteria matched (progress shows ~+ / ~-). |
| `*` | conflicting | Both exists and missing indicators matched. |
| `?` | unknown | Result could not be classified. |
| `X` | not valid | Site marked invalid in data. |
| `!` | error | Request or processing failed. |

### Network Configuration

| Option | Default | Description |
|---|---|---|
| `--proxy` | — | Proxy URL (e.g. `http://host:port`, `socks5://host:port`). |
| `--timeout` | `30` | HTTP request timeout in seconds (1–300). |
| `--allow-redirects` / `--no-allow-redirects` | off | Follow HTTP redirects. |
| `--verify-ssl` / `--no-verify-ssl` | off | Verify SSL certificates. |
| `--impersonate` | `chrome` | Browser to impersonate. Use `none` to disable. |
| `--max-tasks` | `50` | Maximum concurrent requests (1–1000). |

```bash
# Use a SOCKS5 proxy with longer timeout
naminter -u john_doe --proxy socks5://127.0.0.1:9050 --timeout 60

# Disable browser impersonation
naminter -u john_doe --impersonate none

# Increase concurrency
naminter -u john_doe --max-tasks 200

# Enable SSL verification and redirects
naminter -u john_doe --verify-ssl --allow-redirects
```

### TLS Fingerprinting

Advanced options for evading bot detection.

| Option | Description |
|---|---|
| `--ja3` | Custom JA3 fingerprint string. |
| `--akamai` | Custom Akamai fingerprint string. |
| `--extra-fp` | Extra fingerprint options as a JSON string. |

```bash
# Custom JA3 fingerprint
naminter -u john_doe --ja3 "771,4865-4866-4867..."

# Extra fingerprint options
naminter -u john_doe --extra-fp '{"tls_grease": true, "tls_cert_compression": "brotli"}'
```

### Validation Mode

| Option | Description |
|---|---|
| `--mode` | Detection mode: `all` (default) or `any`. |

- **`all`**: EXISTS when both the expected HTTP status and the expected body string match; MISSING when both the missing status and missing string match. If only one matches, you get PARTIAL_EXISTS or PARTIAL_MISSING (strict AND).
- **`any`**: EXISTS when either the expected status or the expected body string matches; MISSING when either the missing status or missing string matches.

```bash
naminter -u john_doe --mode any
```

### Site Testing

| Option | Description |
|---|---|
| `--test` | Run site validation using known usernames from the data. No `--username` required. |
| `--skip-validation` | Skip JSON schema validation of the WMN data on load. |

```bash
# Test all sites against their known usernames
naminter --test

# Test specific sites
naminter --test -s GitHub -s "X"

# Test with verbose output for debugging
naminter --test -vvv

# Skip schema validation for faster startup
naminter -u john_doe --skip-validation
```

### Export

Export results to one or more formats. Each format has an optional path flag; if omitted, a timestamped filename is generated in the current directory.

| Flag | Path Option | Format |
|---|---|---|
| `--csv` | `--csv-path` | CSV |
| `--json` | `--json-path` | JSON |
| `--html` | `--html-path` | HTML report |
| `--pdf` | `--pdf-path` | PDF report |

```bash
# Export to CSV with auto-generated filename
naminter -u john_doe --csv

# Export to multiple formats with custom paths
naminter -u john_doe \
    --csv --csv-path results.csv \
    --json --json-path results.json \
    --html --html-path report.html \
    --pdf --pdf-path report.pdf

# Export all results (not just "exists")
naminter -u john_doe --filter-all --csv --json
```

### Response Saving

Save raw HTTP responses to disk for offline analysis.

| Option | Description |
|---|---|
| `--save-response` | Enable saving HTTP response bodies. |
| `--response-dir` | Directory to save responses in. Defaults to current directory. |
| `--open-response` | Open saved response files in the browser. |
| `--browse` | Open found profile URLs in the browser. |

```bash
# Save all responses to a folder
naminter -u john_doe --save-response --response-dir ./responses --filter-all

# Save responses and auto-open in browser
naminter -u john_doe --save-response --open-response

# Open found profiles directly in browser
naminter -u john_doe --browse
```

### Display & Logging

| Option | Short | Description |
|---|---|---|
| `--verbose` | `-v` | Increase verbosity. `-v` errors, `-vv` details, `-vvv` headers. |
| `--no-color` | — | Disable colored output. |
| `--no-progressbar` | — | Disable the progress bar. |
| `--log-level` | — | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `--log-file` | — | Path to write log output. |

```bash
# Maximum verbosity with logging
naminter -u john_doe -vvv --log-level DEBUG --log-file naminter.log

# Clean output for piping
naminter -u john_doe --no-color --no-progressbar

# Show error details only
naminter -u john_doe -v --filter-errors
```

---

## Practical Examples

### OSINT Investigation

Enumerate a target username across all platforms, export a full report, and save responses for evidence:

```bash
naminter -u target_user \
    --filter-all \
    --save-response --response-dir ./evidence \
    --csv --csv-path report.csv \
    --html --html-path report.html \
    -vv
```

### Proxy Routing

Route all traffic through a proxy:

```bash
naminter -u john_doe \
    --proxy socks5://127.0.0.1:9050 \
    --timeout 60 \
    --max-tasks 20
```

### Targeted Category Scan

Only check social media platforms, exclude adult content:

```bash
naminter -u john_doe \
    --include-categories social \
    --exclude-categories adult
```

### CI / Automation

Non-interactive output suitable for scripts and pipelines:

```bash
naminter -u john_doe \
    --no-color \
    --no-progressbar \
    --json --json-path results.json \
    --filter-exists
```

### Dataset Maintenance

Validate and format a local copy of the WhatsMyName data:

```bash
# Validate the dataset
naminter validate \
    --local-schema wmn-data-schema.json \
    --local-data wmn-data.json

# Auto-format the dataset
naminter format \
    --local-schema wmn-data-schema.json \
    --local-data wmn-data.json
```

### Debugging a Specific Site

Test a single site with maximum verbosity and response saving:

```bash
naminter -u known_username \
    -s GitHub \
    -vvv \
    --save-response --response-dir ./debug \
    --log-level DEBUG --log-file debug.log \
    --filter-all
```
