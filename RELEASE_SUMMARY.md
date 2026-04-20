# SIPG (Shodan IP Grabber) v2.1.4 Release Summary

## Release Goal
Deliver a major usability and capability upgrade so SIPG (Shodan IP Grabber) works strongly in both API-key and no-key workflows, with better collection options, output control, and reliability.

## Highlights
- Default mode now auto-selects API when a key exists (`-M auto`), with explicit `-M free` override.
- Added `--domain-suffix` so domain/subdomain results can be strictly filtered by suffix boundary (e.g., `.mil` but not `.mil.ng`).
- Added `ports` field behavior for full per-host ports and kept `port` as search-match ports.
- Added `sipg info --probe` to verify Search API access directly.

## Key Features Added
- `search --collect` now supports:
  - `ips` (default)
  - `domains`
  - `subdomains`
  - `all`
  - comma-separated values (example: `domains,subdomains`)
- New `--fields` support:
  - `search`: customize table columns and CSV schema.
  - `collect`: customize CSV schema (`type,value`).
- New `sipg fields` command:
  - Human-readable field list.
  - `--json` machine-readable output for scripts/automation.
- Added short command aliases:
  - `s`, `cfg`, `i`, `ex`, `cl`, `fs`
- Added short flag forms for common options (for faster CLI usage).

## Reliability and Behavior Improvements
- Improved no-key facet parsing for current Shodan HTML structures.
- Added stronger retry/backoff behavior for transient network/API issues.
- Better handling and messaging for `401`, `403`, `429`, and `503` responses.
- Free deep IP collection now streams results progressively.
- Removed noisy free-mode progress text; output is cleaner and more automation-friendly.
- Restored concise total result summaries (while keeping `--silent` truly minimal).

## UX and Documentation
- Simplified mode choices to `api` and `free` (`free` now covers deep behavior).
- Improved `search --details` and `search --table` output usefulness.
- README fully updated with new commands, aliases, options, and examples.
- `.gitignore` updated to exclude local/dev/output artifacts more safely.

## Version and Packaging
- Version remains `2.1.4` in project metadata and CLI output.
- Build validation completed:
  - `twine check dist/*` passed for wheel and sdist.
  - Fresh virtual environment install from wheel succeeded.
  - CLI smoke checks (`--version`, `--help`, alias help, `fields --json`) succeeded.

## Testing
- Test coverage updated for new implementations and behavior paths, including CLI/config changes tied to this release.

## Release Status
- Ready for commit and push to `main`.
- Tag remains `v2.1.4` for the current published release.
- Ready for GitHub Release publishing and PyPI/TestPyPI publishing workflows.
