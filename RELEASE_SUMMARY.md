# SIPG v2.1.2 Release Summary

## Release Goal
Deliver a major usability and capability upgrade so SIPG works strongly in both API-key and no-key workflows, with better collection options, output control, and reliability.

## Highlights
- Added dual-mode operation: `api` mode and `free` mode.
- Upgraded free mode to deep, ipfinder-style collection behavior for larger no-key IP collection.
- Added dedicated `collect` command with `txt`, `json`, and `csv` export formats.
- Added field customization support with `--fields` and a new `fields` helper command.
- Simplified command usage with short aliases and short flags.

## Key Features Added
- New `sipg collect` command for collecting:
  - `ips`
  - `domains`
  - `subdomains`
  - `all`
- New `--fields` support:
  - `search`: customize table columns and CSV schema.
  - `collect`: customize CSV schema (`type,value`).
- New `sipg fields` command:
  - Human-readable field list.
  - `--json` machine-readable output for scripts/automation.
- Added short command aliases:
  - `s`, `c`, `cfg`, `i`, `ex`, `cl`, `fs`
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
- Version bumped to `2.1.2` in project metadata and CLI output.
- Build validation completed:
  - `twine check dist/*` passed for wheel and sdist.
  - Fresh virtual environment install from wheel succeeded.
  - CLI smoke checks (`--version`, `--help`, alias help, `fields --json`) succeeded.

## Testing
- Test coverage updated for new implementations and behavior paths, including CLI/config changes tied to this release.

## Release Status
- Changes committed and pushed to `main`.
- Tag `v2.1.2` created and pushed.
- Ready for GitHub Release publishing and PyPI/TestPyPI publishing workflows.
