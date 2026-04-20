# Changelog

All notable changes to SIPG (Shodan IP Grabber) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.4] - 2026-04-20

### Added
- Added `--domain-suffix` filtering for domain/subdomain collection and table/csv hostname/domain columns.
- Added `ports` field behavior to load full host ports via `GET /shodan/host/{ip}` while keeping `port` as search-match ports.
- Added `sipg info --probe` to check `/shodan/host/search` access directly from the CLI.

### Changed
- Default mode now resolves automatically: API when a key is configured, free mode otherwise (`-M auto` default).
- Improved table readability with row separators and full hostname/domain display.
- Improved unsupported `--fields` errors to list all supported field names and point to `sipg fields`.

### Fixed
- Fixed API request headers so REST calls use JSON-appropriate headers (resolves false 403 behavior for some keys).
- Fixed multiple indentation/syntax issues found in CLI/core paths during release hardening.
- Updated README documentation for new mode behavior, port semantics, and domain suffix filtering.

## [2.0.0] - 2024-01-XX

### Added
- Complete rewrite with professional package structure
- Modern CLI interface using Click
- Rich terminal output with progress bars and tables
- Secure configuration management with user home directory storage
- Comprehensive error handling and user feedback
- Support for detailed search results with additional metadata
- Rate limiting and API request management
- Cross-platform compatibility (Windows, macOS, Linux)
- Professional documentation and examples
- Unit tests and development tools
- Pre-commit hooks for code quality
- Makefile for common development tasks
- PyPI packaging support

### Changed
- Replaced simple script with modular package architecture
- Improved API key management (no longer stored in project directory)
- Enhanced search functionality with better filtering
- More intuitive command-line interface
- Better error messages and user guidance

### Removed
- Old single-file script approach
- Local config.json file (now uses ~/.sipg/config.json)
- Basic command-line argument parsing

## [1.0.0] - 2023-XX-XX

### Added
- Initial release
- Basic Shodan API integration
- Simple command-line interface
- IP address extraction and display
- Basic file output functionality

## [2.1.1] - 2024-12-19

### Changed
- Updated package with latest improvements and bug fixes
- Enhanced user experience and documentation

## [2.1.0] - 2024-12-19

### Added
- Added page range support with `--start-page` and `--end-page` options
- Enhanced CLI help with detailed descriptions for all options
- Added comprehensive examples showing how to use page ranges
- Improved documentation explaining how output is saved and how to limit results

### Changed
- Enhanced search command with better help text and usage examples
- Updated README with new options and detailed usage instructions
- Improved user experience with clearer option descriptions

## [2.0.2] - 2024-12-19

### Fixed
- Fixed CLI argument parsing to properly handle quoted search queries
- Updated examples to show correct shell quoting for complex queries
- Fixed issue where queries with spaces and special characters were not parsed correctly

## [2.0.1] - 2024-07-10

### Improved
- CLI now handles queries with spaces and special characters correctly (no more argument errors)
- Examples and help output are now copy-paste friendly and clear
- Added usage examples to main help output
- Removed deprecated license classifier for modern PyPI compatibility

### Fixed
- No more errors when using queries with spaces or quotes
- No more confusion in help or examples
