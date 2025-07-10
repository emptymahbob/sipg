# Changelog

All notable changes to SIPG will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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