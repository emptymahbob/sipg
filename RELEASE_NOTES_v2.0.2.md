# SIPG v2.0.2 Release Notes

## 🐛 Bug Fixes

### Fixed CLI Argument Parsing
- **Issue**: Queries with spaces and special characters like `ssl:"Uber Technologies Inc"` were being parsed as multiple arguments, causing "Got unexpected extra arguments" errors
- **Solution**: Changed CLI argument handling from `nargs=-1` to `type=str` to properly handle quoted search queries
- **Impact**: Users can now use complex Shodan queries with spaces and special characters without issues

### Updated Examples and Documentation
- Fixed all example commands to show correct shell quoting
- Updated help text to reflect proper usage
- Examples now show copy-paste friendly syntax

## ✅ What's Working Now

All these queries now work correctly:
```bash
sipg search 'ssl:"Uber Technologies Inc"'
sipg search 'ssl.cert.subject.CN:"*.uber.com"'
sipg search 'country:"United States"'
sipg search 'product:"nginx"'
sipg search 'org:"Amazon"'
```

## 📦 Installation

```bash
pip install sipg==2.0.2
```

## 🔗 Links

- **PyPI**: https://pypi.org/project/sipg/
- **GitHub**: https://github.com/emptymahbob/sipg
- **Documentation**: See README.md for usage examples

## 🎯 Breaking Changes

None - this is a bug fix release that maintains full backward compatibility.

## 🚀 Migration

No migration required - existing commands will continue to work, and new complex queries will now work properly. 