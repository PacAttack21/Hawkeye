# Changelog

All notable changes to Hawkeye will be documented in this file.

## [2.0.0] - 2025-01-15

### Added
- **Multi-phase scanning**: Quick wins → Deep scanning phases
- **Smart subdomain enumeration**: FFUF-based with wildcard filtering
- **Automatic /etc/hosts updates**: Resolves discovered subdomains
- **Real-time progress tracking**: Live URL updates and progress indicators
- **Periodic report generation**: HTML, JSON, and Markdown reports
- **Competition-ready features**: Optimized for CPTC and similar competitions
- **Resume capability**: Save and resume scans
- **Multiple screenshot engines**: Playwright, wkhtmltopdf, curl fallback
- **Priority scoring**: Automatically categorizes findings by importance
- **Comprehensive wordlists**: 19,966 subdomains, 1.2M+ directories
- **Interactive prompts**: User guidance for large directories
- **Live URL updates**: Real-time terminal output
- **Subdomain reachability testing**: Verify subdomains before fuzzing

### Changed
- **Simplified CLI**: Reduced from 20+ options to essential flags
- **Improved performance**: Optimized concurrency and timeouts
- **Better error handling**: Graceful handling of missing tools
- **Enhanced logging**: Structured JSON logs with timeline
- **Streamlined output**: Clean, informative progress display

### Fixed
- **Progress tracking**: Accurate job counting and percentages
- **File path issues**: Proper handling of special characters
- **Screenshot functionality**: Multiple fallback engines
- **Subdomain enumeration**: Fixed false positives and timeouts
- **Memory usage**: Optimized for long-running scans

### Removed
- **Complex CLI options**: Simplified to essential features
- **External tool dependencies**: FFUF-only subdomain enumeration
- **Redundant features**: Streamlined for competition use

## [1.0.0] - 2024-12-01

### Added
- Initial release
- Basic web scanning functionality
- FFUF integration
- Screenshot capture
- Report generation

---

## Version History

- **v2.0.0**: Complete rewrite for competition use
- **v1.0.0**: Initial release with basic functionality

## Migration Guide

### From v1.0 to v2.0

The CLI has been significantly simplified:

**Old (v1.0):**
```bash
python3 hawkeye.py --targets http://example.com --ports 80,443 --wordlist /path/to/wordlist --threads 50 --timeout 10
```

**New (v2.0):**
```bash
python3 hawkeye.py http://example.com --threads 50 --timeout 10
```

### Key Changes
1. **Target as positional argument**: No more `--targets` flag
2. **Simplified options**: Many advanced options removed
3. **Smart defaults**: Automatic configuration based on scan mode
4. **New flags**: `--fast`, `--deep`, `--background`, `--resume`

### Breaking Changes
- CLI interface completely changed
- Configuration file format changed
- Output directory structure updated
- Log format changed to JSONL

## Future Roadmap

### v2.1.0 (Planned)
- [ ] Docker support
- [ ] Web dashboard
- [ ] API endpoints
- [ ] Plugin system
- [ ] Custom report templates

### v2.2.0 (Planned)
- [ ] Machine learning-based prioritization
- [ ] Integration with other tools
- [ ] Cloud deployment options
- [ ] Advanced filtering options

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to Hawkeye.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/hawkeye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hawkeye/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/hawkeye/wiki)
