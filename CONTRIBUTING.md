# Contributing to Hawkeye

Thank you for your interest in contributing to Hawkeye! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Git
- FFUF installed
- Basic understanding of web security testing

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

## 🎯 How to Contribute

### Types of Contributions
- **Bug fixes**: Fix issues and improve stability
- **New features**: Add functionality while maintaining simplicity
- **Documentation**: Improve README, docs, and code comments
- **Performance**: Optimize speed and memory usage
- **Testing**: Add tests and improve coverage

### Contribution Process

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test your changes**
   ```bash
   python3 hawkeye.py http://httpbin.org --fast
   ```
5. **Commit your changes**
   ```bash
   git commit -m "Add: your feature description"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request**

## 📝 Code Style

### Python Style
- Follow PEP 8
- Use type hints where possible
- Keep functions small and focused
- Add docstrings for public functions

### Code Formatting
```bash
# Format code
black hawkeye.py

# Check style
flake8 hawkeye.py

# Type checking
mypy hawkeye.py
```

### Example Code Style
```python
async def example_function(url: str, timeout: int = 10) -> List[str]:
    """
    Example function with proper style.
    
    Args:
        url: Target URL to process
        timeout: Request timeout in seconds
        
    Returns:
        List of discovered URLs
    """
    results = []
    # Implementation here
    return results
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=hawkeye

# Run specific test
pytest tests/test_subdomain_enum.py
```

### Writing Tests
- Test files should be in `tests/` directory
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies

### Example Test
```python
import pytest
from hawkeye import Hawkeye

def test_subdomain_enumeration():
    """Test subdomain enumeration functionality."""
    hk = Hawkeye(mock_args)
    result = hk.enumerate_subdomains("example.com")
    assert isinstance(result, list)
    assert len(result) >= 0
```

## 🐛 Bug Reports

### Before Reporting
1. Check existing issues
2. Test with latest version
3. Try to reproduce the issue

### Bug Report Template
```markdown
**Bug Description**
Brief description of the bug

**Steps to Reproduce**
1. Run command: `python3 hawkeye.py ...`
2. See error: ...

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: Ubuntu 20.04
- Python: 3.9.7
- Hawkeye: 2.0.0

**Additional Context**
Any other relevant information
```

## ✨ Feature Requests

### Before Requesting
1. Check existing issues and roadmap
2. Consider if it fits the project's scope
3. Think about implementation complexity

### Feature Request Template
```markdown
**Feature Description**
Brief description of the feature

**Use Case**
Why is this feature needed?

**Proposed Solution**
How should it work?

**Alternatives Considered**
Other approaches you've thought about

**Additional Context**
Any other relevant information
```

## 📚 Documentation

### Types of Documentation
- **Code comments**: Explain complex logic
- **Docstrings**: Document functions and classes
- **README updates**: Update usage examples
- **Wiki pages**: Detailed guides and tutorials

### Documentation Standards
- Use clear, concise language
- Include examples where helpful
- Keep documentation up to date
- Use proper markdown formatting

## 🔒 Security

### Security Considerations
- Never include sensitive data in code
- Be careful with subprocess calls
- Validate all user inputs
- Follow secure coding practices

### Reporting Security Issues
- **DO NOT** open public issues for security vulnerabilities
- Email security issues to: security@hawkeye-scanner.com
- Include detailed reproduction steps
- Allow time for response before disclosure

## 🏷️ Release Process

### Version Numbering
- **Major** (2.0.0): Breaking changes
- **Minor** (2.1.0): New features, backward compatible
- **Patch** (2.0.1): Bug fixes, backward compatible

### Release Checklist
- [ ] Update version in `hawkeye.py`
- [ ] Update `CHANGELOG.md`
- [ ] Run all tests
- [ ] Update documentation
- [ ] Create release notes
- [ ] Tag release

## 🤝 Community Guidelines

### Be Respectful
- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community

### Be Constructive
- Provide helpful feedback
- Suggest improvements
- Share knowledge and experience
- Help others learn

## 📞 Getting Help

### Resources
- **Issues**: [GitHub Issues](https://github.com/yourusername/hawkeye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hawkeye/discussions)
- **Wiki**: [Project Wiki](https://github.com/yourusername/hawkeye/wiki)

### Questions
- Use GitHub Discussions for questions
- Be specific about your problem
- Include relevant code and error messages
- Search existing discussions first

## 🎉 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project README (for significant contributions)

## 📄 License

By contributing to Hawkeye, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Hawkeye! 🦅
