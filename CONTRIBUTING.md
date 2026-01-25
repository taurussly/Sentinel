# Contributing to Sentinel

First off, thanks for taking the time to contribute! 🎉

## Code of Conduct

Be respectful. Be constructive. We're all here to build something useful.

## How Can I Contribute?

### Reporting Bugs

1. Check if the bug was already reported in [Issues](https://github.com/yourusername/sentinel/issues)
2. If not, create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version, OS, and Sentinel version

### Suggesting Features

Open an issue with the `[Feature]` prefix. Describe:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

### Pull Requests

1. Fork the repo
2. Create a branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest tests/ -v`)
5. Ensure coverage stays above 80%
6. Commit with clear messages (`git commit -m 'feat: add amazing feature'`)
7. Push and open a PR

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sentinel.git
cd sentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=sentinel --cov-report=term-missing
```

## Code Style

- Use type hints everywhere
- Follow PEP 8
- Docstrings for all public functions
- Keep functions small and focused

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `chore:` Maintenance tasks

## Testing

- Write tests before implementing (TDD encouraged)
- Maintain 80%+ coverage
- Test both success and failure cases
- Use pytest fixtures for common setups

```bash
# Run specific test file
pytest tests/test_wrapper.py -v

# Run tests matching a pattern
pytest tests/ -v -k "anomaly"

# Run with coverage report
pytest tests/ -v --cov=sentinel --cov-report=html
```

## Project Structure

```
sentinel/
├── src/sentinel/
│   ├── core/          # Wrapper, decorator, exceptions
│   ├── rules/         # Rule engine and parsing
│   ├── approval/      # Approval interfaces (terminal, webhook)
│   ├── audit/         # Audit logging
│   ├── anomaly/       # Anomaly detection
│   ├── dashboard/     # Streamlit dashboard
│   └── integrations/  # LangChain, etc.
├── tests/             # Test files mirror src structure
├── examples/          # Usage examples
├── docs/              # Documentation
└── config/            # Sample configurations
```

## Questions?

Open an issue with the `[Question]` prefix or reach out to the maintainers.

---

Thanks for contributing to Sentinel! 🛡️
