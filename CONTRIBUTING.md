# Contributing to TraylinxAuthClient (Python)

Thank you for your interest in contributing to the TraylinxAuthClient Python library! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment. By participating, you agree to uphold these standards:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Prioritize community well-being
- Report unacceptable behavior to the maintainers

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Poetry for dependency management
- Git for version control

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/traylinx-auth-client-py.git
   cd traylinx-auth-client-py
   ```

## Development Setup

### Install Dependencies

1. Install Poetry if you haven't already:
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

2. Install project dependencies:
   ```bash
   poetry install
   ```

3. Activate the virtual environment:
   ```bash
   poetry shell
   ```

### Environment Configuration

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Configure your test environment variables:
   ```bash
   # .env
   TRAYLINX_CLIENT_ID=your_test_client_id
   TRAYLINX_CLIENT_SECRET=your_test_client_secret
   TRAYLINX_API_BASE_URL=https://your-test-api.com
   TRAYLINX_AGENT_USER_ID=your-test-uuid
   ```

## Development Workflow

### Branch Naming

Use descriptive branch names with prefixes:
- `feature/add-new-validation`
- `bugfix/fix-token-refresh`
- `docs/update-readme`
- `test/add-error-scenarios`

### Making Changes

1. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code style guidelines
3. Add or update tests for your changes
4. Update documentation if needed
5. Commit your changes with clear messages

### Commit Messages

Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(auth): add input validation for client configuration`
- `fix(network): handle connection timeout errors properly`
- `docs(readme): add troubleshooting section`
- `test(client): add tests for error scenarios`

## Testing

### Running Tests

Run the full test suite:
```bash
poetry run pytest
```

Run tests with coverage:
```bash
poetry run pytest --cov=traylinx_auth_client --cov-report=html
```

Run specific test files:
```bash
poetry run pytest tests/test_client.py
```

Run tests with verbose output:
```bash
poetry run pytest -v
```

### Test Requirements

- All new features must include comprehensive tests
- Bug fixes must include regression tests
- Maintain >90% test coverage
- Tests should cover both success and error scenarios
- Include integration tests for complex features

### Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── test_client.py      # Main client functionality
│   ├── test_config.py      # Configuration validation
│   ├── test_exceptions.py  # Exception hierarchy
│   └── test_token_manager.py # Token management
├── integration/            # Integration tests
│   ├── test_auth_flow.py   # End-to-end authentication
│   └── test_error_scenarios.py # Error handling
└── fixtures/               # Test data and mocks
    └── mock_responses.py   # Mock API responses
```

### Writing Tests

Use pytest conventions and fixtures:

```python
import pytest
from traylinx_auth_client import TraylinxAuthClient
from traylinx_auth_client.exceptions import ValidationError

def test_client_validates_client_id():
    """Test that invalid client_id raises ValidationError"""
    with pytest.raises(ValidationError, match="Client ID must contain only"):
        TraylinxAuthClient(
            client_id="invalid@client",  # Invalid character
            client_secret="valid_secret",
            api_base_url="https://api.example.com",
            agent_user_id="550e8400-e29b-41d4-a716-446655440000"
        )

@pytest.fixture
def mock_auth_response():
    """Fixture for mocking authentication responses"""
    return {
        "access_token": "test_access_token",
        "agent_secret_token": "test_agent_secret_token",
        "expires_in": 3600
    }
```

## Code Style

### Python Style Guidelines

- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Maximum line length: 88 characters (Black default)
- Use descriptive variable and function names
- Add docstrings to all public methods and classes

### Code Formatting

Use Black for code formatting:
```bash
poetry run black traylinx_auth_client/ tests/
```

Use isort for import sorting:
```bash
poetry run isort traylinx_auth_client/ tests/
```

### Linting

Run flake8 for linting:
```bash
poetry run flake8 traylinx_auth_client/ tests/
```

Run mypy for type checking:
```bash
poetry run mypy traylinx_auth_client/
```

### Pre-commit Hooks

Install pre-commit hooks to automatically format and lint:
```bash
poetry run pre-commit install
```

## Submitting Changes

### Pull Request Process

1. Ensure all tests pass and coverage is maintained
2. Update documentation for any API changes
3. Add entries to CHANGELOG.md for notable changes
4. Create a pull request with:
   - Clear title and description
   - Reference to related issues
   - List of changes made
   - Testing instructions

### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Coverage maintained above 90%

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
```

### Review Process

1. Automated checks must pass (tests, linting, coverage)
2. At least one maintainer review required
3. Address all review feedback
4. Squash commits before merging (if requested)

## Release Process

### Version Numbering

Follow Semantic Versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md with release notes
3. Create release branch: `release/v1.x.x`
4. Run full test suite and quality checks
5. Create GitHub release with tag
6. Publish to PyPI: `poetry publish`

## Getting Help

### Documentation

- [README.md](README.md) - Basic usage and installation
- [API Documentation](docs/api.md) - Detailed API reference
- [Design Document](docs/design.md) - Architecture and design decisions

### Communication

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Security**: See [SECURITY.md](SECURITY.md) for security-related issues

### Maintainers

Current maintainers:
- [@maintainer1](https://github.com/maintainer1)
- [@maintainer2](https://github.com/maintainer2)

## Development Tips

### Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

client = TraylinxAuthClient(
    # ... config
    log_level="DEBUG"
)
```

### Testing Against Real API

For integration testing against a real API:
1. Set up test credentials in `.env`
2. Use the test environment endpoints
3. Never commit real credentials to version control

### Performance Testing

Run performance tests:
```bash
poetry run pytest tests/performance/ -v
```

Monitor memory usage:
```bash
poetry run python -m memory_profiler your_test_script.py
```

Thank you for contributing to TraylinxAuthClient! Your efforts help make this library better for everyone.