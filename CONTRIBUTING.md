# Contributing to CloudFail-Killer

Thank you for your interest in contributing to CloudFail-Killer! This guide covers everything you need to get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding a New Data Source](#adding-a-new-data-source)
- [Adding a New Exporter](#adding-a-new-exporter)
- [Code Style](#code-style)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Notes](#security-notes)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this standard.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/smart-jemy/cloudfail-killer.git
   cd cloudfail-killer
   ```
3. Install in development mode with all optional dependencies:
   ```bash
   pip install -e ".[dev,pdf]"
   ```
4. Verify the installation:
   ```bash
   cloudkill --version
   pytest tests/ -q
   ```

## Development Setup

### Prerequisites

- Python 3.11+
- pip (latest)
- Git

### Install Dependencies

```bash
# Core development tools
pip install -e ".[dev]"

# With PDF export support
pip install -e ".[dev,pdf]"

# All optional dependencies
pip install -e ".[all]"
```

### Environment Configuration

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` with your API keys (optional — most sources work without keys):
```
OTX_API_KEY=your-otx-key
SHODAN_API_KEY=your-shodan-key
CENSYS_API_ID=your-censys-id
CENSYS_API_SECRET=your-censys-secret
```

## Project Structure

```
cloudkill/
├── cli.py              # CLI entry point (Typer)
├── config.py           # Configuration & profiles (Pydantic)
├── core/               # Core engine components
│   ├── engine.py       # Async HTTP client (httpx, HTTP/2, IPv6)
│   ├── runner.py       # Pipeline orchestrator
│   ├── models.py       # Data models (EnrichedResult, ScanReport)
│   ├── enrichment.py   # Enrichment pipeline coordinator
│   ├── active_scanner.py
│   ├── host_header.py
│   ├── webhooks.py
│   └── filters.py
├── sources/            # Data source plugins (BaseSource)
├── enrichers/          # Enrichment modules
├── exporters/          # Output format exporters
├── cache/              # SQLite cache
├── utils/              # Utilities (DNS, favicon, stealth)
└── profiles/           # Profile YAML configs
```

## Adding a New Data Source

1. **Create the source plugin** in `cloudkill/sources/your_source.py`:

```python
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

class YourSource(BaseSource):
    name = "your_source"
    description = "Your source description"
    priority = 5  # 1-10, higher = more important

    async def enumerate(self, domain: str) -> list[SourceResult]:
        """Enumerate IPs/subdomains for the given domain."""
        results = []
        # ... your logic here ...
        return results
```

2. **Register the source** in `cloudkill/sources/__init__.py`:

```python
from cloudkill.sources.your_source import YourSource

# Add to SOURCE_CLASSES list
SOURCE_CLASSES.append(YourSource)
```

3. **Add unit tests** in `tests/unit/test_your_source.py`:

```python
import pytest
from cloudkill.sources.your_source import YourSource

class TestYourSource:
    def test_name(self):
        assert YourSource.name == "your_source"

    async def test_enumerate(self):
        source = YourSource(config=mock_config)
        results = await source.enumerate("example.com")
        # assertions...
```

4. **Run tests** to verify everything works:
```bash
pytest tests/unit/test_your_source.py -v
```

## Adding a New Exporter

1. **Create the exporter** in `cloudkill/exporters/your_format.py`:

```python
from pathlib import Path
from cloudkill.core.models import ScanReport

def export_your_format(report: ScanReport, output_path: Path, **kwargs) -> Path:
    """Export report in your format."""
    # ... your logic ...
    return output_path
```

2. **Register** in `cloudkill/exporters/__init__.py`
3. **Wire up** in `cloudkill/cli.py` `_save_report()` function
4. **Add tests** in `tests/unit/`

## Code Style

- **Formatter**: [Ruff](https://docs.astral.sh/ruff/) — `ruff format cloudkill/`
- **Linter**: Ruff — `ruff check cloudkill/`
- **Type Checker**: MyPy — `mypy cloudkill/`
- **Line length**: 100 characters max
- **Type hints**: Required for all public functions
- **Docstrings**: Required for all public classes and methods

### Pre-commit Hooks (recommended)

```bash
pip install pre-commit
pre-commit install
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Performance benchmarks
pytest tests/benchmarks/ -v

# Specific phase
pytest tests/unit/test_phase4.py -v
```

### Coverage Report

```bash
pytest tests/ --cov=cloudkill --cov-report=html
```

### Writing Tests

- Unit tests go in `tests/unit/test_phaseN.py` or `tests/unit/test_feature.py`
- Integration tests go in `tests/integration/`
- Use `pytest-asyncio` for async tests
- Use `unittest.mock` for HTTP mocking
- Test error cases, edge cases, and boundary conditions

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(source): add Shodan API source plugin
fix(scoring): correct ASN 14061 DO/Azure conflict
docs(readme): add Docker usage examples
test(integration): add full pipeline tests
refactor(engine): extract rate limiter to separate module
```

## Pull Request Process

1. **Update documentation** for any changed behavior
2. **Add tests** for all new features
3. **Ensure CI passes**: lint, type-check, tests, security scan
4. **Keep PRs focused**: One feature or fix per PR
5. **Write a clear description** explaining the change and motivation
6. **Link related issues** using `Fixes #123` or `Closes #123`

## Security Notes

- **Never commit API keys** or secrets to the repository
- Use `.env` file for local configuration (`.env` is git-ignored)
- Report security vulnerabilities privately (see [SECURITY.md](SECURITY.md))
- The active scanner uses HTTP-level probing only — no raw SYN scans
- All HTTP requests use encryption (HTTPS) by default
