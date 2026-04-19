# Contributing to SurfaceAudit

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Development Environment

```bash
# Clone the repo
git clone https://github.com/your-org/surfaceaudit.git
cd surfaceaudit

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run the full test suite
pytest tests/

# Run a specific test file
pytest tests/test_rule_engine.py

# Run with verbose output
pytest tests/ -v
```

The project uses [Hypothesis](https://hypothesis.readthedocs.io/) for property-based testing. These tests run automatically alongside standard unit tests.

## Adding YAML Rules

Rules live in `surfaceaudit/rules/` under two directories:

- `classification/` — map asset attributes to an asset type
- `assessment/` — map asset attributes to vulnerability indicators

### Classification Rule

Create a new `.yaml` file in `surfaceaudit/rules/classification/`:

```yaml
rules:
  - id: cls-my-service
    name: My Service
    match:
      ports: [9200, 9300]
      banners: ["elasticsearch"]
    asset_type: database
```

Required fields: `id`, `name`, `match` (with at least one of `ports`, `banners`, `services`), `asset_type`.

### Assessment Rule

Create a new `.yaml` file in `surfaceaudit/rules/assessment/`:

```yaml
rules:
  - id: assess-my-finding
    name: Elasticsearch Exposed
    match:
      ports: [9200]
    severity: high
    category: risky_port
    description: "Elasticsearch port 9200 is publicly accessible"
```

Required fields: `id`, `name`, `match`, `severity`, `description`, `category`.

## Adding a New Provider

1. Create `surfaceaudit/providers/your_provider.py`
2. Subclass `BaseProvider` and implement all abstract methods:

```python
from surfaceaudit.providers.base import BaseProvider
from surfaceaudit.models import RawAsset

class YourProvider(BaseProvider):
    def name(self) -> str:
        return "your_provider"

    def authenticate(self, api_key: str) -> None:
        # Validate credentials
        ...

    def get_credits(self) -> int:
        # Return available API quota
        ...

    def discover(self, targets: list[str]) -> list[RawAsset]:
        # Query the data source and return raw assets
        ...
```

3. Register it in `surfaceaudit/providers/__init__.py`:

```python
from surfaceaudit.providers.your_provider import YourProvider
ProviderRegistry.register("your_provider", YourProvider)
```

4. Add tests in `tests/test_providers.py`.

## Code Style

- Format with [Black](https://github.com/psf/black)
- Type hints on all public functions
- Docstrings on modules and classes

## Pull Requests

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure `pytest tests/` passes
4. Open a PR with a clear description of the change
