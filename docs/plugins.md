# Plugin Sources (Community)

CloudKill's data sources are plugins by design. The 15+ built-in sources live
inside the package, but **anyone can add a new source without touching
CloudKill's code** — through Python entry points.

## Publish your own source in 3 steps

### 1. Implement a `BaseSource` subclass

```python
# my_package/source.py
import os
from cloudkill.sources.base import BaseSource, SourceResult

class MyOriginSource(BaseSource):
    name = "my-origin"
    description = "Finds origins from my private API"
    requires_api_key = True
    supports_ipv6 = True

    def is_configured(self) -> bool:
        return bool(os.getenv("MY_API_KEY"))

    async def enumerate(self, domain):
        async with self.engine.get("https://api.example.com", params={"q": domain}) as resp:
            data = await resp.json()
        for hit in data["origins"]:
            yield SourceResult(
                subdomain=hit["host"],
                ip=hit["ip"],
                source=self.name,
            )
```

### 2. Register the entry point

In your package's `pyproject.toml`:

```toml
[project.entry-points."cloudkill.sources"]
my-origin = "my_package.source:MyOriginSource"
```

### 3. Install it next to CloudKill

```bash
pip install cloudkill-my-origin
cloudkill sources     # → my-origin  (plugin) ✓
```

That's it. CloudKill discovers it automatically, respects
`is_configured()`, feeds it through the enrichment pipeline and the
confidence scorer, and includes it in exports.

## Rules of the road

- A broken plugin **never breaks a scan**: load failures are logged and
  skipped.
- Classes that are not `BaseSource` subclasses are rejected at load time.
- Respect `self.rate_limiter` semantics — the shared batch budget depends on
  sources going through the normal request path.

## Registry API

```python
from cloudkill.sources.loader import load_plugin_sources

plugins = load_plugin_sources()   # {name: BaseSource subclass}
```
