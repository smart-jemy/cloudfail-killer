"""
CloudFail-Killer — External Source Plugin Loader

Third-party sources integrate through Python entry points, so the community
can add data sources WITHOUT touching CloudKill's code.

Publishing a plugin source — three steps:

1. Implement a subclass of ``cloudkill.sources.base.BaseSource``::

       from cloudkill.sources.base import BaseSource

       class MyOriginSource(BaseSource):
           name = "my-origin"
           description = "Finds origins from my own API"
           requires_api_key = True

           def is_configured(self) -> bool:
               return bool(os.getenv("MY_API_KEY"))

           async def enumerate(self, domain):
               ...  # yield SourceResult(...)

2. Expose it under the ``cloudkill.sources`` entry-point group in your
   package's metadata::

       [project.entry-points."cloudkill.sources"]
       my-origin = "my_package.source:MyOriginSource"

3. ``pip install`` your package next to CloudKill — done. CloudKill picks it
   up automatically and lists it in ``cloudkill sources`` marked ``(plugin)``.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from cloudkill.sources.base import BaseSource

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "cloudkill.sources"


def load_plugin_sources() -> dict[str, type[BaseSource]]:
    """
    Discover and load external sources registered under
    ``cloudkill.sources`` entry points.

    A broken plugin never breaks the tool: load failures are logged and
    skipped, and classes that are not BaseSource subclasses are rejected.
    """
    out: dict[str, type[BaseSource]] = {}
    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - very old importlib fallback
        eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[union-attr]

    for ep in eps:
        try:
            cls = ep.load()
        except Exception as e:
            logger.warning("Plugin source '%s' failed to load: %s", ep.name, e)
            continue
        if not (isinstance(cls, type) and issubclass(cls, BaseSource)):
            logger.warning(
                "Plugin source '%s' is not a BaseSource subclass — skipped", ep.name
            )
            continue
        cls.is_plugin = True  # type: ignore[attr-defined]
        out[cls.name] = cls
    return out
