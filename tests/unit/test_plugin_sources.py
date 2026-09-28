"""Tests for cloudkill.sources.loader — entry-point plugin discovery."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from cloudkill.sources.base import BaseSource
from cloudkill.sources.loader import load_plugin_sources


class FakePluginSource(BaseSource):
    name = "fake-plugin"
    description = "A fake source registered via entry points"

    async def enumerate(self, domain):
        yield


class NotASource:  # violates the protocol
    name = "bogus"


def _ep(name, obj):
    return SimpleNamespace(name=name, load=lambda: obj)


def test_valid_plugin_source_is_loaded():
    with patch("cloudkill.sources.loader.entry_points",
               return_value=[_ep("fake-plugin", FakePluginSource)]):
        out = load_plugin_sources()
    assert "fake-plugin" in out
    assert out["fake-plugin"].is_plugin is True


def test_broken_plugin_is_skipped_not_fatal():
    def boom():
        raise ImportError("half-installed package")

    with patch("cloudkill.sources.loader.entry_points",
               return_value=[_ep("broken", boom)]):
        out = load_plugin_sources()
    assert "broken" not in out


def test_non_basesource_class_is_rejected():
    with patch("cloudkill.sources.loader.entry_points",
               return_value=[_ep("bogus", NotASource)]):
        out = load_plugin_sources()
    assert "bogus" not in out


def test_no_plugins_returns_empty():
    with patch("cloudkill.sources.loader.entry_points", return_value=[]):
        assert load_plugin_sources() == {}


def test_registered_plugin_integrates_with_registry():
    """A loaded plugin registers into the source registry like built-ins."""
    from cloudkill.sources import _SOURCE_REGISTRY, _register_source
    with patch("cloudkill.sources.loader.entry_points",
               return_value=[_ep("fake-plugin", FakePluginSource)]):
        for name, cls in load_plugin_sources().items():
            if name not in _SOURCE_REGISTRY:
                _register_source(cls)
    assert _SOURCE_REGISTRY["fake-plugin"] is FakePluginSource
