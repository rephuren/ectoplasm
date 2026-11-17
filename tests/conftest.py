import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("ECTOPLASM_CACHE", str(tmp_path / "cache"))
