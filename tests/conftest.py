import os
import shutil
import tempfile

import pytest

# Must run before any ztz import: ztz resolves ~/.ztz paths at module import time,
# and tests such as init_environment(force=True) would otherwise overwrite the
# developer's real authority key and cache.
_FAKE_HOME = tempfile.mkdtemp(prefix="ztz-test-home-")
for _var in ("HOME", "USERPROFILE"):
    os.environ[_var] = _FAKE_HOME
os.environ.pop("HOMEDRIVE", None)
os.environ.pop("HOMEPATH", None)
os.environ.pop("ZTZ_TRUST_LOCAL", None)


@pytest.fixture(scope="session", autouse=True)
def _isolated_home():
    from ztz.core import setup, trust_store, cache

    for path in (setup.ZTZ_HOME, trust_store.DEFAULT_ZTZ_STORE, cache.CACHE_DB_PATH):
        assert path.startswith(_FAKE_HOME), f"test would touch real home: {path}"
    yield
    shutil.rmtree(_FAKE_HOME, ignore_errors=True)
