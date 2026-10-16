# pytest capture

Written by pytest 9.1.1 on Python 3.12 on 2026-10-16.

```sh
python -m pytest -p no:cacheprovider -o junit_family=xunit2 --junitxml=junit.xml -q test_demo.py
```

Two values were sanitized after capture: the `hostname` attribute is
`build-host`, and the absolute path in the skip message was cut to
`test_demo.py:21`.

`test_demo.py`:

```python
import pytest


@pytest.fixture
def broken():
    raise RuntimeError("fixture setup failed")


def test_pass():
    assert True


def test_fail():
    assert 1 == 2


def test_error(broken):
    assert broken


@pytest.mark.skip(reason="not applicable")
def test_skip():
    pass
```

pytest reported 1 passed, 1 failed, 1 error and 1 skipped.
