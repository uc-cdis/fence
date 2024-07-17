import pytest
from fence.metrics import Metrics


@pytest.fixture(scope="function")
def metrics_fixture():
    metrics = Metrics()
    yield metrics


def test_increment_counter(metrics_fixture):
    metrics_fixture.create_counter("test_counter", {"label": "test"})
    metrics_fixture.increment_counter("test_counter", {"label": "test"})
    assert (
        metrics_fixture.metrics["test_counter"].labels(label="test")._value.get() == 1
    )


def test_set_gauge(metrics_fixture):
    metrics_fixture.create_gauge("test_gauge", {"label": "test"})
    metrics_fixture.set_gauge("test_gauge", {"label": "test"}, 10)
    assert metrics_fixture.metrics["test_gauge"].labels(label="test")._value.get() == 10
