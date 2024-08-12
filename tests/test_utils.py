import pytest

from fence.config import FenceConfig


def test_find_duplicates():
    dup_case = FenceConfig._find_duplicates([1, 1, 2])
    unique_case = FenceConfig._find_duplicates([1, 2, 3])
    tuple_dup_case = FenceConfig._find_duplicates((1, 1, 1))
    tuple_unique_case = FenceConfig._find_duplicates((1, 2, 3))
    assert (dup_case == {1} and unique_case == set() and
            tuple_dup_case == {1} and tuple_unique_case == set())


def test__coerce_to_array():
    identity_case = FenceConfig._coerce_to_array([1, 2, 3])
    wrap_case = FenceConfig._coerce_to_array({"foo": "bar"})
    none_case = FenceConfig._coerce_to_array(None)
    assert (identity_case == [1, 2, 3] and wrap_case == [{"foo": "bar"}] and
            none_case == [])

    test_message = "foo"
    with pytest.raises(ValueError):
        bad_case = FenceConfig._coerce_to_array("uh oh")
    with pytest.raises(ValueError):
        bad_case_custom = FenceConfig._coerce_to_array("uh oh", test_message)


def test__some():
    test_pred = lambda v: 2 > v > 0
    one_case = FenceConfig._some(test_pred, [3, 2, 1])
    two_case = FenceConfig._some(test_pred, [3, 2, 0.5, 2, 1])
    none_case = FenceConfig._some(test_pred, [0, 0, 0])
    custom_none_case = FenceConfig._some(test_pred, [0], "foo")
    assert (one_case == 1 and two_case == 0.5 and
            none_case is None and custom_none_case == "foo")
