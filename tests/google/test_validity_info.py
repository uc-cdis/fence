"""
Tests for the fence.resources.google.access_utils.ValidityInfo object
"""
from fence.resources.google.access_utils import ValidityInfo

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


def test_dict_like_validity_object():
    test_validity = ValidityInfo()

    # should evaluate to true by default
    assert test_validity

    # adding a new item should still result in "true" validity
    test_validity['test_validity123'] = True
    assert test_validity

    # adding a new FALSE item should result in FALSE validity
    test_validity['test_validity567'] = False
    assert not test_validity

    for key, _ in test_validity:
        assert key in ['test_validity123', 'test_validity567']


def test_dict_like_validity_object_nested():
    test_validity = ValidityInfo()
    nested_test_validity = ValidityInfo()

    # should evaluate to true by default
    assert test_validity

    # adding a new FALSE item should result in FALSE validity
    nested_test_validity['test_validity567'] = False
    assert not nested_test_validity

    # top level should be false now
    test_validity['nested'] = nested_test_validity
    assert not test_validity

    assert 'nested' in test_validity
    assert 'test_validity567' in test_validity['nested']
    assert test_validity['nested']['test_validity567'] is False
