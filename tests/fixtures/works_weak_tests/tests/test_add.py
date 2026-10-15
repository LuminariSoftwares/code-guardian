import unittest

import pytest

from weakpkg import add


def check_sum(a, b, total):
    assert add(a, b) == total


def test_runs():
    add(1, 2)


def test_nothing():
    pass


def test_asserts():
    assert add(1, 2) == 3


def test_raises():
    with pytest.raises(TypeError):
        add(1, None)


def test_helper():
    check_sum(1, 2, 3)


class TestAdd(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(add(2, 2), 4)

    def test_silent(self):
        add(2, 2)
