from greeter.core import format_for_tests, greet


def test_greet():
    assert greet("a") == "hello a"


def test_format():
    assert format_for_tests("a") == "<a>"
