from cleanpkg import cli


def test_main_is_callable():
    assert callable(cli.main)
