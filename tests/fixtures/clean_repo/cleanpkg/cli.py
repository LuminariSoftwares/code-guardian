import argparse

from cleanpkg.fetch import fetch


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cleanpkg")
    parser.add_argument("path", nargs="?", default="")
    args = parser.parse_args(argv)
    print(fetch(args.path))
    return 0
