import sys

from greeter.core import greet


def cmd_hello(name="world"):
    return greet(name)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return greet()
    handler = getattr(sys.modules[__name__], "cmd_" + argv[0])
    return handler(*argv[1:])
