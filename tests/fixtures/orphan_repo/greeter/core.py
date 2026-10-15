def greet(name="world"):
    return "hello " + name


def shout(name):
    return greet(name).upper()


def format_for_tests(name):
    return "<%s>" % name
