"""The app: greets, and reports the machine's uptime through the helper it still imports from the old copy."""
from old import helper


def main():
    print(helper.greet("world"))
    print(helper.uptime())


if __name__ == "__main__":
    main()
