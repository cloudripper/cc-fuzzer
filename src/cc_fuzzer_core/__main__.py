"""`python3 -m cc_fuzzer_core` / the `cc-fuzzer` console script."""
import sys

from cc_fuzzer_core.cli import main as _cli_main


def main(argv=None):
    return _cli_main(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
