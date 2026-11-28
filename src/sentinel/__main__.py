"""Entry point for running Sentinel via ``python -m sentinel``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
