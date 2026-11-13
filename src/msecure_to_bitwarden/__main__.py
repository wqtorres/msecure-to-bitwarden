"""Allow running the tool with: python -m msecure_to_bitwarden"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
