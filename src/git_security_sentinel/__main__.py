"""
Package execution entry point: python -m git_security_sentinel
"""

import sys
from git_security_sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
