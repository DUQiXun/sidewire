#!/usr/bin/env python3
"""Launcher that works without installing anything.

    python sw.py serve
    python sw.py doctor
    python sw.py add sub 192.168.1.50 --key sw1_...
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sidewire.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
