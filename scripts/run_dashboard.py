#!/usr/bin/env python
"""Script to start the Sentinel Dashboard.

This is a convenience script that can be run directly:
    python scripts/run_dashboard.py

Or you can use the module directly:
    python -m sentinel.dashboard
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for development
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from sentinel.dashboard.__main__ import main

if __name__ == "__main__":
    main()
