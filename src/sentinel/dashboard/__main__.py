"""Main entry point for running the Sentinel Dashboard.

Usage:
    python -m sentinel.dashboard [--port PORT] [--api-port API_PORT]

This starts both the Streamlit dashboard and the FastAPI server.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path

import uvicorn


def run_api_server(port: int = 8000):
    """Run the FastAPI server in a separate thread."""
    from sentinel.dashboard.api import app

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


def run_streamlit(port: int = 8501):
    """Run the Streamlit app."""
    app_path = Path(__file__).parent / "app.py"

    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        str(app_path),
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
    ])


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Sentinel Command Center - Dashboard for AI Agent Governance"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Port for the Streamlit dashboard (default: 8501)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=8000,
        help="Port for the FastAPI server (default: 8000)",
    )
    parser.add_argument(
        "--api-only",
        action="store_true",
        help="Run only the API server (no dashboard UI)",
    )
    parser.add_argument(
        "--dashboard-only",
        action="store_true",
        help="Run only the dashboard (no API server)",
    )

    args = parser.parse_args()

    print("\U0001F6E1\uFE0F  Sentinel Command Center")
    print("=" * 40)

    if args.api_only:
        print(f"Starting API server on port {args.api_port}...")
        print(f"API URL: http://localhost:{args.api_port}")
        print(f"API Docs: http://localhost:{args.api_port}/docs")
        run_api_server(args.api_port)
    elif args.dashboard_only:
        print(f"Starting Dashboard on port {args.port}...")
        print(f"Dashboard URL: http://localhost:{args.port}")
        run_streamlit(args.port)
    else:
        # Run both
        print(f"Starting API server on port {args.api_port}...")
        print(f"Starting Dashboard on port {args.port}...")
        print()
        print(f"Dashboard URL: http://localhost:{args.port}")
        print(f"API URL: http://localhost:{args.api_port}")
        print(f"API Docs: http://localhost:{args.api_port}/docs")
        print()
        print("Configure your Sentinel agent to use:")
        print(f'  webhook_url="http://localhost:{args.api_port}/approval"')
        print(f'  status_url_template="http://localhost:{args.api_port}/approval/{{action_id}}/status"')
        print()

        # Start API server in background thread
        api_thread = threading.Thread(
            target=run_api_server,
            args=(args.api_port,),
            daemon=True,
        )
        api_thread.start()

        # Give API server time to start
        time.sleep(1)

        # Run Streamlit in main thread (blocking)
        run_streamlit(args.port)


if __name__ == "__main__":
    main()
