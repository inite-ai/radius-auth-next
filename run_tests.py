#!/usr/bin/env python3
"""Test runner script for authorization service."""

import argparse
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list, description: str) -> bool:
    """Run a command and return success status."""
    print(f"\n🔧 {description}")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} - SUCCESS")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - FAILED")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return False


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(description="Run authorization service tests")
    parser.add_argument(
        "--test-type",
        choices=["all", "integration", "unit", "auth", "oauth", "security"],
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run tests with coverage reporting"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Skip slow tests"
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run tests in parallel"
    )
    
    args = parser.parse_args()
    
    # Base pytest command
    cmd = ["python3", "-m", "pytest"]
    
    # Add test path based on type
    if args.test_type == "all":
        cmd.append("tests/")
    elif args.test_type == "integration":
        cmd.append("tests/integration/")
    elif args.test_type == "unit":
        cmd.append("tests/unit/")
    else:
        cmd.extend(["-m", args.test_type])
    
    # Add options
    if args.verbose:
        cmd.append("-v")
    
    if args.fast:
        cmd.extend(["-m", "not slow"])
    
    if args.parallel:
        cmd.extend(["-n", "auto"])  # Requires pytest-xdist
    
    if args.coverage:
        cmd.extend([
            "--cov=app",
            "--cov-report=html",
            "--cov-report=term-missing",
            "--cov-fail-under=80"
        ])
    
    # Run the tests
    success = run_command(cmd, f"Running {args.test_type} tests")
    
    if success:
        print("\n🎉 All tests passed!")
        
        if args.coverage:
            print("\n📊 Coverage report generated in htmlcov/")
            print("Open htmlcov/index.html in your browser to view detailed coverage.")
            
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
