#!/usr/bin/env python3
"""Simple test script to verify code quality."""


def test_function():
    # Test with wrong style to see if pre-commit catches it
    return "Hello World"


if __name__ == "__main__":
    print(test_function())
