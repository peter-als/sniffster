#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


TEST_LINE_RE = re.compile(r"^\s*Test\s+#\d+:\s+(?P<name>.+?)\s*$")


def discover_tests(repo_root: Path, preset: str) -> list[str]:
    result = subprocess.run(
        ["ctest", "--preset", preset, "-N"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=True,
    )

    tests: list[str] = []
    for line in result.stdout.splitlines():
        match = TEST_LINE_RE.match(line)
        if match:
            tests.append(match.group("name"))
    return tests


def print_tests(tests: list[str]) -> None:
    for name in tests:
        print(name)


def build_exact_regex(names: list[str]) -> str:
    return "^(" + "|".join(re.escape(name) for name in names) + ")$"


def select_tests_by_prefix(discovered: list[str], prefixes: list[str]) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()

    for prefix in prefixes:
        matches = [name for name in discovered if name.startswith(prefix)]
        if not matches:
            raise ValueError(prefix)
        for name in matches:
            if name not in seen:
                selected.append(name)
                seen.add(name)

    return selected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List discovered CTest tests from the build and optionally run selected names."
    )
    parser.add_argument(
        "tests",
        nargs="*",
        help="Discovered CTest name prefixes to run, for example PacketMetaEvent or SnifferTest.Sample.",
    )
    parser.add_argument(
        "--preset",
        default="debug",
        help="CTest preset to query and run. Default: debug",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List discovered tests and exit.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all discovered tests for the selected preset.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent
    discovered = discover_tests(repo_root, args.preset)

    if args.list or (not args.tests and not args.all):
        print_tests(discovered)
        return 0

    if args.all:
        selected = discovered
    else:
        try:
            selected = select_tests_by_prefix(discovered, args.tests)
        except ValueError as error:
            print("Unknown test prefix:", file=sys.stderr)
            print(error.args[0], file=sys.stderr)
            print("\nDiscovered tests:", file=sys.stderr)
            print_tests(discovered)
            return 2

    regex = build_exact_regex(selected)
    command = ["ctest", "--preset", args.preset, "--output-on-failure", "-R", regex]
    print("Running:", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=repo_root)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
