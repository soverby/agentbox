"""agentbox command line. P0: --version and validate."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys

from . import __version__
from .profile import ProfileError, load_profile


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        profile = load_profile(args.file, name=args.name)
    except ProfileError as e:
        for path, msg in e.problems:
            print(f"error: {path}: {msg}", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(profile), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentbox", description="Docker sandboxes for AI agents")
    parser.add_argument("--version", action="version", version=f"agentbox {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    p = sub.add_parser("validate", help="validate a profile file and print it resolved")
    p.add_argument("file")
    p.add_argument("--name", help="profile name (default: file name without .toml)")
    p.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
