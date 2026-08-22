from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .core.config import BuildConfig
from .core.pipeline import build as build_carrier
from .injectable import (
    InjectableError,
    InjectableSpec,
    inspect_injectable,
    inspect_path,
    install_injectable,
    load_spec,
)
from .osslsigncode import prepare_osslsigncode


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "injectable.json"
INJECTABLES = ROOT / "bin" / "injectables"


def _resolve_existing_path(value: Path, project_root: Path = ROOT) -> Path:
    resolved = value.resolve()
    if resolved.exists() or value.is_absolute():
        return resolved
    project_relative = (project_root / value).resolve()
    return project_relative if project_relative.exists() else resolved


def _resolve_injectable_path(value: Path, spec: InjectableSpec) -> Path:
    if (
        not value.is_absolute()
        and len(value.parts) == 1
        and value.name.casefold() == spec.name.casefold()
    ):
        return (INJECTABLES / spec.name).resolve()
    return _resolve_existing_path(value)


def _prep(_: argparse.Namespace) -> int:
    spec = load_spec(MANIFEST)
    result = install_injectable(spec, INJECTABLES)
    item = result.injectable
    print(
        f"{item.name}: {result.action} ({item.size:,} bytes) "
        f"SHA256={item.sha256}"
    )
    print(f"path: {item.path}")
    signing_tool = prepare_osslsigncode()
    version = f"v{signing_tool.version}, " if signing_tool.version else ""
    print(
        f"osslsigncode: {signing_tool.action} "
        f"({version}{signing_tool.path})"
    )
    return 0


def _list(_: argparse.Namespace) -> int:
    spec = load_spec(MANIFEST)
    item = inspect_injectable(spec, INJECTABLES)
    print("NAME                 STATUS   ARCH   SIZE       SHA256")
    if item.status == "ready":
        assert item.pe is not None and item.size is not None and item.sha256 is not None
        print(
            f"{item.name:20} ready    x64    {item.size:10} {item.sha256}"
        )
        return 0
    print(f"{item.name:20} {item.status:8} -      -          -")
    print(f"reason: {item.reason}")
    return 1


def _progress(_percent: int, message: str) -> None:
    print(f"[+] {message}")


def _build(args: argparse.Namespace) -> int:
    spec = load_spec(MANIFEST)
    payload = _resolve_existing_path(args.input)
    injectable = _resolve_injectable_path(args.injectable, spec)
    output = args.output.resolve()
    if output.suffix.lower() != ".exe":
        raise InjectableError("output must use an .exe extension")
    if output in {payload, injectable}:
        raise InjectableError("output must not overwrite the input or injectable")

    status = inspect_path(spec, injectable)
    if status.status != "ready":
        raise InjectableError(
            f"injectable is not the pinned {spec.name}: {status.reason}"
        )

    artifact_dir = output.parent / f"{output.stem}.artifacts"
    config = BuildConfig(
        root=ROOT,
        payload=payload,
        host=injectable,
        output=output,
        artifact_dir=artifact_dir,
        self_sign=True,
    )
    command_line = [
        "barrel-giga.py",
        "build",
        "--input",
        str(payload),
        "--injectable",
        str(injectable),
        "--output",
        str(output),
    ]
    manifest = build_carrier(
        config,
        command_line=command_line,
        progress=_progress,
    )
    repairs = manifest["compatibility"]["planned_repairs"]
    print(f"output:   {manifest['injection']['output']}")
    print(f"manifest: {artifact_dir / 'manifest.json'}")
    print(f"sha256:   {manifest['injection']['output_sha256']}")
    print(f"signer:   {manifest['signing']['certificate_subject']}")
    print(f"timestamp: {manifest['signing']['timestamp_url']}")
    print(f"iat:      {len(repairs)} bounded repair(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="barrel-giga.py",
        description="Build a fixed-recipe x64 PE carrier",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    prep = commands.add_parser("prep", help="download pinned build dependencies")
    prep.set_defaults(func=_prep)

    listing = commands.add_parser("list", help="show injectable readiness")
    listing.set_defaults(func=_list)

    build = commands.add_parser("build", help="build the fixed Barrel-Giga carrier")
    build.add_argument("--input", type=Path, required=True)
    build.add_argument("--injectable", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.set_defaults(func=_build)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        if os.environ.get("BARREL_GIGA_DEBUG"):
            raise
        return 1
