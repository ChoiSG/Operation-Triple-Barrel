from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from barrel_giga.cli import (
    INJECTABLES,
    _progress,
    build_parser,
    _resolve_existing_path,
    _resolve_injectable_path,
)
from barrel_giga.injectable import load_spec


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_progress_uses_a_simple_success_prefix(self):
        with patch("builtins.print") as mocked_print:
            _progress(62, "Working")
        mocked_print.assert_called_once_with("[+] Working")

    def test_commands_are_limited_to_prep_list_and_build(self):
        parser = build_parser()
        command = next(action for action in parser._actions if action.dest == "command")
        self.assertEqual(set(command.choices), {"prep", "list", "build"})

    def test_build_requires_the_final_three_paths(self):
        args = build_parser().parse_args(
            [
                "build",
                "--input",
                "payload.bin",
                "--injectable",
                "AppleWin-x64.exe",
                "--output",
                "output.exe",
            ]
        )
        self.assertEqual(args.input, Path("payload.bin"))
        self.assertEqual(args.injectable, Path("AppleWin-x64.exe"))
        self.assertEqual(args.output, Path("output.exe"))

    def test_build_exposes_no_recipe_controls(self):
        parser = build_parser()
        command = next(action for action in parser._actions if action.dest == "command")
        build = command.choices["build"]
        arguments = {action.dest for action in build._actions}
        self.assertEqual(arguments, {"help", "input", "injectable", "output"})

    def test_listed_name_resolves_from_the_managed_cache(self):
        spec = load_spec(ROOT / "injectable.json")
        self.assertEqual(
            _resolve_injectable_path(Path("AppleWin-x64.exe"), spec),
            (INJECTABLES / spec.name).resolve(),
        )

    def test_missing_shell_path_falls_back_to_project_relative(self):
        with TemporaryDirectory(prefix="barrel-giga-path-test-") as temporary:
            project = Path(temporary)
            expected = project / "inputs" / "payload.bin"
            expected.parent.mkdir()
            expected.write_bytes(b"payload")
            self.assertEqual(
                _resolve_existing_path(Path("inputs") / "payload.bin", project),
                expected.resolve(),
            )


if __name__ == "__main__":
    unittest.main()
