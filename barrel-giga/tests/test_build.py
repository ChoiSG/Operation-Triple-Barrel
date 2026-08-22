from __future__ import annotations

import unittest
from pathlib import Path

from barrel_giga.core.config import Recipe
from barrel_giga.core.modules import ModuleRegistry
from barrel_giga.core.profiles import PROFILE_NAMES, TOOLCHAIN_NAMES
from barrel_giga.injectable import inspect_path, load_spec


ROOT = Path(__file__).resolve().parents[1]


class FixedBuildTests(unittest.TestCase):
    def test_registry_contains_only_the_fixed_recipe(self):
        registry = ModuleRegistry(ROOT / "modules").discover()
        registry.validate_all()
        selected = registry.select(Recipe())
        self.assertEqual(
            [module.qualified_name for module in selected],
            [
                "guardrail/none",
                "anti_emulation/none",
                "memory/image_split_restore",
                "decoder/xor_stream",
                "execute/thread_keepalive",
                "pe_invoke/function_backdoor",
            ],
        )
        self.assertEqual(len(registry.rows()), 6)

    def test_fixed_recipe_contract(self):
        recipe = Recipe()
        self.assertEqual(recipe.guardrail, "none")
        self.assertEqual(recipe.anti_emulation, "none")
        self.assertEqual(recipe.memory, "image_split_restore")
        self.assertEqual(recipe.decoder, "xor_stream")
        self.assertEqual(recipe.execute, "thread_keepalive")
        self.assertEqual(recipe.pe_invoke, "function_backdoor")

    def test_profiles_are_native_only(self):
        self.assertEqual(PROFILE_NAMES, ("auto", "windows", "linux"))
        self.assertEqual(TOOLCHAIN_NAMES, ("auto", "msvc", "mingw"))

    def test_prepared_applewin_matches_the_pin(self):
        path = ROOT / "bin" / "injectables" / "AppleWin-x64.exe"
        if not path.is_file():
            self.skipTest("run `py barrel-giga.py prep` first")
        status = inspect_path(load_spec(ROOT / "injectable.json"), path)
        self.assertEqual(status.status, "ready", status.reason)
        self.assertIsNotNone(status.pe)


if __name__ == "__main__":
    unittest.main()
