import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AXSCRIPT = ROOT / "barrel-kit.axs"
MAKEFILE = ROOT / "Makefile"
BUILD_SCRIPT = ROOT / "build.sh"
LOADER_SOURCE = ROOT / "src" / "loader.c"


class InitialDelayTests(unittest.TestCase):
    def test_ui_exposes_optional_initial_delay(self):
        source = AXSCRIPT.read_text(encoding="utf-8")

        self.assertIn("Check-in Delay:", source)
        self.assertNotIn("0 disables the optional delay", source)
        self.assertIn("initialDelaySpin.setRange(0, 86400);", source)
        self.assertIn("initialDelaySpin.setValue(0);", source)
        self.assertIn('container.put("initial_delay", initialDelaySpin);', source)

    def test_ui_passes_delay_to_make(self):
        source = AXSCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            '"make INITIAL_CHECKIN_DELAY_SECONDS=" + String(initialDelay)',
            source,
        )

    def test_make_default_is_disabled(self):
        source = MAKEFILE.read_text(encoding="utf-8")

        self.assertIn("INITIAL_CHECKIN_DELAY_SECONDS ?= 0", source)
        self.assertIn(
            "-DINITIAL_CHECKIN_DELAY_SECONDS=$(INITIAL_CHECKIN_DELAY_SECONDS)",
            source,
        )
        self.assertIn("bin/loader.x64.o: FORCE", source)

    def test_loader_waits_before_reading_resources(self):
        source = LOADER_SOURCE.read_text(encoding="utf-8")

        delay_call = source.index("KERNEL32$Sleep((DWORD) INITIAL_CHECKIN_DELAY_SECONDS")
        resource_read = source.index("char *     pico_src")
        self.assertLess(delay_call, resource_read)
        self.assertIn("#if INITIAL_CHECKIN_DELAY_SECONDS > 0", source)

    def test_cli_build_passes_delay_to_make(self):
        source = BUILD_SCRIPT.read_text(encoding="utf-8")

        self.assertIn('INITIAL_CHECKIN_DELAY_SECONDS="${INITIAL_CHECKIN_DELAY_SECONDS:-0}"', source)
        self.assertIn(
            'INITIAL_CHECKIN_DELAY_SECONDS="$INITIAL_CHECKIN_DELAY_SECONDS"',
            source,
        )


if __name__ == "__main__":
    unittest.main()
