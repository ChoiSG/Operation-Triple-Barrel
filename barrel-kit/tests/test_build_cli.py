import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "build.sh"


def _find_bash():
    git_bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
    if git_bash.exists():
        return str(git_bash)
    return "bash"


class BuildCLITests(unittest.TestCase):

    def setUp(self):
        self.source = BUILD_SCRIPT.read_text(encoding="utf-8")

    def test_accepts_url_flag(self):
        self.assertIn('--url) AX_HOST="$2"', self.source)

    def test_accepts_user_flag(self):
        self.assertIn('-u)    AX_USER="$2"', self.source)

    def test_accepts_pass_flag(self):
        self.assertIn('-p)    AX_PASS="$2"', self.source)

    def test_accepts_listener_flag(self):
        self.assertIn('-l)    LISTENER="$2"', self.source)

    def test_accepts_delay_flag(self):
        self.assertIn('-d)    INITIAL_CHECKIN_DELAY_SECONDS="$2"', self.source)

    def test_accepts_share_flag(self):
        self.assertIn('-s)    SHARE="$2"', self.source)

    def test_has_help_flag(self):
        self.assertIn('-h)    usage', self.source)

    def test_env_fallbacks_preserved(self):
        self.assertIn('AX_HOST="${AX_HOST:-https://127.0.0.1:4321}"', self.source)
        self.assertIn('AX_USER="${AX_USER:-operator1}"', self.source)
        self.assertIn('AX_PASS="${AX_PASS:-changeme}"', self.source)
        self.assertIn('SHARE="${SHARE:-/mnt/share}"', self.source)
        self.assertIn('INITIAL_CHECKIN_DELAY_SECONDS="${INITIAL_CHECKIN_DELAY_SECONDS:-0}"', self.source)

    def test_default_listener(self):
        self.assertIn('LISTENER="https-testo"', self.source)

    def test_unknown_option_exits(self):
        self.assertIn('Unknown option', self.source)

    def test_help_shows_usage(self):
        result = subprocess.run(
            [_find_bash(), str(BUILD_SCRIPT), "-h"],
            capture_output=True,
        )
        out = result.stdout.decode("utf-8", errors="replace")
        self.assertIn("--url", out)
        self.assertIn("-u", out)
        self.assertIn("-p", out)
        self.assertIn("-l", out)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
