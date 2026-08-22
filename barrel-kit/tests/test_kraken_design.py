import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KRAKEN_SOURCE = ROOT / "src" / "sleep_kraken_adv.c"
PICO_SOURCE = ROOT / "src" / "pico.c"
LOADER_SOURCE = ROOT / "src" / "loader.c"
PHANTOM_SOURCE = ROOT / "src" / "load_phantom.c"
CLEANUP_SOURCE = ROOT / "src" / "cleanup.c"


class KrakenDesignTests(unittest.TestCase):
    def test_kraken_does_not_create_a_private_worker(self):
        source = KRAKEN_SOURCE.read_text(encoding="utf-8")

        forbidden_patterns = (
            "KERNEL32$CreateThread",
            "KERNEL32$VirtualAlloc",
            "workerCopy",
        )
        for forbidden in forbidden_patterns:
            self.assertNotIn(forbidden, source)

    def test_kraken_runs_inline(self):
        source = KRAKEN_SOURCE.read_text(encoding="utf-8")

        self.assertIn("ok = run_kraken(&params);", source)

    def test_kraken_initializes_from_backup_state(self):
        source = KRAKEN_SOURCE.read_text(encoding="utf-8")

        self.assertNotIn("static BOOL initialized", source)
        self.assertIn("if (adv->pBackup == NULL)", source)
        self.assertIn("adv->szBackup != adv->szStomp", source)

    def test_pico_and_agent_use_distinct_images(self):
        loader = LOADER_SOURCE.read_text(encoding="utf-8")
        phantom = PHANTOM_SOURCE.read_text(encoding="utf-8")
        cleanup = CLEANUP_SOURCE.read_text(encoding="utf-8")

        pico_call = loader.index("if (!stomp_alloc_pico(")
        agent_call = loader.index("char * dll_dst = (char *) stomp_alloc_dll(")
        self.assertLess(pico_call, agent_call)
        self.assertIn("layout->Pico.Module   = (PVOID) hModule;", phantom)
        self.assertIn("memory->Pico.Module", cleanup)

    def test_pico_data_destination_is_zeroed(self):
        source = PHANTOM_SOURCE.read_text(encoding="utf-8")

        self.assertIn(
            "for (z = 0; z < pico_data_al; z++) pico_data_dst[z] = 0;",
            source,
        )

    def test_short_wait_floor_and_kraken_threshold(self):
        kraken = KRAKEN_SOURCE.read_text(encoding="utf-8")
        pico = PICO_SOURCE.read_text(encoding="utf-8")

        self.assertIn("milliseconds >= 1500", kraken)
        self.assertNotIn("milliseconds >= 1000", kraken)
        self.assertIn("milliseconds < 1500 && milliseconds < 30", kraken)
        self.assertIn("milliseconds < 1500 && milliseconds < 30", pico)


if __name__ == "__main__":
    unittest.main()
