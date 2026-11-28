# -*- coding: utf-8 -*-
"""The data folder (OPEN_QUESTIONS #3, closed in Sprint 2.5).

Everything the tools keep between runs lives in ONE folder - $SBD_DATA_DIR or
~/.scan_backdoors - and what older versions kept next to the scanner or in the
temp folder is moved there once. These tests check the new defaults and the
move itself: that it happens, that it happens once, that it never merges or
deletes, and that the GUI ends up pointing its settings at the new place.

No test here touches the developer's real data folder: the scanner and the
baseline tool are checked as imported units with SBD_DATA_DIR set to a
throw-away folder, the GUI runs as a subprocess with a private home.
"""

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.SRC)

import scan_backdoors as sb            # noqa: E402  (unit seams: data_root, migration)
import joomla_baseline as jb           # noqa: E402


class TempEnv(object):
    """Run a block with SBD_DATA_DIR (and optionally TMP/TEMP) redirected."""

    def __init__(self, data_dir, **extra):
        self.values = dict(SBD_DATA_DIR=data_dir)
        self.values.update(extra)

    def __enter__(self):
        self.saved = {}
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


class DataRootTest(unittest.TestCase):
    def test_sb_data_dir_wins_for_every_tool(self):
        d = h.workdir("dp-root-")
        with TempEnv(d):
            self.assertEqual(sb.data_root(), os.path.abspath(d))
            self.assertEqual(jb.data_root(), os.path.abspath(d))

    def test_a_relative_and_a_tilde_value_are_resolved(self):
        home = h.workdir("dp-home-")
        with TempEnv(os.path.join(home, ".scan_backdoors")):
            self.assertEqual(sb.data_root(), os.path.join(home, ".scan_backdoors"))
        with TempEnv("~/.scan_backdoors_x"):
            got = sb.data_root()
            self.assertTrue(os.path.isabs(got), got)
            self.assertFalse(got.startswith("~"), got)


class ScannerRuleCacheTest(unittest.TestCase):
    def test_the_default_cache_lives_in_the_data_folder(self):
        d = h.workdir("dp-cache-")
        with TempEnv(d):
            self.assertEqual(sb.default_yarac_dir(), os.path.join(d, "yarac"))

    def test_the_old_temp_cache_is_moved_once_and_never_merged(self):
        root = h.workdir("dp-mig-")
        data = os.path.join(root, "data")
        legacy = os.path.join(root, "temp", "scan-backdoors-yarac")
        os.makedirs(legacy)
        with open(os.path.join(legacy, "abc.yarac"), "wb") as f:
            f.write(b"cached rules")
        saved = sb.LEGACY_YARAC_DIR
        try:
            sb.LEGACY_YARAC_DIR = legacy
            with TempEnv(data):
                self.assertTrue(sb.migrate_yarac_cache(), "the cache must move into the data folder")
                self.assertFalse(os.path.exists(legacy), "the old place must be empty")
                self.assertEqual(os.listdir(sb.default_yarac_dir()), ["abc.yarac"])
                self.assertFalse(sb.migrate_yarac_cache(), "the second run has nothing to move")
        finally:
            sb.LEGACY_YARAC_DIR = saved

    def test_an_existing_destination_wins_and_nothing_is_deleted(self):
        root = h.workdir("dp-keep-")
        data = os.path.join(root, "data")
        legacy = os.path.join(root, "temp", "scan-backdoors-yarac")
        os.makedirs(legacy)
        with open(os.path.join(legacy, "old.yarac"), "wb") as f:
            f.write(b"old")
        os.makedirs(os.path.join(data, "yarac"))
        with open(os.path.join(data, "yarac", "new.yarac"), "wb") as f:
            f.write(b"new")
        saved = sb.LEGACY_YARAC_DIR
        try:
            sb.LEGACY_YARAC_DIR = legacy
            with TempEnv(data):
                self.assertFalse(sb.migrate_yarac_cache(), "an existing cache is never merged into")
                self.assertTrue(os.path.isfile(os.path.join(legacy, "old.yarac")),
                                "the tool must not delete what it did not move")
                self.assertEqual(os.listdir(os.path.join(data, "yarac")), ["new.yarac"])
        finally:
            sb.LEGACY_YARAC_DIR = saved

    @unittest.skipUnless(h.have_yara(), "writing the cache needs the YARA engine")
    def test_a_real_scan_writes_the_cache_into_the_data_folder_only(self):
        root = h.workdir("dp-scan-")
        data, tmp, rules, site = (os.path.join(root, x) for x in ("data", "tmp", "rules", "site"))
        os.makedirs(rules)
        os.makedirs(os.path.join(tmp, "scan-backdoors-yarac"))     # an old cache that must NOT be used
        with open(os.path.join(rules, "a.yar"), "w", encoding="utf-8") as f:
            f.write('rule SbDataPath {\n    strings:\n        $a = "SBD_DATA_PATH_PROBE_551" ascii wide\n'
                    "    condition:\n        $a\n}\n")
        os.makedirs(site)
        with open(os.path.join(site, "page.php"), "w", encoding="utf-8") as f:
            f.write("<?php // SBD_DATA_PATH_PROBE_551\n")
        res = h.run("scan_backdoors.py", [site, "--yara-rules", rules, "--no-csv", "--workers", "1"],
                    env={"SBD_DATA_DIR": data, "TMP": tmp, "TEMP": tmp})
        self.assertEqual(res.returncode, 0, res.out)
        cached = [n for n in os.listdir(os.path.join(data, "yarac")) if n.endswith(".yarac")] \
            if os.path.isdir(os.path.join(data, "yarac")) else []
        self.assertTrue(cached, "the .yarac cache must land under the data folder:\n" + res.out)
        leftovers = os.path.join(tmp, "scan-backdoors-yarac")
        self.assertTrue(not os.path.isdir(leftovers) or os.listdir(leftovers) == [],
                        "the temp folder must not be used for the cache any more")


class BaselineToolTest(unittest.TestCase):
    def test_the_default_cache_is_under_the_data_folder(self):
        d = h.workdir("dp-base-")
        with TempEnv(d):
            self.assertEqual(jb.default_out_dir(), os.path.join(d, "joomla-baselines"))

    def test_no_out_flag_means_the_default_is_used(self):
        args = jb.build_parser().parse_args(["3.9.27"])
        self.assertIsNone(args.out, "--out must stay unset so the data-folder default can apply")

    def test_a_cache_next_to_the_script_is_moved_once(self):
        root = h.workdir("dp-bmig-")
        data = os.path.join(root, "data")
        legacy = os.path.join(root, "tools", "joomla-baselines")
        os.makedirs(os.path.join(legacy, "Joomla_3.9.27"))
        with open(os.path.join(legacy, "Joomla_3.9.27.baseline.json"), "w", encoding="utf-8") as f:
            json.dump({"version": "3.9.27", "files": {}}, f)
        saved = jb.LEGACY_BASELINE_DIR
        try:
            jb.LEGACY_BASELINE_DIR = legacy
            with TempEnv(data):
                target = jb.default_out_dir()
                self.assertTrue(jb.migrate_legacy_baselines(target))
                self.assertFalse(os.path.exists(legacy))
                self.assertTrue(os.path.isfile(os.path.join(target, "Joomla_3.9.27.baseline.json")),
                                "the manifest must travel with the baseline")
                self.assertFalse(jb.migrate_legacy_baselines(target))
        finally:
            jb.LEGACY_BASELINE_DIR = saved

    def test_help_points_at_the_data_folder(self):
        res = h.run("joomla_baseline.py", ["--help"])
        self.assertIn("$SBD_DATA_DIR", res.out, "the default must be described as the data folder")
        self.assertNotIn("current directory", res.out)


class GuiMigrationTest(unittest.TestCase):
    """The GUI moves what older versions left next to the scanner and fixes its own
    settings - while running with a private home, exactly like a user."""

    def _tools(self, home):
        tools = os.path.join(home, "tools")
        os.makedirs(tools)
        with open(os.path.join(tools, "scan_backdoors.py"), "w", encoding="utf-8") as f:
            f.write("# stub scanner - only the folder location matters here\n")
        legacy_wl = os.path.join(tools, "whitelist.txt")
        with open(legacy_wl, "w", encoding="utf-8") as f:
            f.write("aaaa1111  # old entry\n")
        base = os.path.join(tools, "joomla-baselines", "Joomla_3.10.12")
        os.makedirs(base)
        with open(os.path.join(base, "index.php"), "w", encoding="utf-8") as f:
            f.write("<?php // clean stub\n")
        return tools, legacy_wl

    def _config(self, home, tools):
        # only these three matter: everything else the GUI fills in from its defaults
        cfg = {"scanner_path": os.path.join(tools, "scan_backdoors.py"),
               "whitelist_path": os.path.join(tools, "whitelist.txt"),
               "baseline_dir": os.path.join(tools, "joomla-baselines", "Joomla_3.10.12")}
        with open(os.path.join(home, ".scan_backdoors_gui.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)

    def test_legacy_files_move_and_settings_follow(self):
        home = h.workdir("dp-gui-")
        tools, legacy_wl = self._tools(home)
        self._config(home, tools)
        gui = h.Gui(home)
        gui.env["SBD_DATA_DIR"] = os.path.join(home, ".scan_backdoors")
        gui.start()
        try:
            data = os.path.join(home, ".scan_backdoors")
            deadline = time.time() + 30
            while time.time() < deadline and not os.path.isfile(os.path.join(data, "whitelist.txt")):
                time.sleep(0.3)
            self.assertTrue(os.path.isfile(os.path.join(data, "whitelist.txt")),
                            "the whitelist must move into the data folder")
            self.assertFalse(os.path.exists(legacy_wl), "the old place must be empty")
            self.assertTrue(os.path.isdir(os.path.join(data, "joomla-baselines", "Joomla_3.10.12")))
            self.assertFalse(os.path.isdir(os.path.join(tools, "joomla-baselines")))
            settings = gui.settings()
            self.assertEqual(os.path.normpath(settings["whitelist_path"]),
                             os.path.normpath(os.path.join(data, "whitelist.txt")))
            self.assertEqual(os.path.normpath(settings["baseline_dir"]),
                             os.path.normpath(os.path.join(data, "joomla-baselines", "Joomla_3.10.12")))
        finally:
            gui.stop()
        saved = os.path.join(home, ".scan_backdoors_gui.json")
        with open(saved, encoding="utf-8") as f:
            self.assertIn(".scan_backdoors", json.load(f)["whitelist_path"])

    def test_a_second_start_moves_nothing(self):
        home = h.workdir("dp-gui2-")
        tools, _wl = self._tools(home)
        self._config(home, tools)
        for _ in range(2):
            gui = h.Gui(home)
            gui.env["SBD_DATA_DIR"] = os.path.join(home, ".scan_backdoors")
            gui.start()
            try:
                pass
            finally:
                gui.stop()
        data = os.path.join(home, ".scan_backdoors")
        self.assertTrue(os.path.isfile(os.path.join(data, "whitelist.txt")))
        self.assertEqual(os.listdir(os.path.join(data)), sorted(
            ["whitelist.txt", "joomla-baselines"]), "the second run must not duplicate anything")


if __name__ == "__main__":
    unittest.main()
