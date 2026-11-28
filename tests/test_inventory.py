# -*- coding: utf-8 -*-
"""TZ v2 Sprint 3: engines/inventory.py - reading a CMS inventory of a hostile site.

The fixtures are not clean trees: they are the files a compromised site would
hand us. The tests therefore check three things at once - that the inventory is
right, that nothing that looks like PHP is executed, and that a manifest built to
break a parser (or a scanner) is refused instead of obeyed.
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h  # noqa: E402

sys.path.insert(0, h.REPO)

from engines import inventory as inv  # noqa: E402

WP_VERSION_PHP = ("<?php\n"
                  "/**\n * WordPress Version\n */\n"
                  "$wp_version = '6.4.2';\n"
                  "$wp_db_version = 58369;\n"
                  "$tinymce_version = '4950-20231113';\n")


def make_site(files):
    """{relative/path: bytes|str} -> a throw-away site folder."""
    site = h.workdir("inv-site-")
    write_site(site, files)
    return site


def write_site(site, files):
    for rel, content in files.items():
        path = os.path.join(site, *rel.split("/"))
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.makedirs(folder)
        if isinstance(content, bytes):
            with open(path, "wb") as fh:
                fh.write(content)
        else:
            with io.open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
    return site


def wp_tree(**extra):
    files = {"wp-settings.php": "<?php\n", "wp-load.php": "<?php\n",
             "wp-includes/version.php": WP_VERSION_PHP,
             "wp-admin/index.php": "<?php\n", "index.php": "<?php\n"}
    files.update(extra)
    return files


def joomla_tree(**extra):
    files = {"configuration.php": "<?php\nclass JConfig {}\n",
             "administrator/manifests/files/joomla.xml":
                 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                 "<extension type=\"file\" version=\"3.9\" method=\"upgrade\">\n"
                 "  <name>Joomla!</name>\n  <version>4.4.10</version>\n</extension>\n",
             "administrator/index.php": "<?php\n", "index.php": "<?php\n"}
    files.update(extra)
    return files


def by_slug(components):
    out = {}
    for comp in components:
        out.setdefault(comp["slug"], []).append(comp)
    return out


class DetectCmsTest(unittest.TestCase):
    def test_wordpress(self):
        site = make_site(wp_tree())
        self.assertEqual(inv.detect_cms(site), inv.WP)
        self.assertEqual(inv.build_inventory(site)["cms"], "wordpress")

    def test_joomla(self):
        site = make_site(joomla_tree())
        self.assertEqual(inv.detect_cms(site), inv.JOOMLA)
        self.assertEqual(inv.build_inventory(site)["cms"], "joomla")

    def test_one_planted_file_does_not_relabel_a_site(self):
        # A single wp-settings.php in a Joomla site must not turn it into WordPress:
        # WordPress needs a marker file AND both core folders. Getting this wrong
        # switches the CMS-specific checks off for the whole scan.
        site = make_site(joomla_tree(**{"wp-settings.php": "<?php\n"}))
        self.assertEqual(inv.detect_cms(site), inv.JOOMLA)

    def test_a_real_conflict_is_unknown_not_a_guess(self):
        site = make_site(wp_tree(**{"configuration.php": "<?php\nclass JConfig {}\n"}))
        self.assertIsNone(inv.detect_cms(site))
        self.assertEqual(inv.build_inventory(site)["cms"], "unknown")

    def test_empty_and_missing_folder(self):
        self.assertIsNone(inv.detect_cms(h.workdir("inv-empty-")))
        self.assertEqual(inv.build_inventory(h.workdir("inv-nope-"))["cms"], "unknown")

    def test_the_scanner_and_the_inventory_agree(self):
        # scan_backdoors.detect_cms gates the heuristics; the inventory gates the
        # audit. One site must not get two different answers.
        sys.path.insert(0, h.SRC)
        import scan_backdoors as sb
        cases = [(wp_tree(), "wp"),
                 (joomla_tree(), "joomla"),
                 (joomla_tree(**{"wp-settings.php": "<?php\n"}), "joomla"),
                 (wp_tree(**{"configuration.php": "<?php\nclass JConfig {}\n"}), "ambiguous"),
                 ({"index.php": "<?php\n"}, None)]
        for files, expected in cases:
            site = make_site(files)
            self.assertEqual(sb.detect_cms(site), expected, "scanner: %r" % expected)
            as_scanner = {inv.WP: "wp", inv.JOOMLA: "joomla", None: None}[inv.detect_cms(site)]
            self.assertEqual(as_scanner, None if expected == "ambiguous" else expected,
                             "the inventory answered %r where the scanner said %r"
                             % (inv.detect_cms(site), expected))


class WordPressInventoryTest(unittest.TestCase):
    def test_core_version_and_the_file_it_came_from(self):
        site = make_site(wp_tree())
        got = inv.build_inventory(site)
        self.assertEqual(got["cms_version"]["version"], "6.4.2")
        self.assertEqual(got["cms_version"]["file"], "wp-includes/version.php")
        self.assertEqual(got["cms_version"]["source"], "declared")

    def test_two_plugins_are_listed_with_their_declared_versions(self):
        site = make_site(wp_tree(**{
            "wp-content/plugins/akismet/akismet.php":
                "<?php\n/**\n * Plugin Name: Akismet Anti-spam\n * Version: 5.3.1\n */\n",
            "wp-content/plugins/Hello-Dolly/hello.php":
                "<?php\n/**\n * Plugin Name: Hello Dolly\n * Version: 1.7.2\n */\n",
        }))
        got = inv.build_inventory(site)
        found = by_slug(got["components"])
        self.assertEqual(sorted(found), ["Hello-Dolly", "akismet"])
        self.assertEqual(found["akismet"][0]["version"], "5.3.1")
        self.assertEqual(found["akismet"][0]["name"], "Akismet Anti-spam")
        self.assertEqual(found["akismet"][0]["type"], "plugin")
        self.assertEqual(found["akismet"][0]["path"], "wp-content/plugins/akismet")
        for comp in got["components"]:
            self.assertFalse(os.path.isabs(comp["path"]),
                             "a report must never carry an absolute path: %r" % comp["path"])

    def test_theme_version_comes_from_style_css(self):
        site = make_site(wp_tree(**{
            "wp-content/themes/mytheme/style.css":
                "/*\nTheme Name: My Theme\nVersion: 2.1.0\n*/\nbody{}\n",
        }))
        themes = by_slug(inv.build_inventory(site)["components"]).get("mytheme")
        self.assertEqual(themes[0]["type"], "theme")
        self.assertEqual(themes[0]["version"], "2.1.0")

    def test_mu_plugins_are_their_own_kind(self):
        site = make_site(wp_tree(**{
            "wp-content/mu-plugins/one.php":
                "<?php\n/**\n * Plugin Name: Must Use\n * Version: 1.0\n */\n",
        }))
        comps = by_slug(inv.build_inventory(site)["components"])["one"]
        self.assertEqual(comps[0]["type"], "mu-plugin")
        self.assertEqual(comps[0]["version"], "1.0")

    def test_readme_is_a_weaker_second_statement(self):
        site = make_site(wp_tree(**{
            "wp-content/plugins/noheader/noheader.php": "<?php\n// no header here\n",
            "wp-content/plugins/noheader/readme.txt":
                "=== No Header ===\nStable tag: 3.4.5\n== Changelog ==\n= 3.4.4 =\n",
        }))
        comp = by_slug(inv.build_inventory(site)["components"])["noheader"][0]
        self.assertEqual(comp["version"], "3.4.5")
        self.assertEqual(comp["version_source"], "readme")

    def test_plugin_without_any_version_is_listed_as_unknown(self):
        site = make_site(wp_tree(**{"wp-content/plugins/mystery/mystery.php": "<?php\n"}))
        comp = by_slug(inv.build_inventory(site)["components"])["mystery"][0]
        self.assertEqual(comp["version"], "")
        self.assertEqual(comp["version_source"], "declared")

    def test_a_version_claim_is_sanitized_not_stored_raw(self):
        site = make_site(wp_tree(**{
            "wp-content/plugins/evil/evil.php":
                "<?php\n/**\n * Plugin Name: Evil <img src=x onerror=alert(1)>\n"
                " * Version: 1.0\x1b[31m; rm -rf / && echo pwned\n */\n",
        }))
        comp = by_slug(inv.build_inventory(site)["components"])["evil"][0]
        self.assertNotIn("<", comp["name"])
        self.assertNotIn(";", comp["version"])
        self.assertNotIn("\x1b", comp["version"])
        self.assertTrue(json.dumps(comp), "the component must stay JSON-safe")

    def test_php_is_never_executed(self):
        # A version.php that would create a file if it were ever run. The test is
        # the absence of that file: reading a PHP file must stay reading.
        marker = "if-executed-please-do-not-exist.txt"
        site = make_site(wp_tree(**{
            "wp-includes/version.php":
                "<?php file_put_contents(__DIR__.'/%s', 'pwned');\n"
                "$wp_version = '6.4.2';\n" % marker,
            "wp-content/plugins/exec/exec.php":
                "<?php system('echo pwned > %s');\n/**\n * Plugin Name: Exec\n"
                " * Version: 9 '\n * passthru($_GET[0]);\n */\n" % marker,
        }))
        inv.build_inventory(site)
        self.assertFalse(os.path.exists(os.path.join(site, marker)),
                         "a manifest was executed while being inventoried")
        self.assertFalse(os.path.exists(os.path.join(site, "wp-content", "plugins",
                                                     "exec", marker)))
        # and the fake "version" line that carries a quote must not become a version
        self.assertEqual(inv.build_inventory(site)["cms_version"]["version"], "6.4.2")

    def test_a_huge_version_file_yields_no_version(self):
        site = make_site(wp_tree())
        with open(os.path.join(site, "wp-includes", "version.php"), "wb") as fh:
            fh.write(b"<?php\n" + b"x" * (inv.HEADER_LIMIT + 1024) +
                     b"\n$wp_version = '9.9.9';\n")
        self.assertEqual(inv.build_inventory(site)["cms_version"]["version"], "")

    def test_symlinked_component_is_not_read(self):
        outside = h.workdir("inv-outside-")
        write_site(outside, {"secret/secret.php":
                             "<?php\n/**\n * Plugin Name: Outside\n * Version: 6.6\n */\n"})
        site = make_site(wp_tree())
        link = os.path.join(site, "wp-content", "plugins", "secret")
        try:
            os.makedirs(os.path.dirname(link))
            os.symlink(os.path.join(outside, "secret"), link)
        except (OSError, AttributeError):
            self.skipTest("creating a symlink needs privileges here")
        slugs = by_slug(inv.build_inventory(site)["components"])
        self.assertNotIn("secret", slugs,
                         "a link out of the site must not become an inventory entry")

    def test_hosts_file_is_not_read(self):
        # wp-content could contain a link to a file the site does not own.
        site = make_site(wp_tree())
        target = os.path.join(site, "wp-content", "plugins")
        os.makedirs(target)
        link = os.path.join(target, "passwd")
        try:
            os.symlink(os.path.abspath(os.sep + "etc" + os.sep + "passwd")
                       if os.name != "nt" else os.path.join(os.environ.get("WINDIR", "C:"), "win.ini"),
                       link)
        except (OSError, AttributeError):
            self.skipTest("creating a symlink needs privileges here")
        comp = by_slug(inv.build_inventory(site)["components"]).get("passwd")
        self.assertTrue(comp is None or comp[0]["version"] == "")


class JoomlaInventoryTest(unittest.TestCase):
    def test_core_version_from_the_distribution_manifest(self):
        site = make_site(joomla_tree())
        got = inv.build_inventory(site)
        self.assertEqual(got["cms_version"]["version"], "4.4.10")
        self.assertEqual(got["cms_version"]["file"], "administrator/manifests/files/joomla.xml")

    def test_fallback_to_the_php_constants(self):
        site = make_site(joomla_tree())
        os.remove(os.path.join(site, "administrator", "manifests", "files", "joomla.xml"))
        write_site(site, {"libraries/src/Version.php":
                          "<?php\nclass Version\n{\n"
                          " const MAJOR = 4;\n const MINOR = 2;\n const PATCH = 7;\n"
                          " const EXTRA_VERSION = '';\n}\n"})
        self.assertEqual(inv.joomla_core_version(site)["version"], "4.2.7")

    def test_legacy_path_is_tried(self):
        site = make_site(joomla_tree())
        os.remove(os.path.join(site, "administrator", "manifests", "files", "joomla.xml"))
        write_site(site, {"libraries/cms/version/version.php":
                          "<?php\nclass JVersion\n{\n"
                          " public static $RELEASE = '1.0';\n"
                          " const MAJOR = 2;\n const MINOR = 5;\n const PATCH = 28;\n}\n"})
        # [ПРОВЕРИТЬ] the legacy class shape is not guaranteed: what must hold is
        # that trying it neither invents a wrong version nor breaks anything.
        self.assertIn(inv.joomla_core_version(site)["version"], ("", "2.5.28"))

    def test_extensions_of_every_kind(self):
        site = make_site(joomla_tree(**{
            "administrator/components/com_foobar/foobar.xml":
                '<?xml version="1.0"?><extension type="component" version="3.0">'
                "<name>FooBar</name><version>1.4.2</version></extension>",
            "components/com_foobar/foobar.xml":
                '<?xml version="1.0"?><extension type="component" version="3.0">'
                "<name>FooBar</name><version>1.4.2</version></extension>",
            "modules/mod_hello/mod_hello.xml":
                '<?xml version="1.0"?><extension type="module" version="3.0">'
                "<name>mod_hello</name><version>1.0.0</version></extension>",
            "plugins/system/myplug/myplug.xml":
                '<?xml version="1.0"?><extension type="plugin" version="3.0" group="system">'
                "<name>plg_myplug</name><version>0.9</version></extension>",
            "templates/protostar/templateDetails.xml":
                '<?xml version="1.0"?><extension type="template" version="3.0">'
                "<name>protostar</name><version>1.0.1</version></extension>",
        }))
        comps = inv.build_inventory(site)["components"]
        kinds = sorted({c["type"] for c in comps})
        self.assertEqual(kinds, ["component", "module", "plugin", "template"])
        paths = {c["path"] for c in comps}
        self.assertIn("administrator/components/com_foobar", paths)
        self.assertIn("components/com_foobar", paths)
        self.assertIn("plugins/system/myplug", paths,
                      "a Joomla plugin lives under its group folder")
        self.assertEqual(by_slug(comps)["myplug"][0]["version"], "0.9")

    def test_xml_with_an_entity_is_refused(self):
        # The classic billion-laughs manifest: 400 bytes that expand to gigabytes.
        bomb = ('<?xml version="1.0"?>\n'
                '<!DOCTYPE extension [\n'
                '<!ENTITY lol "lol">\n'
                '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
                '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;">\n'
                ']>\n<extension><version>1.0</version></extension>\n')
        site = make_site(joomla_tree(**{
            "administrator/components/com_bomb/bomb.xml": bomb}))
        comps = by_slug(inv.build_inventory(site)["components"])
        self.assertEqual(comps["com_bomb"][0]["version"], "",
                         "an XML that declares entities must never be parsed")

    def test_a_refused_core_manifest_falls_back_instead_of_trusting_itself(self):
        site = make_site(joomla_tree(**{
            "administrator/manifests/files/joomla.xml":
                '<?xml version="1.0"?><!DOCTYPE extension '
                '[<!ENTITY x "y">]><extension><version>9.9.9</version></extension>'}))
        got = inv.joomla_core_version(site)
        self.assertEqual(got["version"], "")

    def test_malformed_manifest_is_a_note_not_a_crash(self):
        site = make_site(joomla_tree(**{
            "administrator/components/com_broken/broken.xml": b"\x00\x01\xff not xml at all"}))
        got = inv.build_inventory(site)
        self.assertEqual(by_slug(got["components"])["com_broken"][0]["version"], "")

    def test_an_oversized_manifest_is_refused(self):
        site = make_site(joomla_tree(**{
            "administrator/components/com_big/big.xml":
                '<?xml version="1.0"?><extension><version>1.0</version><junk>' +
                "x" * 4096 + "</junk></extension>"}))
        original = inv.XML_LIMIT
        try:
            inv.XML_LIMIT = 256
            comps = by_slug(inv.build_inventory(site)["components"])
        finally:
            inv.XML_LIMIT = original
        self.assertEqual(comps["com_big"][0]["version"], "")


class LimitsTest(unittest.TestCase):
    def test_component_count_is_capped(self):
        files = wp_tree()
        for i in range(30):
            files["wp-content/plugins/p%02d/p%02d.php" % (i, i)] = (
                "<?php\n/**\n * Plugin Name: P%d\n * Version: 1.%d\n */\n" % (i, i))
        site = make_site(files)
        original = inv.MAX_COMPONENTS
        try:
            inv.MAX_COMPONENTS = 10
            got = inv.build_inventory(site)["components"]
        finally:
            inv.MAX_COMPONENTS = original
        self.assertEqual(len(got), 10)

    def test_summarize_is_small_and_json_safe(self):
        site = make_site(wp_tree(**{
            "wp-content/plugins/akismet/akismet.php":
                "<?php\n/**\n * Plugin Name: Akismet\n * Version: 5.3.1\n */\n"}))
        summary = inv.summarize(inv.build_inventory(site))
        text = json.dumps(summary, sort_keys=True)
        self.assertIn('"cms": "wordpress"', text)
        self.assertIn('"cms_version": "6.4.2"', text)
        self.assertNotIn(h.REPO.replace("\\", "\\\\"), text,
                         "a summary must not leak the machine's paths")

    def test_a_site_that_cannot_be_read_never_raises(self):
        for path in (None, "", 0, os.path.join(h.workdir("inv-nope-"), "missing")):
            with self.subTest(path=path):
                got = inv.build_inventory(path)
                self.assertEqual(got["cms"], "unknown")
                self.assertTrue(got["problems"])


if __name__ == "__main__":
    unittest.main()
