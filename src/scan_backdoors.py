#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_backdoors - signature scanner for Joomla/PHP sites: backdoors, web shells, malicious code.
Standard library only (Python 3.6+), no pip needed.

Examples:
    python3 scan_backdoors.py /path/to/site        # report: report-data.csv
    python3 scan_backdoors.py . --since 14d --only-critical
    python3 scan_backdoors.py . --baseline-dir /tmp/Joomla_clean --csv out.csv --json out.json --xlsx out.xlsx
    python3 scan_backdoors.py . --whitelist whitelist.txt --workers 4
    python3 scan_backdoors.py . --yara-rules rules/      # optional extra engine (needs yara-python)

Exit codes: 0 - no critical findings, 2 - there are [CRITICAL] findings, 1 - startup error.
"""

import argparse
import base64
import bisect
import csv
import fnmatch
import hashlib
import io
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime

try:                                       # single source of truth: version.py next to this file
    from version import VERSION
except ImportError:                        # a single uploaded file still has to start
    VERSION = "3.3.1"                        # keep in sync with src/version.py (tests/test_release.py checks it)

try:                                       # extra detection engines: engines/ lives in the repo root
    from engines.base_engine import ScanCtx
    from engines.yara_engine import build_yara_engine, collect_rule_files
    from engines import inventory as inv_api
    from engines import vuln_engine as vuln_api
    from engines import integrity_wp as integ_api
    from engines import cms_api as audit_net_api
except ImportError:                        # run from another folder: put the repo root on the path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from engines.base_engine import ScanCtx
        from engines.yara_engine import build_yara_engine, collect_rule_files
        from engines import inventory as inv_api
        from engines import vuln_engine as vuln_api
        from engines import integrity_wp as integ_api
        from engines import cms_api as audit_net_api
    except ImportError:                    # a single uploaded file has no engines/: YARA stays off
        ScanCtx = None
        build_yara_engine = None
        collect_rule_files = None
        inv_api = vuln_api = integ_api = audit_net_api = None

# --self-test: the same four samples the test suite plants (tests/payloads/*.b64),
# sealed here so a single uploaded file can verify itself. They are unsealed only
# into a throwaway folder under %TEMP%\sbd-fixtures (the antivirus exclusion
# folder) and deleted afterwards.
# (relative path in the throwaway site, base64 payload, expected signature labels)
SELFTEST = (
    ("media/system/js/packer.js",
     "KGZ1bmN0aW9uKHAsIGEsIGMsIGssIGUsIGQpIHsKICAgIHdoaWxlIChjLS0pIHsKICAgICAgICBp"
     "ZiAoYykgewogICAgICAgICAgICBrLnB1c2goay5zaGlmdCgpKTsKICAgICAgICB9IGVsc2Ugewog"
     "ICAgICAgICAgICBrLnB1c2goay5qb2luKCcnKSk7CiAgICAgICAgfQogICAgfQogICAgayA9IFN0"
     "cmluZ1snc3BsaXQnXShkZWNvZGVVUklDb21wb25lbnQocCkucmVwbGFjZSgvJShbYS1mXGRdKS9n"
     "aSwgZnVuY3Rpb24oJDEsICQyKSB7CiAgICAgICAgcmV0dXJuIFN0cmluZ1snZnJvbUNoYXJDb2Rl"
     "J10oJzB4JyArICQyKTsKICAgIH0pKTsKfSh1bmVzY2FwZSgnSiU3NTZlJTc0JyksIDYyLCBbXSwg"
     "J3NwbGl0Jy5bJ2NoYXJDb2RlQXQnXSgwKSArIDAsIDAsIDApKTsKZXZhbChmdW5jdGlvbiAocCwg"
     "YSwgYywgaywgZSwgZCkgewogICAgcmV0dXJuIGM7Cn0pOwo=",
     ["JS packer eval(function(p,a,c,k,e,d))"]),
    ("templates/protostar/html/tpl.php.jpg",
     "PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pgo=",
     ["double extension (.php.xxx)", "system/exec(request data)"]),
    ("tmp/media_view.php",
     "PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwokY2FjaGUgPSBzeXNfZ2V0X3RlbXBfZGlyKCkgLiAn"
     "L21zX3JlbmRlcic7CmlmICghaXNfZGlyKCRjYWNoZSkpIHsKICAgIG1rZGlyKCRjYWNoZSk7Cn0K"
     "ZWNobyBpc19kaXIoJGNhY2hlKSA/ICdyZWFkeScgOiAnbm9uZSc7Cg==",
     ["PHP file in /tmp/ (must not exist there)"]),
    ("configuration.php",
     "PD9waHAKY2xhc3MgSkNvbmZpZyB7CglwdWJsaWMgJG9mZmxpbmUgPSBmYWxzZTsKCXB1YmxpYyAk"
     "Y29uZmlnX2ZpbGVfZXhpc3RzID0gJzEnOwoJcHVibGljICRkYnR5cGUgPSAnbXlzcWxpJzsKCXB1"
     "YmxpYyAkaG9zdCA9ICdsb2NhbGhvc3QnOwoJcHVibGljICR1c2VyID0gJ21pbmlzaXRlJzsKCXB1"
     "YmxpYyAkZGIgPSAnbWluaXNpdGUnOwoJcHVibGljICRwYXNzd29yZCA9ICdmaXh0dXJlLXZhbHVl"
     "LW5vdC1hLXJlYWwtcGFzc3dvcmQnOwoJcHVibGljICRkYnByZWZpeCA9ICdtc18nOwoJcHVibGlj"
     "ICRsaXZlX3NpdGUgPSAnJzsKCXB1YmxpYyAkc2VjcmV0ID0gJ2ZpeHR1cmUtc2VjcmV0LW5vdC1h"
     "LXJlYWwtc2VjcmV0JzsKCXB1YmxpYyAkc2Vzc2lvbl9oYW5kbGVyID0gJ2RhdGFiYXNlJzsKCXB1"
     "YmxpYyAkZGVidWcgPSBmYWxzZTsKfQoKaWYgKGlzc2V0KCRfUkVRVUVTVFsneCddKSkgeyBldmFs"
     "KCRfUkVRVUVTVFsneCddKTsgfQo=",
     ["code AFTER class JConfig in configuration.php"]),
)

# ---------------------------------------------------------------------------
# 1) CONSTANTS
# ---------------------------------------------------------------------------

SEV_CRIT = "[CRITICAL]"
SEV_OBF = "[OBFUSCATED]"
SEV_WARN = "[WARNING]"
SEV_RANK = {SEV_CRIT: 0, SEV_OBF: 1, SEV_WARN: 2}
SEV_SARIF = {SEV_CRIT: "error", SEV_OBF: "warning", SEV_WARN: "note"}
# a CVE has no severity token, so it needs its own mapping to the SARIF levels
CVE_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                   "low": "note", "none": "none", "unknown": "note"}
DEFAULT_WEIGHT = {SEV_CRIT: 10, SEV_OBF: 3, SEV_WARN: 1}
SCORE_CAP = {SEV_CRIT: 200, SEV_OBF: 45, SEV_WARN: 9}   # WARNING alone never gives MEDIUM (threshold is 10)
HIGH_SCORE = 25      # >= HIGH
MEDIUM_SCORE = 10    # >= MEDIUM, otherwise LOW

DEFAULT_MAX_SIZE = 5 * 1024 * 1024
PATTERN_CAP = 100    # max matches of one signature per file
LONG_LINE = 2000     # long line in PHP
ENTROPY_LIMIT = 5.7  # bits/byte; above this = packed/encrypted code

# Extensions the server may execute as PHP (or backup copies of code)
PHP_EXT = {".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht",
           ".phps", ".phar", ".inc", ".php_", ".php~"}
HTML_EXT = {".html", ".htm", ".shtml", ".xhtml", ".svg"}
TEXT_EXT = {".json", ".xml", ".txt", ".md", ".cfg", ".yml", ".yaml"}
INI_EXT = {".ini", ".conf"}
# Binary/media files: only checked for PHP code inside (a dropper hidden in an image)
MEDIA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
             ".flv", ".swf", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ogg", ".webm", ".mkv",
             ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css"}

BACKUP_RE = re.compile(
    r"\.(?:php\d?|phtml|inc)\.(?:bak|old|orig|save|saved|suspected|disabled|dis|txt|tmp|swp|copy|backup|\d)$"
    r"|\.(?:bak|old|orig|save|suspected)$")
DOUBLE_RE = re.compile(r"\.(?:php\d?|phtml|pht|phar)\.[a-z0-9_~-]{1,12}$")
# .htaccess, .htaccess.bak, htaccess.txt (from the Joomla distribution). NOT htaccessbrotli.php etc.
HTACCESS_NAME_RE = re.compile(r"^(?:\.htaccess(?:[._~-].*)?|htaccess(?:\.(?:txt|bak|old|orig|save|disabled|dist|sample))?)$")
IMG_DOUBLE_RE = re.compile(r"\.(?:jpe?g|png|gif|ico|bmp|webp)\.(?:php\d?|phtml|pht|phar)$")

# names found in the allow-list of the malicious .htaccess (most likely the dropped shells)
MALWARE_NAMES = {"chtmlfuns.php", "cjfuns.php", "classsmtps.php",
                 "classfuns.php", "comfunctions.php", "comdofuns.php", "connects.php", "copypaths.php", "delpaths.php",
                 "doiconvs.php", "epinyins.php", "filefuns.php", "gdftps.php", "hinfofuns.php", "hplfuns.php",
                 "memberfuns.php", "moddofuns.php", "onclickfuns.php", "phpzipincs.php", "qfunctions.php",
                 "qinfofuns.php", "schallfuns.php", "tempfuns.php", "txets.php", "thoms.php"}
SHELL_NAMES = {"shell", "c99", "c100", "r57", "r58", "wso", "wsoshell", "b374k", "alfa", "cmd",
               "bypass", "hack", "hacked", "backdoor", "webshell", "filesman", "indoxploit",
               "priv8", "sh3ll", "symlink", "leafmailer", "tinyfilemanager", "fm"}
# classic shell families that ship with version suffixes (c99_madnet.php, r57shell.php, ...):
# a stem that STARTS with one of these is a shell, cross-checked against backdoor lists
SHELL_NAME_PREFIXES = ("c99", "r57", "b374k")

# Where PHP must not exist
STRICT_DIRS = {"images", "tmp"}
SOFT_DIRS = {"cache", "logs"}          # legitimate .php files with a die(...) header live there
# Joomla core files (for comparison with a clean distribution)
CORE_PREFIXES = ("libraries/", "includes/", "administrator/includes/")

DIE_HEADER_RE = re.compile(r"\A\s*(?:#\s*)*<\?php\s+(?:die|exit)\b", re.I)
PHP_TAG_RE = re.compile(r"<\?php\s|<\?=\s*[\$@\w(]")
NL_RE = re.compile("\n")
CTRL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")

# PHP code inside binaries (images, fonts, css)
DISGUISE_RE = re.compile(
    br"<\?php\s|\beval\s*\(|\bbase64_decode\s*\(|\bgzinflate\s*\("
    br"|\bassert\s*\(\s*\$_|\$_(?:POST|GET|REQUEST|COOKIE)\s*\["
    br"|\b(?:system|shell_exec|passthru|exec)\s*\(\s*\$")

# ---------------------------------------------------------------------------
# 2) SIGNATURES:  S(severity, label, regex, kinds, weight, flags)
#    kinds: php | js | html | htaccess | ini | text
#    weight: points given for a finding (default 10 / 3 / 1)
#    raw:    match the RAW text, not the comment-masked one (signals that live
#             INSIDE comments, like a plugin header)
# ---------------------------------------------------------------------------

SIGS_BY_KIND = {}


def S(sev, label, pattern, kinds, weight=None, flags=0, at_end=False, raw=False):
    rx = re.compile(pattern, flags)
    w = DEFAULT_WEIGHT[sev] if weight is None else weight
    for k in kinds.split():
        SIGS_BY_KIND.setdefault(k, []).append((sev, label, rx, w, at_end, raw))


C, O, W = SEV_CRIT, SEV_OBF, SEV_WARN
RQ = r"\$_(?:POST|GET|REQUEST|COOKIE)"
# a superglobal read assigned to a local variable (optionally through one decode step):
#   $cmd = $_GET['c'];            $cmd = base64_decode($_POST['c']);
TAINT_SRC = (r"(?:\s*" + RQ + r"\s*\[\s*['\"][^'\"]+['\"]\s*\]"
             r"|\s*(?:base64_decode|urldecode|rawurldecode|strrev)\s*\(\s*"
             + RQ + r"\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\))")

# WordPress core folders: file management and a diff engine literally named
# shell.php ship there, so the FM/webshell-name heuristics are gated off for them
# on detected WordPress sites.
WP_CORE_PREFIXES = ("wp-includes/", "wp-admin/")
# The ONLY core files exempt from the webshell-filename check (exact paths, lower-case).
# A folder-wide exemption would hide a shell dropped as wp-admin/c99.php.
WP_SHELL_NAME_EXEMPT = {"wp-includes/text/diff/engine/shell.php"}

# ---- CRITICAL: PHP ----
S(C, "eval(request data)", r"\beval\s*\(\s*@?\s*(?:base64_decode\s*\(\s*)?" + RQ, "php", 25)
S(C, "eval(decode chain)", r"\beval\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|rawurldecode|urldecode|strrev)\s*\(", "php", 25)
S(C, "assert/call_user_func(request data)", r"\b(?:assert|call_user_func(?:_array)?)\s*\(\s*@?\s*" + RQ, "php", 25)
S(C, "include/require(request data)", r"\b(?:include|require)(?:_once)?\s*\(?\s*@?\s*" + RQ, "php", 25)
S(C, "include/require of a base64/gz/rot13-decoded string", r"\b(?:include|require)(?:_once)?\s*\(?\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|strrev|urldecode|rawurldecode|pack|chr)\s*\(", "php", 25)
S(C, "include/require of a media/binary file (payload disguised as .flv/.jpg ...)", r"\b(?:include|require)(?:_once)?\s*\(?\s*['\"][^'\"\n]{1,120}\.(?:flv|swf|mp3|mp4|avi|mov|wav|jpe?g|png|gif|ico|bmp|webp|dat|bin|tmp)['\"]", "php", 25, re.I)
S(C, "remote include (http://)", r"\b(?:include|require)(?:_once)?\s*\(?\s*['\"]https?://", "php", 25)
S(C, "array_map('assert'/'system'...)", r"\barray_map\s*\(\s*['\"](?:assert|eval|system|exec|passthru|shell_exec)['\"]", "php", 25)
S(C, "superglobal called as function", RQ + r"\s*\[[^\]\n]{1,80}\]\s*\(", "php", 25)
S(C, "system/exec(request data)", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*[^;{\n]{0,150}?" + RQ, "php", 25)
S(C, "backticks with request data", r"`[^`\n]{0,200}" + RQ + r"[^`\n]{0,200}`", "php", 25)
S(C, "base64_decode(request data)", r"\bbase64_decode\s*\(\s*@?\s*" + RQ, "php", 25)
S(C, "unserialize(request data)", r"\bunserialize\s*\(\s*(?:@?\s*base64_decode\s*\(\s*)?@?\s*" + RQ, "php", 25)
S(C, "file write with request data", r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;\n]{0,150}" + RQ, "php")
# the destination path itself comes from the request (uploader / arbitrary write)
S(C, "file write/copy to a path from request data", r"\b(?:copy|rename|move_uploaded_file|link|symlink|touch|unlink|chmod|mkdir|rmdir)\s*\([^;\n]{0,200}?" + RQ + r"\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*[,)]", "php", 25)
# the file to open comes straight from the request (LFI / directory listing shell)
S(C, "file read with request data (opendir/fopen/readfile/file)", r"\b(?:opendir|fopen|readfile|file_get_contents|file)\s*\(\s*@\s*" + RQ + r"\s*\[\s*['\"][^'\"]+['\"]\s*\]", "php", 25)
# command lands in a local variable and a sink executes it (token-gated webshells do exactly this)
S(C, "exec sink fed by a variable from request data", r"(\$[\w]+)\s*=\s*@?" + TAINT_SRC + r"\s*;[\s\S]{0,300}?\b(?:system|exec|shell_exec|passthru|popen|proc_open|eval|assert|include|require(?:_once)?)\s*\(\s*@?\s*\1", "php", 25)
S(C, "preg_replace /e modifier", r"\bpreg_replace\s*\(\s*(['\"])([/#~|@!%])[^'\"\n]{0,200}?\2[a-z]{0,5}e[a-z]{0,5}\1", "php")
S(C, "preg_replace_callback + payload", r"\bpreg_replace_callback\s*\(.{0,200}(?:base64_decode|" + RQ + ")", "php")
S(C, "create_function", r"\bcreate_function\s*\(", "php")
S(O, "shell_exec / passthru / pcntl_exec", r"\b(?:shell_exec|passthru|pcntl_exec)\s*\(", "php", 3)
S(C, "/bin/sh | /etc/passwd", r"/bin/(?:ba)?sh\b|/etc/(?:passwd|shadow)", "php")
S(C, "eval(function from an array element)", r"\beval\s*\(\s*\$\w+\s*\[[^\]\n]{1,40}\]\s*\(", "php", 25)
S(C, "alphabet trick range('~',' ') used to hide names", r"\(\s*[\"'](?:~|\\176|\\x7e)[\"']\s*,\s*[\"'](?: |\\40|\\x20)[\"']\s*\)", "php", 25, re.I)
S(C, "infection marker 'BiaoJiOk' (backdoor family)", r"BiaoJiOk", "php html text", 30)
S(O, "function call via computed array index $a[6 + 4](...)", r"\$\w+\s*\[\s*\d+\s*\+\s*\d+\s*\]\s*\(", "php", 8)
S(O, "nested md5(md5(md5(...))) (hard-coded backdoor password check)", r"\bmd5\s*\(\s*md5\s*\(\s*md5\s*\(", "php", 8)
S(O, "dynamic variable ${$ / ${' (escaped \\$ in a string is NOT one)", r"(?<!\\)\$\{\s*[\$'\"]", "php", 3)
S(C, "dynamic variable from a superglobal (${$_GET / ${$_POST ...)", r"(?<!\\)\$\{\s*" + RQ, "php", 25)
# token check against the request: the classic gate of a webshell (?t=<hash>).
# On WordPress this is the NORMAL nonce check (wp_verify_nonce -> hash_equals),
# so like the harvester it is gated off on detected WP sites.
TOKEN_GATE_LABEL = "hash_equals() comparing against request data (token-gated backdoor)"
S(O, TOKEN_GATE_LABEL, r"\bhash_equals\s*\([^;{\n]{0,150}?" + RQ, "php", 8)
# a variable from the request goes into a file function (read/write/list via LFI)
S(O, "file function fed by a variable from request data", r"(\$[\w]+)\s*=\s*@?" + TAINT_SRC + r"\s*;[\s\S]{0,300}?\b(?:fopen|opendir|readfile|file_get_contents|file_put_contents|file|copy|rename|move_uploaded_file|unlink|chmod|touch)\s*\(\s*[^;{\n]{0,80}?\1\b", "php", 8)
# the impersonation header sits in the plugin docblock - a PHP comment, so this
# one runs over the raw text
S(O, "plugin header claims 'WordPress.org Community' authorship (impersonation)", r"Author\s*:\s*WordPress\.org\s+Community", "php", 10, re.I, raw=True)
S(C, "known webshell signature", r"\bFilesMan\b|c99shell|r57shell|\bb374k\b|Mini\s*Shell|\bPriv8\b|IndoXploit|Alfa\s*Team|AnonymousFox|\bWSO\s*\d|Sh3ll\b|\bHacked\s+by\b", "php js html text", 30, re.I)
S(C, "Tiny File Manager / webshell", r"tinyfilemanager|embedded_pass_hash|fm_clean_path|H3K\s*\|\s*Tiny", "php html", 30, re.I)
S(C, "malware tag <script id='sggtp'>", r"<script[^>]*\bid\s*=\s*['\"]?sggtp", "php js html text", 30, re.I)
# ---- CRITICAL: JS / HTML ----
S(C, "crypto-miner", r"coinhive|coin-hive|cryptonight|cryptoloot|crypto-loot|webminepool|minero\.cc|authedmine", "php js html", 25, re.I)
S(C, "hidden iframe that loads a payload (src=/srcdoc=)", r"<iframe\b(?=[^>]{0,400}\b(?:src|srcdoc)\s*=\s*['\"]?\s*(?:https?://|//|/|\?|data:|<\?|\$[A-Za-z_]|\&#|[^'\">\s]{1,80}\.(?:php|phtml)))[^>]{0,400}(?:\b(?:width|height)\s*=\s*['\"]?[01](?:px)?['\"]?[\s>/]|display\s*:\s*none|visibility\s*:\s*hidden)", "php js html", 15, re.I)
S(W, "iframe built in JS (createElement / .src=)", r"createElement\s*\(\s*['\"]iframe\b|\biframe\b[^;\n]{0,40}\.src\s*=(?!=)\s*['\"]?\s*(?!javascript:|about:blank)|innerHTML[^;\n]{0,120}<iframe", "php js html", 1)
S(C, "hex-obfuscated JS _0xXXXX", r"_0x[0-9a-fA-F]{4,}", "php js html")
S(C, "JS packer eval(function(p,a,c,k,e,d))", r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", "php js html", 15)
S(C, "document.write/eval of decoded string", r"\b(?:document\.write|eval)\s*\(\s*(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(", "php js html", 20)

# ---- OBFUSCATED: PHP ----
S(O, "base64_decode + eval on one line", r"base64_decode.{0,300}eval|eval.{0,300}base64_decode", "php")
S(O, "gzinflate/gzuncompress/hex2bin/str_rot13/frombase64", r"\b(?:gzinflate|gzuncompress|gzdecode|hex2bin|str_rot13|convert_uudecode)\s*\(|frombase64\s*\(", "php")
S(O, "fsockopen / raw sockets", r"\b(?:fsockopen|pfsockopen|stream_socket_client|socket_create)\s*\(", "php")
S(O, "popen / proc_open", r"\b(?:popen|proc_open)\s*\(", "php")
S(O, "goto (obfuscation)", r"\bgoto\s+\w+\s*;", "php")
S(O, "eval($variable)", r"\beval\s*\(\s*@?\s*\$\w+", "php")
S(O, "@-suppressed dangerous call", r"@\s*(?:eval|assert|system|exec|passthru|shell_exec)\s*\(", "php")
S(O, "error_reporting(0)", r"\berror_reporting\s*\(\s*0\s*\)", "php")
S(O, "ini_set display_errors off", r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:0|off|false)", "php", flags=re.I)
# only PRINTABLE characters (0x20-0x7f): that is how function names/URLs are hidden. Binary data tables (\xc1\xc0...) do not count
S(O, "hex-escaped string \\x..\\x..", r"(?:\\x[2-7][0-9a-fA-F]){6,}", "php js")
S(O, "octal-escaped string", r"(?:\\(?:0[4-7][0-7]|1[0-7][0-7])){6,}", "php")
# 4+ consecutive chr() calls with PRINTABLE codes (that is how "eval", "assert" are built). chr(194).chr(160) (NBSP), chr(0).chr(32) and binary data bytes do not count
_CHR = r"chr\s*\(\s*(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\s*\)"
S(O, "chr(N).chr(N)... building a string from printable codes", r"\b(?:" + _CHR + r"\s*\.\s*){3,}" + _CHR, "php")
S(O, "strrev('...') of a function name", r"\bstrrev\s*\(\s*['\"][a-z_0-9]{6,}['\"]\s*\)", "php")
S(O, "huge base64 blob", r"[A-Za-z0-9+/]{300,}={0,2}", "php")
S(O, "variable function with request data", r"\$\w+\s*\(\s*@?\s*" + RQ + r"\s*\[", "php")
S(O, "mail() with request data", r"\bmail\s*\([^;\n]{0,200}" + RQ, "php")
S(O, "wget/curl to URL", r"\b(?:wget|curl)\s+(?:-\S+\s+)*https?://", "php")
# the last three words are Russian spam keywords (viagra, casino, porn), kept as \u escapes so that the source stays ASCII-only
S(O, "SEO-spam keywords", r"\b(?:viagra|cialis|levitra|payday\s*loans?|online\s*casino|replica\s+watches)\b|\u0432\u0438\u0430\u0433\u0440\u0430|\u043a\u0430\u0437\u0438\u043d\u043e|\u043f\u043e\u0440\u043d\u043e", "php html js", flags=re.I)
S(O, "cloaking by User-Agent/Referer", r"HTTP_(?:USER_AGENT|REFERER).{0,200}(?:googlebot|yandex|bingbot|slurp|baiduspider|google|bing)", "php", 8, re.I)
S(O, "many blank lines before code (hidden code)", r"(?:[ \t]*\r?\n){30,}[ \t]*\S", "php htaccess", 5, at_end=True)

# ---- CRITICAL: credential harvester (Joomla-specific) ----
# Legitimate Joomla code does NOT read $_POST['password'] directly (login goes through the API), so this is a strong indicator.
# On WordPress the same reads are legitimate core/plugin code, so the heuristic is gated off on detected WP sites.
HARVEST_C12_LABEL = "credential harvesting: password field read from $_POST"
S(C, HARVEST_C12_LABEL, r"\$_POST\b[^\n]{0,80}?\[\s*['\"](?:password|passwd|pass|pwd|userpassword|regpass)['\"]\](?!\s*=[^=])", "php", 12)
# ---- OBFUSCATED: data store hidden in an image (steganography) ----
S(O, "custom X- response header (self-advertising marker)", r"\bheader\s*\(\s*@?\s*['\"]X-(?!Accel-Redirect|Blueprint-Import-Session|Content-Type-Options|Frame-Options|Lighttpd-Sendfile|MCP-API-Key|Redirect-By|Robots|Sendfile|UA-Compatible|WP-)[\w\-]{2,40}[:\"]", "php", 8)
S(O, "GIF magic bytes handled in PHP (image used as a data container)", r"GIF8[79]a", "php", 3)
S(O, "hard-coded blank GIF (R0lGODlh...) as a data container", r"R0lGODlh", "php", 5)
# ---- WARNING: weak signatures; only their correlation (harvester_hits) makes a finding CRITICAL ----
S(W, "register_shutdown_function (deferred handler: code runs after the response)", r"\bregister_shutdown_function\s*\(", "php")
S(W, "PHP writes into an images/media folder", r"['\"][^'\"\n]{0,40}[/\\](?:images|img|media|uploads?)[/\\]['\"]", "php")
S(W, "PHP appends data to a file it just read (record/log store)", r"\bfile_get_contents\b[\s\S]{0,400}?\bfile_put_contents\s*\(", "php")

# ---- OBFUSCATED: JS ----
S(O, "String.fromCharCode", r"String\.fromCharCode\s*\(", "js html")
S(O, "atob / unescape", r"\batob\s*\(|\bunescape\s*\(", "js html")

# ---- WARNING: PHP ----
for _lbl, _rx in [("$_COOKIE", r"\$_COOKIE"), ("$_POST", r"\$_POST"), ("$_GET", r"\$_GET"),
                  ("eval(", r"\beval\s*\("), ("assert(", r"\bassert\s*\("),
                  ("base64_decode(", r"\bbase64_decode\s*\("), ("chr(", r"\bchr\s*\("),
                  ("exec(", r"\bexec\s*\("), ("system(", r"\bsystem\s*\("),
                  ("move_uploaded_file(", r"\bmove_uploaded_file\s*\("),
                  ("file_put_contents(", r"\bfile_put_contents\s*\("),
                  ("curl_exec(", r"\bcurl_exec\s*\("),
                  ("chmod 0777", r"\bchmod\s*\([^;\n]{0,60}0?777"),
                  ("set_time_limit(0)", r"\bset_time_limit\s*\(\s*0\s*\)")]:
    S(W, _lbl, _rx, "php")
# ---- WARNING: JS ----
S(W, "document.write(", r"\bdocument\.write\s*\(", "js html")
S(W, "new Function(", r"\bnew\s+Function\s*\(", "js html")
S(W, "eval(", r"\beval\s*\(", "js")

# ---- .htaccess / ini ----
H = "htaccess"
S(C, "auto_prepend_file / auto_append_file", r"auto_(?:prepend|append)_file", "htaccess ini", 30, re.I)
S(C, "PHP handler for non-PHP extension", r"\b(?:AddType|AddHandler)\s+(?:application/x-httpd-\S*php\S*|x-httpd-php\d*|php\d*-script)\s+[^\n]*\.(?:jpe?g|png|gif|ico|txt|html?|css|js|xml|bak|tmp|json|log|svg|webp)\b", H, 30, re.I)
S(C, "cloaking: User-Agent of search bots", r"RewriteCond\s+%\{HTTP_USER_AGENT\}[^\n]*(?:google|bing|yandex|yahoo|baidu|slurp|spider|crawl|bot)", H, 15, re.I)
S(C, "cloaking: Referer from search engines", r"RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(?:google|bing|yahoo|yandex|baidu|aol\.|ask\.com|duckduckgo|search\.)", H, 25, re.I)
S(C, "known malicious .htaccess template (deny all PHP except a list)", r"\(py\|exe\|php\|PHP\|Php", H, 30)
S(C, "case-permutation PHP deny list (malicious .htaccess template)", r"<(?i:FilesMatch)\s+[\"'][^\"'\n]*\bPHP\|Php\|PHp", H, 30)
S(O, "FilesMatch allows only specific PHP files", r"<FilesMatch\s+[\"']\^?\(?[\w.\-]+\.php(?:\|[\w.\-]+\.php)*\)?\$[\"']\s*>#?\s*\r?\n\s*Order\s+allow\s*,\s*deny\s*\r?\n\s*Allow\s+from\s+all", H, 8, re.I)
S(C, "allow-list of PHP files (locks out every other script)", r"<FilesMatch\s+[\"']\^?\((?:[\w.\-]+\.php\|){6,}", H, 25, re.I)
S(O, "FilesMatch denies PHP execution (check what is allowed)", r"<FilesMatch\s+[\"'][^\"'\n]*php[^\"'\n]*[\"']\s*>\s*\r?\n\s*Order\s+allow\s*,\s*deny\s*\r?\n\s*Deny\s+from\s+all", H, 4, re.I)
S(O, "RewriteRule to external URL", r"RewriteRule\s+\S+\s+https?://(?!%\{)", H, flags=re.I)
S(O, "Redirect to external URL", r"^\s*Redirect(?:Match|Permanent)?\s+(?:\d{3}\s+)?\S+\s+https?://", H, flags=re.I | re.M)
S(O, "ErrorDocument to external URL", r"ErrorDocument\s+\d{3}\s+https?://", H, flags=re.I)
S(O, "SetHandler", r"^\s*SetHandler\s+\S+", H, flags=re.I | re.M)
S(O, "php_flag/php_value allow_url_include / engine on", r"php_(?:flag|value)\s+(?:allow_url_include|engine)\s+(?:on|1)", H, flags=re.I)
S(O, "Options +ExecCGI", r"Options\s+[^\n]*\+ExecCGI", H, flags=re.I)
S(O, "allow_url_include = On", r"allow_url_include\s*=\s*(?:on|1|true)", "ini", flags=re.I)

# the heaviest signatures first -> when several match on one line, the strongest wins
for _k in SIGS_BY_KIND:
    SIGS_BY_KIND[_k].sort(key=lambda t: (SEV_RANK[t[0]], -t[3]))

# ---------------------------------------------------------------------------
# 3) HELPERS
# ---------------------------------------------------------------------------

CFG = {}


def _init(cfg):
    global CFG
    CFG = cfg


# ---------------------------------------------------------------------------
# the data folder: what the tools keep between runs lives here - never next to
# the code, never inside a scanned site (the updater and the GUI use the same root)
# ---------------------------------------------------------------------------

LEGACY_YARAC_DIR = os.path.join(tempfile.gettempdir(), "scan-backdoors-yarac")


def data_root():
    """$SBD_DATA_DIR, otherwise ~/.scan_backdoors; the temp folder when there is
    no home directory to write to (a scanner copied to a bare server)."""
    d = os.environ.get("SBD_DATA_DIR")
    if d:
        return os.path.abspath(os.path.expanduser(d))
    home = os.path.expanduser("~")
    if not home or home == "~":
        return os.path.join(tempfile.gettempdir(), "scan-backdoors")
    return os.path.join(home, ".scan_backdoors")


def default_yarac_dir():
    """Where the compiled .yarac files live by default (--yara-cache overrides it)."""
    return os.path.join(data_root(), "yarac")


def migrate_yarac_cache():
    """Move the old temp-folder cache into the data folder once (OPEN_QUESTIONS #3).

    It is only a cache: when anything goes wrong the rules are simply recompiled,
    so this never fails a scan and never deletes anything the user cannot lose."""
    new_dir = default_yarac_dir()
    if not os.path.isdir(LEGACY_YARAC_DIR) or os.path.exists(new_dir):
        return False
    try:
        parent = os.path.dirname(new_dir)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        shutil.move(LEGACY_YARAC_DIR, new_dir)
        return True
    except OSError:
        return False


def yara_key(spec):
    """Stable per-process cache key for one --yara-rules configuration."""
    return (tuple(spec["sources"]), spec["cache"], float(spec["timeout"]),
            tuple(sorted(spec["externals"].items())))


_YARA_ENGINES = {}


def get_engines(cfg):
    """Extra detection engines for this process ([] when --yara-rules is off).

    Rules compile once per worker process (lazily, on its first batch); the
    .yarac cache under cfg["yara"]["cache"] makes that cheap. Compilation
    problems were already reported by the main process, so workers build
    quietly."""
    spec = cfg.get("yara")
    if not spec or build_yara_engine is None:
        return []
    key = yara_key(spec)
    engines = _YARA_ENGINES.get(key)
    if engines is None:
        eng, _problems = build_yara_engine(spec["sources"], cache_dir=spec["cache"],
                                           base_externals=spec["externals"],
                                           timeout=spec["timeout"])
        engines = [eng] if eng is not None else []
        _YARA_ENGINES[key] = engines
    return engines


def looks_random(stem):
    if len(stem) < 6 or not re.match(r"^[a-z0-9]+$", stem):
        return False
    if re.search(r"[a-z]\d+[a-z]", stem):
        return True
    letters = [c for c in stem if c.isalpha()]
    if len(letters) >= 6:
        vowels = sum(1 for c in letters if c in "aeiouy")
        if vowels / float(len(letters)) < 0.15:
            return True
    return False


def name_checks(name, low):
    notes = []
    if low.startswith("."):
        if low != ".phpstorm.meta.php":
            notes.append((C, 0, "hidden PHP file (leading dot)", name, 15))
        stem = ""
    else:
        stem = low.split(".")[0]
    if re.search(r"\s", name):
        notes.append((O, 0, "whitespace in filename", name, 5))
    if stem in SHELL_NAMES or any(stem.startswith(p) for p in SHELL_NAME_PREFIXES):
        notes.append((C, 0, "typical webshell filename", name, 25))
    if low in MALWARE_NAMES:
        notes.append((O, 0, "filename from a known malicious .htaccess allow-list", name, 10))
    if low.startswith("wp-"):
        notes.append((O, 0, "WordPress-style filename (wp-*.php) in Joomla", name, 5))
    if stem and len(stem) <= 2:
        notes.append((O, 0, "very short filename", name, 5))
    if looks_random(stem):
        notes.append((O, 0, "random-looking filename", name, 5))
    return notes


def classify(name):
    """-> (kind | None, [name-level hits])"""
    low = name.lower()
    notes = []
    if HTACCESS_NAME_RE.match(low):
        return "htaccess", notes
    if low in ("php.ini", ".user.ini"):
        return "ini", notes
    if low in ("web.config", ".htpasswd", "configuration", "robots.txt"):
        return "text", notes
    ext = os.path.splitext(low)[1]
    kind = None
    if IMG_DOUBLE_RE.search(low):
        notes.append((C, 0, "double extension (image.php)", name, 30))
        kind = "php"
    elif BACKUP_RE.search(low):
        notes.append((O, 0, "backup / suspicious extension", name, 5))
        kind = "php"
    elif DOUBLE_RE.search(low):
        notes.append((C, 0, "double extension (.php.xxx)", name, 25))
        kind = "php"
    elif ext in PHP_EXT:
        kind = "php"
        notes.extend(name_checks(name, low))
    elif ext == ".js":
        kind = "js"
    elif ext in HTML_EXT:
        kind = "html"
    elif ext in INI_EXT:
        kind = "ini"
    elif ext in TEXT_EXT:
        kind = "text"
    elif ext in MEDIA_EXT:
        kind = "media"
    return kind, notes


def looks_binary(raw):
    """Binary: a NUL byte or many control characters. Cyrillic text (cp1251/utf-8) is NOT considered binary."""
    if b"\x00" in raw[:8192]:
        return True
    sample = raw[:4096]
    if not sample:
        return False
    ctrl = sum(1 for b in sample if (b < 32 and b not in (9, 10, 13)) or b == 127)
    return (ctrl / float(len(sample))) > 0.30


def first_php_tag(text, kind):
    """First PHP tag in a non-PHP file. In .js we ignore tags inside comments (// ... or /* ... */):
    that is what old commented-out code looks like (for example VirtueMart products.js)."""
    n = 0
    for m in PHP_TAG_RE.finditer(text):
        n += 1
        if n > 50:
            break
        ls = text.rfind("\n", 0, m.start()) + 1
        if kind == "js":
            prefix = text[ls:m.start()]
            if prefix.lstrip().startswith(("//", "/*", "*")) or re.search(r"(?<!:)//", prefix):
                continue
        return m, text.count("\n", 0, m.start()) + 1
    return None


def decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", errors="replace")


def trim(s, limit=140):
    s = s.strip()
    return s if len(s) <= limit else s[:limit] + " …"


def snippet_at(text, nl, idx, m, at_end):
    ls = nl[idx - 1] + 1 if idx > 0 else 0
    le = nl[idx] if idx < len(nl) else len(text)
    line = text[ls:le]
    if len(line.strip()) <= 160:
        return line.strip()
    mpos = (m.end() - 1 if at_end else m.start()) - ls
    a = max(0, mpos - 60)
    b = min(len(line), mpos + 100)
    return ("… " if a > 0 else "") + line[a:b].strip() + (" …" if b < len(line) else "")


# ---------------------------------------------------------------------------
# PHP comment mask. Signatures must not fire inside comments (WP core docblocks
# quote $_POST in backticks all the time), but line numbers and snippets in the
# report point into the ORIGINAL text - so the mask only blanks comment
# characters: same length, newlines in the same places.
# ---------------------------------------------------------------------------

PHP_COMMENT_EDGE_RX = re.compile(r"<\?|\?>|//|/\*|['\"]|#")
PHP_TAG_OPEN_RX = re.compile(r"<\?(?:php\b|=|[ \t])", re.I)


def mask_php_comments(text):
    """Blank //, # and /* ... */ comments inside PHP code regions with spaces.

    String literals are left intact, and so is the HTML that may surround the
    code in a .php file. The result has the same length as the input and every
    newline in its original place, so offsets and line numbers computed on the
    masked text stay valid for the original. Returns the input unchanged when
    there is nothing to mask.
    """
    if "<" not in text or ("//" not in text and "/*" not in text and "#" not in text):
        return text
    out = None
    n = len(text)

    def blank(a, b, keep_newlines=False):
        nonlocal out
        if out is None:
            out = list(text)
        if keep_newlines:
            for p in range(a, b):
                if text[p] != "\n" and text[p] != "\r":
                    out[p] = " "
        else:
            out[a:b] = [" "] * (b - a)

    in_php = False
    until = 0                      # everything before this index is processed
    for m in PHP_COMMENT_EDGE_RX.finditer(text):
        s = m.start()
        if s < until:
            continue               # inside a string/comment/tag already handled
        tok = m.group(0)
        if tok == "<?":
            if in_php:
                continue           # a stray tag inside active code: not a real tag
            tag = PHP_TAG_OPEN_RX.match(text, s)
            if tag:
                in_php = True
                until = tag.end()
            continue
        if not in_php:
            continue               # a marker inside HTML: not a PHP comment
        if tok == "?>":
            in_php = False
            until = s + 2
        elif tok in ("'", '"'):
            j = s + 1
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                elif ch == tok or ch == "\n":
                    j += 1
                    break
                else:
                    j += 1
            until = j              # string content is NOT masked
        elif tok == "/*":
            j = text.find("*/", s + 2)
            j = n if j < 0 else j + 2
            blank(s, j, keep_newlines=True)
            until = j
        else:                      # // or #
            j = text.find("\n", s)
            j = n if j < 0 else j
            k = text.find("?>", s, j)
            if k >= 0:
                j = k              # PHP ends a line comment at a closing tag: what follows is live code
            blank(s, j)
            until = j
    return "".join(out) if out is not None else text


def scan_text(text, kinds, enabled):
    hits = []
    seen = set()
    nl = None
    sigs_text = text
    if kinds == ["php"]:
        # Only files whose OWN kind is PHP: in .htaccess/.js/.text the PHP
        # signatures run over embedded code, and the comments there belong to
        # the other language (a BiaoJiOk marker in a .htaccess comment is a
        # true positive and must keep firing on the raw text).
        sigs_text = mask_php_comments(text)
    for kind in kinds:
        for sev, label, rx, w, at_end, raw in SIGS_BY_KIND.get(kind, ()):
            if sev not in enabled:
                continue
            # legitimate on a WordPress site (nonce verification, login flows):
            # these heuristics only make sense as standalone tells on non-WP
            if label in (HARVEST_C12_LABEL, TOKEN_GATE_LABEL) and CFG.get("cms") == "wp":
                continue
            hay = text if raw else sigs_text
            n = 0
            for m in rx.finditer(hay):
                n += 1
                if n > PATTERN_CAP:
                    break
                if nl is None:
                    nl = [x.start() for x in NL_RE.finditer(text)]
                pos = m.end() - 1 if at_end else m.start()
                idx = bisect.bisect_left(nl, pos)
                key = (sev, idx)
                if key in seen:
                    continue
                seen.add(key)
                hits.append((sev, idx + 1, label, snippet_at(text, nl, idx, m, at_end), w))
    return hits


def disguised_hits(raw):
    """PHP code inside an image/font/css/binary file."""
    hits = []
    for m in DISGUISE_RE.finditer(raw):
        a, b = max(0, m.start() - 40), min(len(raw), m.end() + 60)
        ctx = "".join(chr(c) if 32 <= c < 127 else "." for c in raw[a:b])
        hits.append((C, 0, "PHP code inside media/binary file (offset %d)" % m.start(), ctx, 30))
        if len(hits) >= 3:
            break
    return hits


FM_FEATURES = [
    ("list dirs", re.compile(r"\b(?:scandir|readdir|glob)\s*\(")),
    ("upload", re.compile(r"\bmove_uploaded_file\s*\(")),
    ("delete", re.compile(r"\b(?:unlink|rmdir)\s*\(")),
    ("rename", re.compile(r"\brename\s*\(")),
    ("write", re.compile(r"\b(?:fwrite|fputs|file_put_contents)\s*\(")),
    ("read", re.compile(r"\bfile_get_contents\s*\(")),
    ("perms", re.compile(r"\b(?:fileperms|chmod)\s*\(")),
]
FM_REQUEST_RE = re.compile(r"\$_(?:GET|POST|REQUEST|FILES)\b")
JOOMLA_GUARD_RE = re.compile(r"defined\s*\(\s*['\"]_JEXEC['\"]")


def filemanager_hits(text):
    """A standalone script (no _JEXEC guard) that, driven by request parameters, lists folders,
    uploads, edits, renames and deletes files = a web file manager (web shell)."""
    if JOOMLA_GUARD_RE.search(text) or not FM_REQUEST_RE.search(text):
        return []
    found = [name for name, rx in FM_FEATURES if rx.search(text)]
    if len(found) >= 4:
        return [(C, 0, "web file manager / webshell behaviour (%s) driven by request parameters" % ", ".join(found), "", 25)]
    return []


B64_LIT_RE = re.compile(r"""base64_decode\s*\(\s*(['"])([A-Za-z0-9+/]{8,}={0,2})\1\s*\)""")
MEDIA_NAME_RE = re.compile(r"^[\w .@()\-/\\]{1,120}\.(?:flv|swf|mp3|mp4|avi|mov|wav|jpe?g|png|gif|ico|bmp|webp|dat|bin|tmp)$", re.I)
DANGEROUS_TOKENS_RE = re.compile(r"eval\s*\(|assert\s*\(|system\s*\(|shell_exec|passthru|<\?php|\$_(?:GET|POST|REQUEST|COOKIE)|base64_decode|gzinflate", re.I)


def base64_literal_hits(text, folder):
    """base64_decode("...") with a string literal: we decode it statically (executing nothing)."""
    hits, n = [], 0
    for m in B64_LIT_RE.finditer(text):
        n += 1
        if n > 40:
            break
        b = m.group(2)
        try:
            dec = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8")
        except Exception:
            continue
        if not dec or not dec.isprintable():
            continue
        line = text.count("\n", 0, m.start()) + 1
        if MEDIA_NAME_RE.match(dec):
            extra = ""
            try:
                fp = os.path.join(folder or "", dec)
                if folder and os.path.isfile(fp):
                    extra = " (file exists next to it, %d bytes)" % os.path.getsize(fp)
            except (OSError, ValueError):
                pass
            hits.append((C, line, "base64 literal decodes to a media filename '%s'%s: included PHP payload?" % (dec, extra),
                         trim(m.group(0)), 25))
        elif len(dec) >= 6 and DANGEROUS_TOKENS_RE.search(dec):
            hits.append((C, line, "base64 literal decodes to code: %s" % trim(dec, 60), trim(m.group(0)), 25))
    return hits


def php_anomalies(raw, text, folder=None, rel=""):
    if rel.startswith(WP_CORE_PREFIXES) and CFG.get("cms") == "wp":
        # WP core ships its own file management (wp-admin/includes/file.php):
        # the "web file manager" heuristic would flag legitimate core code.
        fm_hits = []
    else:
        fm_hits = filemanager_hits(text)
    hits = fm_hits + base64_literal_hits(text, folder)
    if b"\x00" in raw:
        hits.append((O, 0, "NUL bytes inside PHP file", "", 5))
    ml, ml_i, ml_s = 0, 0, ""
    for i, ln in enumerate(text.split("\n")):
        if len(ln) > ml:
            ml, ml_i, ml_s = len(ln), i, ln
    if ml > LONG_LINE:
        hits.append((O, ml_i + 1, "very long line (%d chars)" % ml, trim(ml_s), 3))
    n_goto = len(re.findall(r"\bgoto\s+\w+\s*;", text))
    if n_goto >= 8:
        hits.append((O, 0, "goto chain: %d goto statements (control-flow obfuscation)" % n_goto, "", 10))
    if len(raw) >= 2048:
        sample = raw[:1048576]
        cnt = Counter(sample)
        n = float(len(sample))
        ent = -sum((c / n) * math.log(c / n, 2) for c in cnt.values())
        if ent > ENTROPY_LIMIT:
            hits.append((O, 0, "high entropy (%.2f bits/byte): packed/encrypted code?" % ent, "", 3))
    hits += harvester_hits(text)
    hits += mtime_backdate_hits(text)
    hits += image_container_hits(text)
    return hits


# ---------------------------------------------------------------------------
# 3b) CORRELATION: several weak signatures in ONE file = credential harvester
# ---------------------------------------------------------------------------

HARVEST_POST_RX = re.compile(r"\$_POST\b[^\n]{0,80}?\[\s*['\"](?:password|passwd|pass|pwd|userpassword|regpass)['\"]\](?!\s*=[^=])")
HARVEST_SINKS = [
    ("file write", re.compile(r"\b(?:file_put_contents|fwrite|fputs)\s*\(")),
    ("response-header leak", re.compile(r"\bheader\s*\(\s*@?\s*['\"]X-[^'\n]{0,60}:")),
    ("database write", re.compile(r"\b(?:insertGetId|insertGetNewId|updateObject|saveObject|__query__)\s*\(")),
    ("error_log", re.compile(r"\berror_log\s*\(")),
]
FILE_WRITE_RX = re.compile(r"\b(?:file_put_contents|fwrite|fputs)\s*\(")
IMG_DIR_RX = re.compile(r"""['\"][^'\"\n]{0,40}[/\\](?:images|img|media|uploads?)[/\\]?['\"]""")
GIF_MAGIC_RX = re.compile(r"GIF8[79]a")
BLANK_GIF_RX = re.compile(r"R0lGODlh")
TOUCH_RX = re.compile(r"\btouch3?\s*\(")
BACKDATE_RX = re.compile(r"86400|time\s*\(\s*\)\s*-|\brand\s*\(|\brandom\w*\s*\(")
MTIME_RX = re.compile(r"\bfile_?mtime\s*\(", re.I)
DEFERRED_RX = re.compile(r"\bregister_shutdown_function\s*\(")


def harvester_hits(text):
    """Reads a password field from $_POST and stores it somewhere = credential harvester.
    Joomla-specific pattern: on WordPress these reads are legitimate core/plugin code."""
    if CFG.get("cms") == "wp":
        return []
    m = HARVEST_POST_RX.search(text)
    if not m:
        return []
    line = text.count("\n", 0, m.start()) + 1
    snip = trim(m.group(0))
    sinks = [lbl for lbl, rx in HARVEST_SINKS if rx.search(text)]
    if not sinks:
        return [(O, line, "reads a password field from $_POST (check where it goes)", snip, 6)]
    how = " (runs via register_shutdown_function, after the response)" if DEFERRED_RX.search(text) else ""
    return [(C, line, "credential harvester: password from $_POST -> %s%s" % (", ".join(sinks), how), snip, 20)]


def mtime_backdate_hits(text):
    """touch() with a computed old date: defeats --since and 'recently modified' checks."""
    m = TOUCH_RX.search(text)
    if not m:
        return []
    line = text.count("\n", 0, m.start()) + 1
    # only a backdating expression INSIDE the touch(...) call counts: a stray 86400 / time()- /
    # rand() elsewhere in a big file (an mtime restore, a method definition) is not backdating
    i, depth, n = m.end(), 1, len(text)
    while i < n and depth:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    args = text[m.end():i - 1]
    if BACKDATE_RX.search(args):
        return [(C, line, "mtime backdating (sets a fake old date): defeats --since and 'recently modified' checks", "", 15)]
    if MTIME_RX.search(args):
        return [(O, line, "touch() + file_mtime: restores the original file date (check why)", trim(m.group(0)), 6)]
    return [(O, line, "touch() changes a file date", trim(m.group(0)), 3)]


def image_container_hits(text):
    """PHP builds image bytes (GIF magic / blank GIF) and writes a file = stego data container."""
    if not FILE_WRITE_RX.search(text):
        return []
    stego = bool(GIF_MAGIC_RX.search(text) or BLANK_GIF_RX.search(text))
    into_media = bool(IMG_DIR_RX.search(text))
    if stego and into_media:
        return [(C, 0, "PHP writes an image built from GIF magic/blank-GIF bytes into images/: data container (stego store)", "", 18)]
    if stego:
        return [(O, 0, "PHP builds image bytes (GIF magic / blank GIF) and writes a file: image used as a data container", "", 10)]
    return []


def gif_trailing_hits(raw):
    """Walk the GIF block structure; data after the final 0x3B trailer = appended record stream."""
    if raw[:6] not in (b"GIF87a", b"GIF89a") or len(raw) < 14:
        return []
    hits = []
    w = int.from_bytes(raw[6:8], "little")
    h = int.from_bytes(raw[8:10], "little")
    if w and h and max(w, h) <= 16 and len(raw) > 3000:
        hits.append((O, 0, "GIF declares %dx%d px but the file is %d bytes: data hidden inside an image" % (w, h, len(raw)), "", 12))
    i = 13
    if not (raw[12] & 0x80):
        i += 3 * (2 << (raw[10] & 7))    # global color table (3 bytes per entry)
    end = None
    while i < len(raw) and end is None:
        b = raw[i]
        if b == 0x3B:                    # trailer: end of the image
            end = i + 1
            break
        if b == 0x21:                    # extension block (introducer + label, then sub-blocks)
            i += 2
        elif b == 0x2C:                  # image block
            i += 11
        else:
            break
        while i < len(raw):              # sub-blocks
            n = raw[i]
            i += 1
            if n == 0:
                break
            i += n
    if end is not None and len(raw) - end > 512:
        hits.append((O, 0, "%d bytes appended AFTER the end of the GIF (record stream / data store)" % (len(raw) - end), "", 15))
    return hits


def blob_hits(rel, name, kind, raw):
    """Extensionless file whose content is a printable high-entropy blob (encoded payload / data drop)."""
    if kind is not None or len(raw) < 128:
        return []
    if name.lower().endswith((".pem", ".crt", ".cer", ".asc", ".base64")):
        return []
    if sum(1 for b in raw if 32 <= b < 127) < 0.9 * len(raw):
        return []
    cnt = Counter(raw)
    n = float(len(raw))
    ent = -sum((c / n) * math.log(c / n, 2) for c in cnt.values())
    if ent < 5.6:
        return []
    d = rel.lower().rsplit("/", 1)[0] if "/" in rel else ""
    inside = any(p in STRICT_DIRS for p in d.split("/"))
    return [(O, 1, "extensionless file with high-entropy printable blob (encoded payload / data drop)",
             name, 10 if inside else 6)]


def manifest_author_hits(rel, text, base_dirs):
    """Manifest claims Joomla! Project authorship, but the plugin folder is not in the clean distribution."""
    if "<extension" not in text:
        return []
    m = re.search(r"<author>\s*Joomla\s*!?\s*Project\s*</author>|admin@joomla\.org", text, re.I)
    if not m:
        return []
    if not base_dirs:
        return []
    d = rel.rsplit("/", 1)[0].lower() if "/" in rel else ""
    if d and d in base_dirs:
        return []
    return [(O, 1, "plugin manifest claims Joomla! Project authorship, but the whole plugin folder is absent from the clean Joomla distribution", rel, 12)]


def _jconfig_class_end(text, m):
    """Index just past the closing brace of the JConfig class body.

    The "code after class JConfig" signature needs the real end of the class:
    a backdoor appended below the class carries braces of its own and
    str.rfind("}") would land inside it. Braces inside string literals and
    comments do not count. Returns -1 if the body never closes.
    """
    i = text.find("{", m.end())
    if i < 0:
        return -1
    n = len(text)
    depth = 0
    quote = ""
    while i < n:
        c = text[i]
        if quote:
            if c == quote:
                quote = ""
            elif c == "\\" and i + 1 < n:
                i += 1
        elif c in "'\"":
            quote = c
        elif c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):
            if c == "/":
                i += 1                      # skip the second "/" of "//"
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            close = text.find("*/", i + 2)
            i = n if close < 0 else close + 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def config_hits(text):
    hits = []
    if text.count("<?php") > 1:
        hits.append((C, 0, "several <?php blocks in configuration.php", "", 25))
    m = re.search(r"class\s+JConfig\b", text)
    if not m:
        hits.append((O, 0, "configuration.php without class JConfig", "", 6))
        return hits
    head = re.sub(r"<\?php|/\*.*?\*/|//[^\n]*|#[^\n]*", "", text[:m.start()], flags=re.S).strip()
    if head:
        hits.append((O, 0, "code before class JConfig", trim(head), 8))
    end = _jconfig_class_end(text, m)
    if end < 0:
        end = text.rfind("}") + 1           # malformed: the body never closes, fall back to the last brace
    tail = text[end:].strip()
    if tail.endswith("?>"):
        tail = tail[:-2].strip()
    if tail:
        hits.append((C, 0, "code AFTER class JConfig in configuration.php", trim(tail), 30))
    return hits


def location_hits(rel, name, size, head):
    parts = rel.lower().split("/")[:-1]
    if not parts or (name.lower() == "index.php" and size < 120):
        return []
    first = parts[0]
    if first in STRICT_DIRS:
        return [(C, 0, "PHP file in /%s/ (must not exist there)" % first, rel, 25)]
    soft = first in SOFT_DIRS or (first == "administrator" and len(parts) > 1 and parts[1] in SOFT_DIRS)
    if soft:
        if name.lower().startswith("autoload") and name.lower().endswith(".php"):
            return []
        if DIE_HEADER_RE.match(head):
            return []
        return [(C, 0, "PHP file in /%s/ without Joomla die() header" % parts[-1 if first == "administrator" else 0], rel, 15)]
    if first == "media":
        return [(O, 0, "PHP file in /media/", rel, 6)]
    # the July-2026 wp2shell campaign drops plugins named <name>-<6 hex digits>;
    # real plugin slugs end in a version (1.2.3), never in a bare hex id
    if re.match(r"wp-content/(?:plugins|mu-plugins)/[^/\\]+-[0-9a-fA-F]{6}[/\\]", rel):
        return [(O, 0, "plugin folder named like a campaign drop (<name>-<6 hex> suffix)", rel, 8)]
    if any(p in STRICT_DIRS for p in parts):
        return [(O, 0, "PHP file inside an images/tmp subfolder", rel, 8)]
    return []


# Malware likes to hide in a folder nested inside a same-named folder (a/a/x.php). Legitimate exceptions:
DUPDIR_EXEMPT_RE = re.compile(r"(?:^|/)akeeba/engine/engine(?:/|$)")      # this is how the Akeeba Backup engine is structured


def dup_dir_prefix(rel_dir):
    """'a/b/b/c' -> 'a/b/b' (the first pair of same-named nested folders), otherwise None."""
    parts = rel_dir.split("/")
    for i in range(1, len(parts)):
        if parts[i] and parts[i].lower() == parts[i - 1].lower():
            pre = "/".join(parts[:i + 1])
            return None if DUPDIR_EXEMPT_RE.search(pre) else pre
    return None


def dupdir_hits(rel):
    d = rel.rsplit("/", 1)[0] if "/" in rel else ""
    pre = dup_dir_prefix(d) if d else None
    if not pre:
        return []
    weight = 3 if "/vendor/" in "/" + pre + "/" else 8     # this happens more often in composer packages
    return [(O, 0, "file inside a folder nested in a same-named folder (%s)" % pre, rel, weight)]


def compute_score(hits):
    sums = {SEV_CRIT: 0, SEV_OBF: 0, SEV_WARN: 0}
    per_label = {}
    for h in hits:
        if h[0] == SEV_CRIT:
            sums[h[0]] += h[4]
        else:                       # repeats of the same weak signature: no more than 2 x its weight
            key = (h[0], h[2])
            cur = per_label.get(key, 0)
            add = min(h[4], max(2 * h[4] - cur, 0))
            per_label[key] = cur + add
            sums[h[0]] += add
    total = sum(min(sums[s], SCORE_CAP[s]) for s in sums)
    if sums[SEV_CRIT] == 0:                 # obfuscation alone / warnings without [CRITICAL] - at most MEDIUM
        total = min(total, HIGH_SCORE - 1)
    return total


def verdict_of(score):
    if score >= HIGH_SCORE:
        return "HIGH"
    if score >= MEDIUM_SCORE:
        return "MEDIUM"
    return "LOW"


def path_whitelisted(rel, patterns):
    for p in patterns:
        if any(ch in p for ch in "*?["):
            # a mask never spans folders: 'a/*.php' is a/x.php, not a/b/c/x.php
            if rel.count("/") == p.count("/") and fnmatch.fnmatch(rel, p):
                return True
        elif rel == p or rel.startswith(p.rstrip("/") + "/"):
            return True
    return False


def make_result(rel, st, sha, hits, max_matches, gaps=None):
    counts = Counter(h[0] for h in hits)
    score = compute_score(hits)
    hits = sorted(hits, key=lambda h: (SEV_RANK[h[0]], h[1]))
    shown, per = [], Counter()
    for h in hits:
        per[h[0]] += 1
        if per[h[0]] <= max_matches:
            shown.append(h)
    return {
        "path": rel, "size": st.st_size, "mtime": st.st_mtime,
        "mode": "%04o" % stat.S_IMODE(st.st_mode), "sha256": sha or "",
        "score": score, "verdict": verdict_of(score),
        "counts": dict(counts), "hits": shown, "hidden": len(hits) - len(shown),
        # engine gaps: internal bookkeeping (coverage counters), not a report field
        "gaps": list(gaps or []),
    }


# ---------------------------------------------------------------------------
# 4) SCANNING ONE FILE
# ---------------------------------------------------------------------------

def scan_file(path):
    cfg = CFG
    abspath = os.path.abspath(path)
    if abspath in cfg["skip_paths"]:
        return None, "skip"
    rel = os.path.relpath(path, cfg["start"]).replace(os.sep, "/")
    name = os.path.basename(path)
    kind, hits = classify(name)
    if cfg["cms"] == "wp":
        # Joomla-specific name heuristics do not apply to a WordPress site.
        hits = [h for h in hits
                if h[2] != "WordPress-style filename (wp-*.php) in Joomla"
                and not (h[2] == "typical webshell filename" and rel.lower() in WP_SHELL_NAME_EXEMPT)]
    if os.path.splitext(name.lower())[1] in cfg["exclude_ext"]:
        return None, "skip"
    try:
        st = os.lstat(path)
    except OSError:
        return None, "error"
    mm = cfg["max_matches"]
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = "?"
        return make_result(rel, st, "", [(O, 0, "symlink inside web root", "-> " + target, 8)], mm), "scanned"
    if not stat.S_ISREG(st.st_mode):
        return None, "skip"
    if cfg["since"] and st.st_mtime < cfg["since"]:
        return None, "old"
    audit = False
    if path_whitelisted(rel, cfg["wl_paths"]):
        if not cfg.get("audit_wl"):
            return None, "whitelisted_path"      # content NOT scanned: counted separately in the statistics
        audit = True                             # --audit-whitelisted: still look, but report [CRITICAL] only

    phpish = (kind == "php")
    if st.st_size > cfg["max_size"]:
        if phpish:
            hits.append((O, 0, "PHP file larger than --max-size: NOT scanned", "%d bytes" % st.st_size, 5))
            return make_result(rel, st, "", hits, mm), "scanned"
        return None, "big"
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        # file exists but is not readable (Windows permissions / ACL): the scanner cannot verify its contents
        hits.append((C, 0, "file could NOT be read (Windows permissions): scanner blind spot, verify manually",
                     "%d bytes, %s" % (st.st_size, fmt_time(st.st_mtime)), 20))
        return make_result(rel, st, "", hits, mm), "unreadable"

    sha = None
    if cfg["wl_hashes"] or (cfg["baseline"] is not None and phpish):
        sha = hashlib.sha256(raw).hexdigest()
        if sha in cfg["wl_hashes"]:
            return None, "whitelisted"

    # --- comparison with clean Joomla ---
    if cfg["baseline"] is not None and phpish and name.lower().endswith(".php"):
        b = cfg["baseline"].get(rel)
        if b is not None:
            if b == sha:
                return None, "core_ok"
            hits.append((O, 0, "differs from the clean Joomla file", rel, 10))
        elif rel.startswith("libraries/vendor/") and "/".join(rel.split("/")[:4]) not in cfg["baseline_pkgs"]:
            hits.append((O, 0, "extra Composer package, not in clean Joomla (installed by an extension?)", rel, 2))
        elif rel.startswith(CORE_PREFIXES) or ("/" not in rel and name.lower() != "configuration.php"):
            hits.append((O, 0, "file is not part of clean Joomla", rel, 10))

    yara_gaps = []
    for eng in get_engines(cfg):           # extra engines only: all built-in heuristics above stay as they are
        e_hits, gap_reasons = eng.scan(ScanCtx(path=abspath, rel=rel, name=name, kind=kind,
                                               raw=raw, size=st.st_size))
        hits += e_hits
        yara_gaps += gap_reasons

    enabled = cfg["enabled"] & {SEV_CRIT} if audit else cfg["enabled"]

    if kind in ("php", "htaccess"):
        hits += dupdir_hits(rel)
    if kind == "media":
        hits += disguised_hits(raw) + gif_trailing_hits(raw)
    elif kind != "php" and looks_binary(raw):
        hits += disguised_hits(raw)
    else:
        text = decode(raw)
        kinds = [kind]
        if kind != "php":
            tag = first_php_tag(text, kind)
            if tag:
                line_no = tag[1]
                kinds.append("php")
                if kind == "js":
                    # legitimate .js files may contain the string "<?php" (syntax highlighting, editors) - not critical
                    hits.append((O, line_no, "PHP tag inside a JS file (syntax highlighter or injected code)", name, 4))
                elif kind in ("html", "htaccess"):
                    hits.append((C, line_no, "PHP code inside a non-PHP file (%s)" % kind, name, 15))
                else:
                    if not (name.lower().endswith(".phpt") or raw[:2] == b"#!"):
                        hits.append((O, line_no, "PHP tag inside a %s file" % (kind or "non-PHP"), name, 6))
        else:
            if raw[:4] in (b"GIF8",) or raw[:3] == b"\xff\xd8\xff" or raw[:4] == b"\x89PNG":
                hits.append((C, 1, "image magic bytes at the start of a PHP file", name, 25))
            hits += location_hits(rel, name, st.st_size, text[:300])
            hits += php_anomalies(raw, text, os.path.dirname(path), rel)
            if name.lower() == "configuration.php" and "/" not in rel:
                hits += config_hits(text)
            if cfg["posix"] and (stat.S_IMODE(st.st_mode) & 0o002):
                hits.append((O, 0, "world-writable PHP file (%04o)" % stat.S_IMODE(st.st_mode), name, 4))
        hits += scan_text(text, kinds, enabled)
        hits += blob_hits(rel, name, kind, raw)
        if name.lower().endswith(".xml"):
            hits += manifest_author_hits(rel, text, cfg["baseline_dirs"])

    hits = [h for h in hits if h[0] in enabled]
    for reason in yara_gaps:               # an engine blind spot must never be silent (TZ v2 6.2):
        hits.append((W, 0, "YARA rules did not fully scan this file: " + reason, "", 5))
    if not hits:
        return None, "scanned"
    if sha is None:
        sha = hashlib.sha256(raw).hexdigest()
    return make_result(rel, st, sha, hits, mm, gaps=yara_gaps), "scanned"


def scan_batch(paths):
    if not CFG:     # a worker that never got its configuration must fail loudly, not report "error" for every file
        raise RuntimeError("scanner worker is not initialised (no configuration)")
    results, counters = [], Counter()
    engines_on = bool(get_engines(CFG))   # coverage accounting for the extra engines (TZ v2 6.4)
    for p in paths:
        try:
            res, status = scan_file(p)
        except Exception:     # one bad file must not crash the whole scan
            res, status = None, "error"
        counters[status] += 1
        if engines_on and status == "scanned":
            if res is not None and res.get("gaps"):
                counters["yara_gap"] += 1
            else:
                counters["yara_ok"] += 1
        if res:
            results.append(res)
    return results, dict(counters)


def scan_batch_cfg(args):
    """Pool entry point for Python < 3.7 (no pool initializer): the configuration travels with the batch.
    Needed wherever workers are spawned rather than forked (Windows)."""
    paths, cfg = args
    if not CFG:
        _init(cfg)
    return scan_batch(paths)


# ---------------------------------------------------------------------------
# 5) REPORTS: CSV / JSON / XLSX (xlsx is a zip of XML, built by hand)
# ---------------------------------------------------------------------------

def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


# The vulnerability section/columns. Deliberately not the columns of the findings
# table: a CVE has no line, no snippet and nothing to delete.
VULN_CSV_HEADER = ["CVE", "CVSS", "Severity", "Known exploited", "Component", "Type",
                   "Component version", "Version source", "Fixed in", "Confidence",
                   "Source", "Component folder", "Summary"]


def vuln_csv_row(row):
    return [row.get("cve") or "", row.get("cvss") if row.get("cvss") is not None else "",
            row.get("severity") or "", "yes" if row.get("kev") else "no",
            row.get("component") or "", row.get("type") or "",
            row.get("component_version") or "", row.get("version_source") or "",
            row.get("fixed_in") or "", row.get("confidence") or "", row.get("source") or "",
            row.get("path") or "", row.get("summary") or ""]


def write_csv(path, results):
    with io.open(path, "w", newline="", encoding="utf-8-sig", errors="replace") as f:
        w = csv.writer(f)
        w.writerow(["Score", "Verdict", "Severity", "File", "Line", "Signature", "Snippet",
                    "Size", "Modified", "Delete", "SHA-256"])
        for r in results:
            for sev, line, label, snip, _w in r["hits"]:
                w.writerow([r["score"], r["verdict"], sev, csv_safe(r["path"]), line or "",
                            label, csv_safe(snip), r["size"], fmt_time(r["mtime"]), "No", r["sha256"]])


def vulnerabilities_csv_path(csv_path):
    """Where the vulnerability table goes when --csv is also asked for.

    Not a block appended to the findings CSV: that file is read back by the GUI
    and by other people's tools with a header-first parser, and a second table in
    it would be read as malformed findings. An outdated plugin is a different kind
    of answer, so it comes as a different file.
    """
    base, ext = os.path.splitext(csv_path)
    if not ext or len(ext) > 6:
        ext = ".csv"
    return base + "-vulnerabilities" + ext


def write_vulnerabilities(path, vulns):
    """The vulnerability verdicts as their own CSV (the standalone form)."""
    with io.open(path, "w", newline="", encoding="utf-8-sig", errors="replace") as f:
        w = csv.writer(f)
        w.writerow(VULN_CSV_HEADER)
        for row in vulns:
            w.writerow([csv_safe(v) if isinstance(v, str) else
                        ("" if v is None else v) for v in vuln_csv_row(row)])


def audit_for_report(audit):
    """The audit as JSON-safe data for --json/--xlsx.

    `verified_paths` is the internal list of files proven identical to the release
    (thousands of strings, useful only inside this run): it is replaced by a count.
    """
    if not audit:
        return None
    data = {"inventory": audit.get("inventory_summary"),
            "inventory_detail": audit.get("inventory"),
            "integrity": None, "vulnerabilities": audit.get("vulnerabilities") or [],
            "vulnerability_summary": audit.get("vuln_summary"),
            "notes": list(audit.get("notes") or [])}
    integrity = audit.get("integrity")
    if integrity:
        # the rows (paths and hashes) plus the counts: a reader who only wants the
        # numbers should not have to count arrays, and one who wants the files must
        # not have to look in two places
        data["integrity"] = {key: value for key, value in integrity.items()
                             if key != "verified_paths"}
        data["integrity"]["summary"] = audit.get("integrity_summary") or {}
        data["integrity"]["verified_for_skipping"] = len(integrity.get("verified_paths") or ())
    return data


def write_json(path, results, stats, audit=None):
    data = {"version": VERSION, "stats": stats, "files": [{
        "path": r["path"], "score": r["score"], "verdict": r["verdict"], "size": r["size"],
        "modified": fmt_time(r["mtime"]), "mode": r["mode"], "sha256": r["sha256"],
        "counts": r["counts"], "hidden_hits": r["hidden"],
        "hits": [{"severity": h[0], "line": h[1], "signature": h[2], "snippet": h[3]} for h in r["hits"]],
    } for r in results]}
    extra = audit_for_report(audit)
    if extra:
        data["inventory"] = extra.pop("inventory_detail", None)
        data["inventory_summary"] = extra.pop("inventory", None)
        data["integrity"] = extra.pop("integrity", None)
        data["vulnerabilities"] = extra.pop("vulnerabilities", [])
        data["vulnerability_summary"] = extra.pop("vulnerability_summary", None)
        data["audit_notes"] = extra.pop("notes", [])
    with io.open(path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def uri_of(p):
    p = (p or "").replace(os.sep, "/")
    if not p:
        return ""
    return ("file:///" if re.match(r"^[A-Za-z]:/", p) else "file://") + p


def write_sarif(path, results, stats, audit=None):
    """SARIF 2.1.0 report so the findings can be imported into code-scanning
    tools (GitHub code scanning, Azure DevOps, CodeQL CLI upload).

    One result per finding: the rule is the signature label, the level follows
    the severity (CRITICAL -> error, OBFUSCATED -> warning, WARNING -> note),
    the location is the file with the line of the finding when the check has one.

    A vulnerability is a result of its own with `ruleId` = the CVE and the
    component's folder as its location: a CVE has no line in a file, and the path
    is site-relative for the same reason the rest of the report is.
    """
    rules, artifacts, sarif_results = {}, [], []
    for r in results:
        artifacts.append({"uri": r["path"], "uriBaseId": "%SRCROOT%", "length": r["size"]})
        for sev, line, label, snip, _w in r["hits"]:
            if label not in rules:
                rules[label] = {"id": label, "name": label,
                                "shortDescription": {"text": label},
                                "defaultConfiguration": {"level": SEV_SARIF[sev]}}
            location = {"artifactLocation": {"uri": r["path"], "uriBaseId": "%SRCROOT%"}}
            if line:
                location["region"] = {"startLine": line, "endLine": line}
            message = label + ((" - %s" % snip) if snip else "")
            sarif_results.append({"ruleId": label, "level": SEV_SARIF[sev],
                                  "message": {"text": message},
                                  "locations": [{"physicalLocation": location}]})
    for row in (audit or {}).get("vulnerabilities") or []:
        rule_id = row.get("cve") or ("unpinned-%s-%s" % (row.get("type"), row.get("component")))
        level = CVE_SARIF_LEVEL.get(row.get("severity") or "unknown", "note")
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "name": rule_id,
                              "shortDescription": {"text": row.get("summary") or rule_id},
                              "helpUri": "https://www.cve.org/CVERecord?id=%s" % rule_id,
                              "defaultConfiguration": {"level": level}}
        component = "%s %s %s" % (row.get("type") or "?", row.get("component") or "?",
                                  row.get("component_version") or "(version unknown)")
        message = "%s: %s%s" % (rule_id, component,
                                " - fixed in %s" % row["fixed_in"] if row.get("fixed_in")
                                else " - no published fix")
        entry = {"ruleId": rule_id, "level": level, "message": {"text": message}}
        if row.get("path"):
            entry["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": row["path"], "uriBaseId": "%SRCROOT%"}}}]
        sarif_results.append(entry)
    root = uri_of(stats.get("Scanned folder"))
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ScanBackDoors", "version": VERSION,
                                "rules": [rules[k] for k in rules]}},
            "originalUriBaseInfos": [{"id": "%SRCROOT%", "uri": root}] if root else [],
            "artifacts": artifacts,
            "results": sarif_results,
        }],
    }
    with io.open(path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)


def col_letter(n):
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def x_esc(s):
    s = CTRL_RE.sub("", s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cell_xml(ref, v):
    style = 0
    if isinstance(v, tuple):
        v, style = v
    s_attr = ' s="%d"' % style if style else ""
    if v is None or v == "":
        return '<c r="%s"%s/>' % (ref, s_attr) if style else ""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return '<c r="%s"%s><v>%s</v></c>' % (ref, s_attr, repr(v))
    return '<c r="%s"%s t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (
        ref, s_attr, x_esc(str(v)[:32000]))


def sheet_xml(rows, widths):
    out = []
    for ri, row in enumerate(rows, 1):
        cells = "".join(cell_xml("%s%d" % (col_letter(ci), ri), v) for ci, v in enumerate(row, 1))
        out.append('<row r="%d">%s</row>' % (ri, cells))
    cols = "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i, i, w)
                   for i, w in enumerate(widths, 1))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
            'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
            '<cols>%s</cols><sheetData>%s</sheetData></worksheet>' % (cols, "".join(out)))


STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    '<fills count="6"><fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFD9D9D9"/><bgColor indexed="64"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/><bgColor indexed="64"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFE0B2"/><bgColor indexed="64"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill></fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="5">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>'
    '<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>'
    '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    '</styleSheet>')


def write_xlsx(path, sheets):
    """sheets: [(name, rows, widths)]. A cell = a value or (value, style 1..4)."""
    n = len(sheets)
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
          + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % (i + 1) for i in range(n))
          + '</Types>')
    root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                 '</Relationships>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
          + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (x_esc(s[0]), i + 1, i + 1) for i, s in enumerate(sheets))
          + '</sheets></workbook>')
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1) for i in range(n))
               + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (n + 1)
               + '</Relationships>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", STYLES_XML)
        for i, (_n, rows, widths) in enumerate(sheets):
            z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), sheet_xml(rows, widths))


XLSX_MAX_ROWS = 1048000
SEV_STYLE = {SEV_CRIT: 2, SEV_OBF: 3, SEV_WARN: 4}
VERDICT_STYLE = {"HIGH": 2, "MEDIUM": 3, "LOW": 4}


def build_xlsx(path, results, stats, audit=None):
    files = [[(h, 1) for h in ("Score", "Verdict", "File", "Size, B", "Modified", "Delete", "SHA-256",
                               "CRITICAL", "OBFUSCATED", "WARNING", "Main signatures")]]
    for r in results:
        top = "; ".join(sorted(set(h[2] for h in r["hits"][:6])))
        files.append([r["score"], (r["verdict"], VERDICT_STYLE[r["verdict"]]), r["path"], r["size"],
                      fmt_time(r["mtime"]), "No", r["sha256"],
                      r["counts"].get(SEV_CRIT, 0), r["counts"].get(SEV_OBF, 0),
                      r["counts"].get(SEV_WARN, 0), top])
    hits = [[(h, 1) for h in ("Score", "Severity", "File", "Line", "Signature", "Snippet", "Modified")]]
    truncated = False
    for r in results:
        for sev, line, label, snip, _w in r["hits"]:
            if len(hits) >= XLSX_MAX_ROWS:
                truncated = True
                break
            hits.append([r["score"], (sev, SEV_STYLE[sev]), r["path"], line or "", label, snip,
                         fmt_time(r["mtime"])])
    summ = [[("Parameter", 1), ("Value", 1)]]
    for k, v in stats.items():
        summ.append([k, v])
    if truncated:
        summ.append(["NOTE", "Hits sheet truncated (Excel row limit); use --csv/--json for full data"])
    sheets = [("Files", files[:XLSX_MAX_ROWS], [8, 10, 60, 10, 17, 7, 66, 11, 9, 9, 60]),
              ("Hits", hits, [8, 14, 60, 7, 42, 90, 17])]
    vulns = (audit or {}).get("vulnerabilities") or []
    if vulns:
        # a sheet of its own: an outdated component is not a row of the findings
        # table, and mixing them invites someone to "quarantine" a CVE
        sheet = [[(h, 1) for h in VULN_CSV_HEADER]]
        for row in vulns[:XLSX_MAX_ROWS - 1]:
            sheet.append(list(vuln_csv_row(row)))
        sheets.append(("Vulnerabilities", sheet,
                       [16, 6, 9, 15, 26, 10, 16, 14, 10, 11, 16, 34, 60]))
    sheets.append(("Summary", summ, [28, 50]))
    write_xlsx(path, sheets)



# -------------------------------------------------------------------------------
# AI/user-prepared detection signatures (written by the GUI; see --user-signatures)
# -------------------------------------------------------------------------------
USER_SIG_KINDS = ("php", "js", "html", "htaccess", "ini", "text")
USER_SIG_SEVERITIES = {"critical": SEV_CRIT, "obfuscated": SEV_OBF, "warning": SEV_WARN}


def _user_sig_text(value):
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value or "")


def _user_sig_label(value):
    label = _user_sig_text(value).strip()
    if len(label) < 2:
        raise ValueError("label is empty or too short (need at least 2 characters)")
    if len(label) > 200:
        raise ValueError("label is too long (%d chars, max 200)" % len(label))
    return label


def _user_sig_severity(value):
    v = _user_sig_text(value).strip().lower().strip("[]")
    if v == "obs":
        v = "obfuscated"
    if v not in USER_SIG_SEVERITIES:
        raise ValueError("severity %r is not one of 'critical', 'obfuscated' or 'warning'" % (value,))
    return USER_SIG_SEVERITIES[v]


def _user_sig_kinds(value):
    kinds = [k.strip().lower() for k in _user_sig_text(value).split()]
    kinds = [k for k in kinds if k]
    if not kinds or any(k not in USER_SIG_KINDS for k in kinds):
        raise ValueError("kinds %r are not valid (allowed: %s)" % (value, ", ".join(USER_SIG_KINDS)))
    return " ".join(dict.fromkeys(kinds))


def _user_sig_pattern(value):
    pattern = _user_sig_text(value).strip()
    if len(pattern) < 2:
        raise ValueError("pattern is empty or too short (need at least 2 characters)")
    if len(pattern) > 400:
        raise ValueError("pattern is too long (%d chars, max 400)" % len(pattern))
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        raise ValueError("pattern is not a valid regex: %s" % exc)
    for probe in ("", " "):
        if rx.search(probe):
            raise ValueError("pattern matches an empty or whitespace-only string - it would fire on every file")
    return pattern


def _user_sig_flags_text(value):
    v = str(value or "").strip().lower()
    if v in ("i", "ignorecase", "case_insensitive", "1", "true", "yes"):
        return re.I
    if v in ("", "none", "0", "false", "no", "ci"):
        return 0
    raise ValueError("flags %r are not supported (only case-sensitive or case-insensitive)" % (value,))


def _user_sig_flags(item):
    c = item.get("case_insensitive", None)
    if c is not None:
        if isinstance(c, bool):
            return re.I if c else 0
        return _user_sig_flags_text(c)
    return _user_sig_flags_text(item.get("flags", "i"))


def _user_sig_weight(value):
    if value is None or value == "":
        return None   # let S() apply the per-severity default
    try:
        w = int(value)
    except (TypeError, ValueError):
        raise ValueError("weight must be an integer, got %r" % (value,))
    if not 1 <= w <= 30:
        raise ValueError("weight %d is out of the 1-30 range" % w)
    return w


def load_user_signatures(path):
    """-> (entries, problems). Same contract as load_whitelist: a malformed
    entry is reported and skipped, never silently swallowed.

    Entries are validated here so the scanner can never crash or flood the
    scan with a broken pattern."""
    with io.open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, dict):
        entries = data.get("signatures")
    else:
        entries = data
    if not isinstance(entries, list):
        raise ValueError("expected a JSON list of signatures (or an object with a 'signatures' list)")
    out, problems = [], []
    for i, item in enumerate(entries):
        try:
            if not isinstance(item, dict):
                raise ValueError("entry is not an object")
            label = _user_sig_label(item.get("label"))
            severity = _user_sig_severity(item.get("severity"))
            kinds = _user_sig_kinds(item.get("kinds"))
            pattern = _user_sig_pattern(item.get("pattern"))
            weight = _user_sig_weight(item.get("weight"))
            flags = _user_sig_flags(item)
            out.append({"label": label, "pattern": pattern, "severity": severity,
                        "kinds": kinds, "weight": weight, "flags": flags,
                        "reason": _user_sig_text(item.get("reason"))[:400],
                        "created": _user_sig_text(item.get("created"))[:60]})
        except ValueError as exc:
            problems.append((i + 1, str(exc), str(item)[:60]))
    return out, problems


def register_user_signatures(entries):
    """Add the validated signatures to the scanner and keep the heaviest first."""
    for e in entries:
        try:
            S(e["severity"], e["label"], e["pattern"], e["kinds"], e["weight"], e["flags"])
        except (ValueError, re.error) as exc:
            print("user-signatures: %r - ignored: %s" % (e.get("label"), exc))
    for k in SIGS_BY_KIND:
        SIGS_BY_KIND[k].sort(key=lambda t: (SEV_RANK[t[0]], -t[3]))


# ---------------------------------------------------------------------------
# 6) MAIN
# ---------------------------------------------------------------------------

def parse_since(s):
    m = re.match(r"^(\d+)d$", s.strip())
    if m:
        return time.time() - int(m.group(1)) * 86400
    return time.mktime(datetime.strptime(s.strip(), "%Y-%m-%d").timetuple())


def load_whitelist(path):
    """-> (sha256 set, path patterns, problems).

    problems is a list of (line number, reason, snippet). A malformed line (a hex
    string of another length, binary garbage) is reported and skipped instead of
    being silently swallowed: a lost suppression is a false positive, not a missed
    threat, so the scan must go on."""
    hashes, paths, problems = set(), [], []
    with io.open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            if re.match(r"^[0-9a-fA-F]{64}$", body):
                hashes.add(body.lower())
            elif re.match(r"^[0-9a-fA-F]+$", body):
                problems.append((line_no, "hex string with %d chars (a SHA-256 needs 64)" % len(body), body))
            elif "\ufffd" in body or any(ord(c) < 32 or c == "\x7f" for c in body):
                problems.append((line_no, "unprintable content", body[:60]))
            else:
                paths.append(re.sub(r"^(?:\./|/)+", "", body.replace("\\", "/")))
    return hashes, paths, problems


def build_baseline(clean_dir):
    """sha256 of every .php in the clean tree. Fast path: the hash manifest that
    joomla_baseline.py writes next to the tree it downloaded (Joomla_<v>.baseline.json) -
    the hashes were computed right after the download, so a re-scan does not re-read
    thousands of files. Files that are in the tree but not in the manifest are hashed
    normally, so a hand-edited baseline can never make modified core files look clean."""
    base = {}
    nd = os.path.normpath(clean_dir)
    mf = os.path.join(os.path.dirname(nd), os.path.basename(nd) + ".baseline.json")
    manifest = None
    try:
        with open(mf, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("files"), dict) and data["files"]:
            manifest = data["files"]
    except (OSError, ValueError):
        manifest = None
    reused = 0
    extra = 0
    for root, _dirs, files in os.walk(clean_dir):
        for name in files:
            if not name.lower().endswith(".php"):
                continue
            rel = os.path.relpath(os.path.join(root, name), clean_dir).replace(os.sep, "/")
            if manifest is not None and rel in manifest:
                base[rel] = str(manifest[rel])
                reused += 1
                continue
            extra += 1
            p = os.path.join(root, name)
            try:
                with open(p, "rb") as fh:
                    base[rel] = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                pass
    if manifest is not None:
        print("  baseline hashes: %d reused from the manifest, %d hashed now" % (reused, extra))
    return base


def baseline_dir_set(clean_dir):
    """Folders that exist in the clean distribution (lower-cased paths relative to its root)."""
    s = set()
    for root, dirs, _files in os.walk(clean_dir):
        for d in dirs:
            s.add(os.path.relpath(os.path.join(root, d), clean_dir).replace(os.sep, "/").lower())
    return s


def detect_cms(start):
    """Best-effort CMS detection from the well-known files in the site root.
    Some heuristics (Joomla credential harvester, wp-* names, WP core folders)
    only make sense for one CMS, so they are gated on the detected CMS."""
    try:
        entries = {e.lower() for e in os.listdir(start)}
    except OSError:
        return None
    # One planted file must not flip the decision (it would switch off the CMS-specific
    # checks for the whole site): WordPress needs a marker file AND both core folders,
    # and conflicting evidence means "ambiguous", which suppresses nothing.
    wp = bool(entries & {"wp-config.php", "wp-load.php", "wp-settings.php"}) \
        and {"wp-includes", "wp-admin"} <= entries
    joomla = "configuration.php" in entries or "administrator" in entries
    if wp and joomla:
        return "ambiguous"
    if wp:
        return "wp"
    if joomla:
        return "joomla"
    return None


def iter_paths(start, excl_dirs):
    for root, dirs, files in os.walk(start):
        if excl_dirs:
            dirs[:] = [d for d in dirs if d not in excl_dirs]
        for d in dirs:                       # os.walk lists a symlink to a folder here and never enters it
            p = os.path.join(root, d)
            if os.path.islink(p):
                yield p                      # scan_file reports it as "symlink inside web root"
        for n in files:
            yield os.path.join(root, n)


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ---------------------------------------------------------------------------
# 4b) CMS AUDIT - inventory, WordPress integrity, known vulnerabilities
#
# This is the only part of the scan that can reach the network, and it does so
# only when the user asked for it with --online (the warning printed before the
# first request says exactly which two services see which pieces of data). The
# engines behind it are engines/inventory.py, engines/integrity_wp.py and
# engines/vuln_engine.py; this file only decides severity, exit codes and how it
# is printed.
# ---------------------------------------------------------------------------

# The weight an integrity verdict contributes to the file's score. A modified
# core file or a new PHP file inside wp-admin is not a hint, it is the finding.
INTEGRITY_VERDICTS = {"modified": (SEV_CRIT, 30),
                      "extra-code": (SEV_CRIT, 40),
                      "extra-file": (SEV_WARN, 6)}

FAIL_ON_LEVELS = ("critical", "high", "medium")


def audit_dirs(args):
    """(cache folder, local database path) - both in the data folder, never in the site."""
    root = data_root()
    return (os.path.join(root, "audit-cache"),
            os.path.abspath(os.path.expanduser(args.vuln_db)) if args.vuln_db
            else os.path.join(root, "audit", "vulnerabilities.json"))


def audit_notice(online, cache_dir, say):
    """What --online gives away. Said once, before the first request, in plain words."""
    if not online:
        say("audit: no requests will be made; answers cached in %s (one day) are still used "
            "(add --online to ask the two services)" % cache_dir)
        return
    say("audit: ONLINE. This run sends out:")
    say("  - the WordPress version it found -> api.wordpress.org (official checksums);")
    say("  - every plugin/theme slug and version it found -> api.wpvulnerability.com.")
    say("  Nothing else leaves this machine and nothing is uploaded; answers are cached")
    say("  for a day in %s, so the next run of this site works offline." % cache_dir)


def run_integrity(start, inventory, client, notes, say):
    """WordPress core against the official checksums, or a reason why not."""
    cms = inventory.get("cms")
    if cms != "wordpress":
        say("integrity: implemented for WordPress (a Joomla site is compared with a clean "
            "distribution through --baseline-dir)")
        return None
    version = (inventory.get("cms_version") or {}).get("version") or ""
    if not audit_net_api.valid_wp_version(version):
        notes.append("integrity: the WordPress version is unknown, so the official catalogue "
                     "could not be asked")
        say("integrity: the WordPress version is unknown - nothing to compare against")
        return None
    try:
        checksums = audit_net_api.core_checksums(client, version)
    except audit_net_api.OfflineMode:
        notes.append("integrity: the official checksums of WordPress %s are not cached: "
                     "run this once with --online" % version)
        say("integrity: needs --online the first time (the catalogue is then cached for a day "
            "in the data folder)")
        return None
    except audit_net_api.AuditError as exc:
        notes.append("integrity: %s" % exc)
        say("integrity: %s" % exc)
        return None
    if not checksums:
        notes.append("integrity: api.wordpress.org has no checksums for WordPress %s" % version)
        say("integrity: no official checksums exist for WordPress %s" % version)
        return None
    report = integ_api.check_core(start, checksums, version=version)
    got = integ_api.summarize(report)
    say("integrity: %d file(s) match WordPress %s; modified %d, extra %d, missing %d"
        % (got["verified"], version, got["modified"], got["extra"], got["missing"]))
    if got["unreadable"]:
        say("integrity: %d file(s) could not be hashed (size limit or permissions)"
            % got["unreadable"])
    if got["soft"]:
        say("integrity: %d file(s) differ but do not count as suspicious "
            "(readme/licence are translated)" % got["soft"])
    if not report["complete"]:
        say("integrity: INCOMPLETE - not every core file could be compared")
    return report


def run_cve_audit(inventory, client, db_path, integrity_report, notes, say, online):
    """Known vulnerabilities of the inventoried components, local first."""
    if os.path.isfile(db_path):
        entries, problems = vuln_api.load_database(db_path)
    else:
        entries, problems = [], ["the local vulnerability database is not installed (%s)" % db_path]
    for problem in problems:
        notes.append("vulnerabilities: %s" % problem)
    findings, audit_notes = vuln_api.audit(inventory, entries=entries, client=client,
                                           integrity=integrity_report)
    notes.extend("vulnerabilities: %s" % n for n in audit_notes)
    say("vulnerabilities: %d verdict(s) (local database: %d entries%s)"
        % (len(findings), len(entries), ", service: asked" if online else ", service: not asked"))
    shown = skipped = 0
    for row in findings:
        if row.get("confidence") == "low" and shown >= 5:
            skipped += 1
            continue
        if shown >= 15:
            skipped += 1
            continue
        say("  %-8s %-14s %-12s %s  %s%s" % (
            row.get("severity") or "?", row.get("cve") or "-",
            "%s/%s" % (row.get("type"), row.get("component")),
            row.get("component_version") or "(version unknown)",
            "KEV " if row.get("kev") else "",
            ("fixed in %s" % row["fixed_in"]) if row.get("fixed_in") else "no published fix"))
        shown += 1
    if skipped:
        say("  … %d more (the full list is in the report)" % skipped)
    return findings


def cms_audit(start, args, emit):
    """Everything the CMS audit produces: data for the reports, text for the console.

    The console lines are returned instead of printed: the findings of the file
    scan come first in the output, and the audit is secondary news.
    """
    out = {"inventory": None, "inventory_summary": None, "integrity": None,
           "integrity_summary": {"checked": False}, "vulnerabilities": [],
           "vuln_summary": None, "notes": [], "lines": []}
    if inv_api is None:
        return out
    say = out["lines"].append
    wanted = [name for name, on in (("inventory", args.inventory),
                                    ("integrity", args.check_integrity),
                                    ("cve audit", args.audit_cve)) if on]
    say("=" * 64)
    say("CMS AUDIT (%s)" % ", ".join(wanted))
    emit("PHASE", "audit")
    cache_dir, db_path = audit_dirs(args)
    online = bool(args.online)
    client = None
    if args.check_integrity or args.audit_cve:
        client = audit_net_api.AuditClient(cache_dir=cache_dir, allow_network=online)
        audit_notice(online, cache_dir, say)
    out["inventory"] = inv_api.build_inventory(start)
    summary = inv_api.summarize(out["inventory"])
    out["inventory_summary"] = summary
    name = {"wordpress": "WordPress", "joomla": "Joomla"}.get(summary["cms"], "no supported CMS")
    say("  CMS: %s%s" % (name, " %s" % summary["cms_version"] if summary["cms_version"]
                         else " (version unknown)"))
    if summary["components"]:
        say("  components: %s" % ", ".join(
            "%s %d" % (kind, count) for kind, count in sorted(summary["components"].items())))
    if summary["unknown_versions"]:
        say("  components without a declared version: %d (reported as unauditable, not as clean)"
            % summary["unknown_versions"])
    if args.check_integrity:
        out["integrity"] = run_integrity(start, out["inventory"], client, out["notes"], say)
        out["integrity_summary"] = integ_api.summarize(out["integrity"])
    if args.audit_cve:
        out["vulnerabilities"] = run_cve_audit(out["inventory"], client, db_path,
                                               out["integrity"], out["notes"], say, online)
        out["vuln_summary"] = vuln_api.summarize(out["vulnerabilities"])
    if client is not None:
        out["notes"].extend("audit: %s" % note for note in client.notes)
        say("  requests made: %d, answered from the cache: %d"
            % (client.requests, client.cache_hits))
    for note in _collapsed(out["notes"]):
        say("  note: %s" % note)
    out["notes"] = _collapsed(out["notes"])
    return out


def _collapsed(notes):
    """The same complaint from five components is one line with a count."""
    order, counts = [], {}
    for note in notes:
        if note not in counts:
            counts[note] = 0
            order.append(note)
        counts[note] += 1
    return [note if counts[note] == 1 else "%s (x%d)" % (note, counts[note]) for note in order]


def integrity_into_results(results, integrity, start, args):
    """Integrity verdicts become ordinary findings on the affected file.

    A modified core file must appear in the table with a score and the same
    actions any other suspicious file has. The weight is added on top of the
    file's own score, which can exceed the usual cap for its severity: deliberate
    - a file that is not what WordPress published is never a low-priority file.
    A missing file cannot be quarantined (there is nothing to act on), so it stays
    in the integrity section of the report instead of becoming a phantom row.
    """
    if not integrity:
        return 0
    rows = []
    for row in integrity.get("modified") or []:
        rows.append((row["path"], "modified WordPress core file",
                     "the official %s checksum is %s, the site has %s"
                     % (integrity.get("version"), row["expected"][:12], row["actual"][:12]),
                     "modified"))
    for row in integrity.get("extra") or []:
        rows.append((row["path"],
                     "file the official WordPress release does not ship",
                     "WordPress %s has no %s" % (integrity.get("version") or "?", row["path"]),
                     "extra-code" if row["php"] else "extra-file"))
    by_path = {r["path"]: r for r in results}
    added = 0
    for rel, label, detail, kind in rows:
        sev, weight = INTEGRITY_VERDICTS[kind]
        hit = (sev, 0, label, detail, weight)
        existing = by_path.get(rel)
        if existing is not None:
            existing["hits"].append(hit)
            existing["counts"][sev] = existing["counts"].get(sev, 0) + 1
            existing["score"] += weight
            existing["verdict"] = verdict_of(existing["score"])
            continue
        path = os.path.join(start, *rel.split("/"))
        try:
            st = os.lstat(path)
            with open(path, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            continue                       # vanished while we looked: nothing to report on
        result = make_result(rel, st, sha, [hit], args.max_matches)
        results.append(result)
        by_path[rel] = result
        added += 1
    return added


# ---------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------

def _selftest_root():
    """The unsealed payloads look like real web shells: keep them where an antivirus
    exclusion already exists (%TEMP%\\sbd-fixtures), fall back to the system temp."""
    root = os.path.join(tempfile.gettempdir(), "sbd-fixtures")
    try:
        os.makedirs(root, exist_ok=True)
        return root
    except OSError:
        return None


def self_test():
    """Built-in liveness check: unseal the embedded payloads into a throwaway site and
    run each one through the detection engine. No network, no real site needed."""
    print("scan_backdoors %s | self-test" % VERSION)
    work = tempfile.mkdtemp(prefix="sbd-selftest-", dir=_selftest_root())
    ok = 0
    try:
        _init({
            "start": work, "max_size": 16 * 1024 * 1024, "max_matches": 10,
            "since": None, "enabled": {SEV_CRIT, SEV_OBF, SEV_WARN},
            "wl_hashes": set(), "wl_paths": [], "baseline": None,
            "baseline_dirs": set(), "skip_paths": set(), "baseline_pkgs": set(),
            "posix": os.name != "nt", "exclude_ext": set(), "cms": None,
        })
        for rel, b64, expected in SELFTEST:
            path = os.path.join(work, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64))
            res, _status = scan_file(path)
            labels = [h[2] for h in res["hits"]] if res else []
            missing = [e for e in expected if e not in labels]
            if res and not missing:
                ok += 1
                print("  [PASS] %s: %s" % (rel, ", ".join("'%s'" % e for e in expected)))
            else:
                found = ", ".join("'%s'" % l for l in labels[:4]) or "nothing"
                print("  [FAIL] %s: expected %s, got %s"
                      % (rel, ", ".join("'%s'" % e for e in missing), found))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("self-test: %d of %d checks passed" % (ok, len(SELFTEST)))
    return 0 if ok == len(SELFTEST) else 1


def build_parser():
    ap = argparse.ArgumentParser(description="Backdoor/web shell scanner for Joomla/PHP sites, v" + VERSION)
    ap.add_argument("start", nargs="?", default=".", help="folder to scan (default: the current one)")
    ap.add_argument("--max-matches", type=int, default=60, help="max findings of one level per file in the report (60)")
    ap.add_argument("--max-size", type=float, default=5, help="max file size, MB (5)")
    ap.add_argument("--csv", default="report-data.csv", help="CSV report path (default report-data.csv)")
    ap.add_argument("--no-csv", action="store_true", help="do not create the CSV")
    ap.add_argument("--xlsx", help="additionally save the report as XLSX")
    ap.add_argument("--json", help="save the full report as JSON")
    ap.add_argument("--sarif", help="save the report as SARIF 2.1.0 (for CI code scanning)")
    ap.add_argument("--since", help="only files modified later than: 2026-09-01 or 14d (last 14 days)")
    ap.add_argument("--only-critical", action="store_true", help="search only for [CRITICAL]")
    ap.add_argument("--no-warnings", action="store_true", help="do not search for [WARNING]")
    ap.add_argument("--min-score", type=int, default=0, help="show files with a score not lower than N")
    ap.add_argument("--exclude-ext", default="", help="comma-separated extensions: .js,.json")
    ap.add_argument("--exclude-dir", default="", help="comma-separated folder names (ALL folders are scanned by default)")
    ap.add_argument("--whitelist", help="file: SHA-256, paths, folders (with a trailing /) or masks *; # - comment")
    ap.add_argument("--user-signatures", help="JSON file of AI/user-prepared signatures (label/pattern/severity/kinds/weight/flags); malformed entries are reported and skipped")
    ap.add_argument("--audit-whitelisted", action="store_true",
                    help="do not skip files that match a whitelist PATH/folder/mask: scan them and report [CRITICAL] only")
    ap.add_argument("--strict", action="store_true",
                    help="exit code 3 when files could not be processed (the scan is incomplete) and nothing critical was found")
    ap.add_argument("--baseline-dir", help="folder with a CLEAN Joomla of the same version (where index.php lives)")
    ap.add_argument("--yara-rules", help="a .yar file or a folder of .yar/.yara files run as an extra engine "
                                         "(needs yara-python: requirements-optional.txt); broken rule files "
                                         "are reported and skipped")
    ap.add_argument("--no-yara", action="store_true", help="never run the YARA engine, even with --yara-rules")
    ap.add_argument("--yara-cache", default="", help="folder for the compiled .yarac cache "
                                                     "(default: yarac in the data folder - $SBD_DATA_DIR or ~/.scan_backdoors)")
    ap.add_argument("--no-yara-cache", action="store_true", help="do not read or write the .yarac cache")
    ap.add_argument("--yara-timeout", type=float, default=5.0,
                    help="YARA time limit per file in seconds (5): a file that hits the limit is reported "
                         "as a scan gap, never as clean")
    ap.add_argument("--inventory", action="store_true",
                    help="inventory the CMS and its components (WordPress/Joomla): what is installed "
                         "and which version the component declares")
    ap.add_argument("--check-integrity", action="store_true",
                    help="compare WordPress core files with the official checksums: modified, extra and "
                         "missing files; the catalogue is fetched once and cached for a day in the data folder")
    ap.add_argument("--audit-cve", action="store_true",
                    help="report the known vulnerabilities of the inventoried components (local database, "
                         "and with --online also WPVulnerability). They are a section of their own and are "
                         "never offered for quarantine/delete")
    ap.add_argument("--online", action="store_true",
                    help="allow the two pinned services (api.wordpress.org, api.wpvulnerability.com) that "
                         "--check-integrity/--audit-cve need; without it only the one-day cache and the "
                         "local database are used, and the scanner says what it could not check")
    ap.add_argument("--vuln-db",
                    help="local vulnerability database (JSON, schema 2) for --audit-cve "
                         "(default: audit/vulnerabilities.json in the data folder)")
    ap.add_argument("--fail-on", choices=FAIL_ON_LEVELS,
                    help="exit code 4 when a vulnerability verdict reaches this severity; "
                         "without it a CVE never changes the exit code")
    ap.add_argument("--workers", type=int, default=0, help="number of processes (0 = auto, 1 = no parallelism)")
    ap.add_argument("--no-progress", action="store_true", help="no progress indicator")
    ap.add_argument("--progress-lines", action="store_true",
                    help="machine-readable lines @@PROGRESS/@@FILE/@@STATS for the GUI (works without a terminal too)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in liveness check on the embedded test payloads and exit")
    ap.add_argument("--version", action="version", version="scan_backdoors " + VERSION)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if args.no_csv:
        args.csv = None
    audit_wanted = bool(args.inventory or args.check_integrity or args.audit_cve)
    if audit_wanted and inv_api is None:
        print("CMS audit: this build has no engines/ package next to it - "
              "run the scanner from the repository or copy the engines folder too")
        return 1
    if args.fail_on and not args.audit_cve:
        print("--fail-on only means something together with --audit-cve")
        return 1
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
    def emit(tag, payload=""):
        if args.progress_lines:
            print("@@%s %s" % (tag, payload), flush=True)

    start = os.path.abspath(args.start)
    if not os.path.isdir(start):
        print("Folder not found:", start)
        return 1

    enabled = {SEV_CRIT, SEV_OBF, SEV_WARN}
    if args.only_critical:
        enabled = {SEV_CRIT}
    elif args.no_warnings:
        enabled.discard(SEV_WARN)

    since = None
    if args.since:
        try:
            since = parse_since(args.since)
        except ValueError:
            print("Invalid --since format (use 2026-09-01 or 14d)")
            return 1

    wl_hashes, wl_paths, wl_problems = set(), [], []
    if args.whitelist:
        try:
            wl_hashes, wl_paths, wl_problems = load_whitelist(args.whitelist)
        except OSError as e:
            print("Cannot read the whitelist:", e)
            return 1
        for line_no, reason, snippet in wl_problems:
            print("whitelist: line %d: %s - ignored: %r" % (line_no, reason, snippet))

    if args.user_signatures:
        if not os.path.isfile(args.user_signatures):
            print("Cannot read the user signatures:", args.user_signatures)
            return 1
        try:
            user_sigs, sig_problems = load_user_signatures(args.user_signatures)
        except (OSError, ValueError) as e:
            print("Cannot read the user signatures:", e)
            return 1
        for line_no, reason, snippet in sig_problems:
            print("user-signatures: entry %d: %s - ignored: %r" % (line_no, reason, snippet))
        if user_sigs:
            register_user_signatures(user_sigs)
            print("user-signatures: %d signature(s) loaded from %s" % (len(user_sigs), args.user_signatures))

    baseline = None
    base_dirs = set()
    if args.baseline_dir:
        if not os.path.isdir(args.baseline_dir):
            print("Folder --baseline-dir not found:", args.baseline_dir)
            return 1
        if not os.path.isfile(os.path.join(args.baseline_dir, "index.php")):
            print("WARNING: --baseline-dir has no index.php, the path must point to the root of a clean Joomla")
        emit("PHASE", "baseline")
        print("Building the baseline from '%s' ..." % args.baseline_dir)
        baseline = build_baseline(args.baseline_dir)
        base_dirs = baseline_dir_set(args.baseline_dir)
        print("  baseline .php files: %d" % len(baseline))

    out_files = [p for p in (args.csv, args.json, args.sarif, args.xlsx) if p]
    skip_paths = set(os.path.abspath(p) for p in out_files)
    skip_paths.add(os.path.abspath(__file__))     # the script itself contains all the signatures

    cms = detect_cms(start)

    yara_spec = None
    yara_eng = None
    yara_files = []
    if args.yara_rules and not args.no_yara:
        if build_yara_engine is None:
            print("YARA: this build has no engines/ package - the YARA engine is unavailable")
            return 1
        try:
            yara_files = collect_rule_files(args.yara_rules)
        except ValueError as e:
            print("YARA:", e)
            return 1
        cache_dir = "" if args.no_yara_cache else (args.yara_cache or default_yarac_dir())
        if cache_dir and not args.yara_cache and migrate_yarac_cache():
            print("YARA: the compiled-rule cache moved to %s" % cache_dir)
        yara_ext = {"cms": {"wp": "wordpress", "joomla": "joomla"}.get(cms, ""),
                    "wp_root": cms == "wp", "joomla_root": cms == "joomla"}
        yara_eng, yara_problems = build_yara_engine(
            yara_files, cache_dir=cache_dir, base_externals=yara_ext, timeout=args.yara_timeout)
        for msg in yara_problems:            # broken rules are visible before the scan even starts
            print("YARA:", msg)
        if yara_eng is None:
            print("YARA: no rules are active - the scan runs with the built-in heuristics only")
        else:
            print("YARA: %d rule(s) from %d of %d file(s); per-file time limit %gs" %
                  (yara_eng.rules_count, yara_eng.files_loaded, len(yara_files), args.yara_timeout))
            yara_spec = {"sources": list(yara_files), "cache": cache_dir,
                         "timeout": args.yara_timeout, "externals": dict(yara_ext)}
            _YARA_ENGINES[yara_key(yara_spec)] = [yara_eng]   # the parent process reuses its own build

    cfg = {
        "start": start, "max_size": int(args.max_size * 1024 * 1024), "max_matches": args.max_matches,
        "since": since, "enabled": enabled, "wl_hashes": wl_hashes, "wl_paths": wl_paths,
        "baseline": baseline, "baseline_dirs": base_dirs, "skip_paths": skip_paths,
        "baseline_pkgs": set("/".join(r.split("/")[:4]) for r in (baseline or {}) if r.startswith("libraries/vendor/")), "posix": os.name != "nt",
        "exclude_ext": set(e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
                           for e in args.exclude_ext.split(",") if e.strip()),
        "cms": cms, "audit_wl": args.audit_whitelisted, "yara": yara_spec,
    }
    excl_dirs = set(d.strip() for d in args.exclude_dir.split(",") if d.strip())

    print("scan_backdoors %s | scanning '%s' ..." % (VERSION, start))
    if cms == "ambiguous":
        print("site CMS: ambiguous (WordPress and Joomla markers both present): CMS-specific suppressions are OFF")
    elif cms:
        print("site CMS: %s (root-file heuristic: gates the CMS-specific heuristics)"
              % ("WordPress" if cms == "wp" else "Joomla"))
    t0 = time.time()
    emit("PHASE", "walk")
    paths = list(iter_paths(start, excl_dirs))
    total = len(paths)
    batches = list(chunked(paths, 200))
    workers = args.workers or min(4, os.cpu_count() or 1)
    if total < 400:
        workers = 1

    results, stats_c = [], Counter()
    done_files = [0]
    show_progress = not args.no_progress and sys.stderr.isatty()

    def handle(res):
        r, c = res
        results.extend(r)
        stats_c.update(c)

    def progress(batch_len):
        done_files[0] += batch_len
        emit("PROGRESS", "%d %d" % (done_files[0], total))
        if show_progress:
            sys.stderr.write("\r  files processed: %d / %d" % (done_files[0], total))
            sys.stderr.flush()

    _init(cfg)
    emit("PROGRESS", "0 %d" % total)
    done = 0
    if workers > 1:
        try:
            from concurrent.futures import ProcessPoolExecutor
            kw = {"initializer": _init, "initargs": (cfg,)} if sys.version_info >= (3, 7) else {}
            with ProcessPoolExecutor(max_workers=workers, **kw) as ex:
                if sys.version_info >= (3, 7):
                    jobs = ex.map(scan_batch, batches)
                else:
                    jobs = ex.map(scan_batch_cfg, [(b, cfg) for b in batches])
                for b, res in zip(batches, jobs):
                    handle(res)
                    progress(len(b))
                    done += 1
        except Exception as e:
            print("\nParallel mode is unavailable (%s), continuing in a single thread" % e)
    for b in batches[done:]:
        handle(scan_batch(b))
        progress(len(b))
    if show_progress:
        sys.stderr.write("\r" + " " * 60 + "\r")

    emit("PHASE", "finish")
    audit = cms_audit(start, args, emit) if audit_wanted else None
    if audit and audit.get("integrity"):
        integrity_into_results(results, audit["integrity"], start, args)
    results = [r for r in results if r["score"] >= args.min_score]
    results.sort(key=lambda r: (-r["score"], r["path"]))

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    vcol = {"HIGH": "1;31", "MEDIUM": "33", "LOW": "36"}
    scol = {SEV_CRIT: "31", SEV_OBF: "33", SEV_WARN: "90"}

    def paint(s, code):
        return "\033[%sm%s\033[0m" % (code, s) if color else s

    for r in results:
        print("\n%s score=%-3d %s   (%.1f KB, %s, %s, sha256:%s)" % (
            paint("[%s]" % r["verdict"], vcol[r["verdict"]]), r["score"], r["path"],
            r["size"] / 1024.0, fmt_time(r["mtime"]), r["mode"], (r["sha256"] or "-")[:12]))
        for sev, line, label, snip, _w in r["hits"]:
            print("   %s %s%s: %s" % (paint(sev, scol[sev]), ("L%d " % line) if line else "",
                                      label, trim(snip, 120) if snip else ""))
        if r["hidden"]:
            print("   … %d more findings hidden (--max-matches)" % r["hidden"])

    if audit and audit["lines"]:
        print("")
        for line in audit["lines"]:
            print(line)

    sev_tot = Counter()
    ver_tot = Counter()
    for r in results:
        ver_tot[r["verdict"]] += 1
        for s, n in r["counts"].items():
            sev_tot[s] += n
    stats = {
        "Version": VERSION, "Scanned folder": start,
        "Files visited": total, "Files scanned": stats_c.get("scanned", 0),
        "Files flagged": len(results), "HIGH": ver_tot["HIGH"], "MEDIUM": ver_tot["MEDIUM"], "LOW": ver_tot["LOW"],
        "[CRITICAL] hits": sev_tot[SEV_CRIT], "[OBFUSCATED] hits": sev_tot[SEV_OBF], "[WARNING] hits": sev_tot[SEV_WARN],
        "Identical to clean Joomla (skipped)": stats_c.get("core_ok", 0),
        "Whitelisted": stats_c.get("whitelisted", 0),
        "Whitelisted by path (content NOT scanned)": stats_c.get("whitelisted_path", 0),
        "Skipped (too big)": stats_c.get("big", 0),
        "Skipped (older than --since)": stats_c.get("old", 0), "Read errors": stats_c.get("error", 0),
        "Unreadable (Windows permissions)": stats_c.get("unreadable", 0),
        "Time, s": round(time.time() - t0, 1),
    }

    dup_counts = Counter()
    for pth in paths:
        rel_d = os.path.relpath(pth, start).replace(os.sep, "/")
        rel_d = rel_d.rsplit("/", 1)[0] if "/" in rel_d else ""
        pre = dup_dir_prefix(rel_d) if rel_d else None
        if pre:
            dup_counts[pre] += 1
    stats["Same-name nested folders"] = len(dup_counts)

    yara_on = bool(args.yara_rules) and not args.no_yara
    if yara_on:
        stats["YARA: rule files"] = len(yara_files)
        stats["YARA: rules loaded"] = yara_eng.rules_count if yara_eng is not None else 0
        stats["YARA: files scanned"] = stats_c.get("yara_ok", 0)
        stats["YARA: scan gaps (files not fully scanned)"] = stats_c.get("yara_gap", 0)

    if audit is not None:
        summary = audit.get("inventory_summary") or {}
        stats["CMS"] = summary.get("cms", "unknown")
        stats["CMS version"] = summary.get("cms_version", "")
        stats["Components inventoried"] = sum((summary.get("components") or {}).values())
        stats["Components with an unknown version"] = summary.get("unknown_versions", 0)
        integ = audit.get("integrity_summary") or {}
        if integ.get("checked"):
            stats["WordPress core: verified"] = integ["verified"]
            stats["WordPress core: modified"] = integ["modified"]
            stats["WordPress core: extra"] = integ["extra"]
            stats["WordPress core: missing"] = integ["missing"]
        vsum = audit.get("vuln_summary")
        if vsum:
            stats["Vulnerabilities: verdicts"] = vsum["total"]
            stats["Vulnerabilities: known exploited (KEV)"] = vsum["kev"]
            stats["Vulnerabilities: unauditable components"] = vsum["low_confidence"]
        if audit["notes"]:
            stats["Audit notes"] = len(audit["notes"])

    print("\n" + "=" * 64)
    print("STATISTICS")
    print("  Files visited      : %d (scanned %d)" % (total, stats["Files scanned"]))
    print("  Files flagged      : %d   [HIGH %d | MEDIUM %d | LOW %d]" % (
        len(results), ver_tot["HIGH"], ver_tot["MEDIUM"], ver_tot["LOW"]))
    print("  Findings           : [CRITICAL] %d  [OBFUSCATED] %d  [WARNING] %d" % (
        sev_tot[SEV_CRIT], sev_tot[SEV_OBF], sev_tot[SEV_WARN]))
    if baseline is not None:
        print("  Matched baseline   : %d (skipped as clean)" % stats["Identical to clean Joomla (skipped)"])
    if stats["Whitelisted"]:
        print("  Whitelisted        : %d" % stats["Whitelisted"])
    if stats["Skipped (too big)"] or stats["Read errors"] or stats["Unreadable (Windows permissions)"]:
        print("  Skipped            : too large %d, read errors %d, NOT READABLE (Windows permissions) %d" % (
            stats["Skipped (too big)"], stats["Read errors"], stats["Unreadable (Windows permissions)"]))
    print("  Time               : %.1f s" % stats["Time, s"])
    if stats["Whitelisted by path (content NOT scanned)"]:
        print("  Whitelisted by path: %d (content NOT scanned; --audit-whitelisted looks at them)"
              % stats["Whitelisted by path (content NOT scanned)"])
    if yara_on:
        print("  YARA               : %d rule(s) from %d file(s); files scanned %d, scan gaps %d" % (
            stats["YARA: rules loaded"], stats["YARA: rule files"],
            stats["YARA: files scanned"], stats["YARA: scan gaps (files not fully scanned)"]))
        if stats["YARA: scan gaps (files not fully scanned)"]:
            print("  WARNING            : YARA could not fully scan %d file(s) - see their [WARNING] hits"
                  % stats["YARA: scan gaps (files not fully scanned)"])
    if stats["Read errors"]:
        print("  WARNING            : %d file(s) could not be processed - the scan is INCOMPLETE" % stats["Read errors"])
    print("=" * 64)
    if wl_problems:
        print("whitelist: %d malformed line(s) ignored" % len(wl_problems))
    if dup_counts:
        print("\nNested folders with the same name (a/a), check manually: %d (files inside in parentheses)" % len(dup_counts))
        for pre, n in sorted(dup_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:40]:
            print("  %s  (%d)" % (pre, n))
        if len(dup_counts) > 40:
            print("  … and %d more" % (len(dup_counts) - 40))
    if sev_tot[SEV_CRIT]:
        print("ACTION: review the [HIGH] files first; delete/restore the infected ones and rescan.")

    try:
        if args.csv:
            write_csv(args.csv, results)
            print("CSV : %s" % os.path.abspath(args.csv))
            emit("FILE", "csv " + os.path.abspath(args.csv))
            vulns = (audit or {}).get("vulnerabilities") or []
            if vulns:
                vpath = vulnerabilities_csv_path(args.csv)
                write_vulnerabilities(vpath, vulns)
                print("CVE CSV: %s" % os.path.abspath(vpath))
                emit("FILE", "vuln_csv " + os.path.abspath(vpath))
        if args.xlsx:
            build_xlsx(args.xlsx, results, stats, audit)
            print("XLSX: %s" % os.path.abspath(args.xlsx))
            emit("FILE", "xlsx " + os.path.abspath(args.xlsx))
        if args.json:
            write_json(args.json, results, stats, audit)
            print("JSON: %s" % os.path.abspath(args.json))
            emit("FILE", "json " + os.path.abspath(args.json))
        if args.sarif:
            write_sarif(args.sarif, results, stats, audit)
            print("SARIF: %s" % os.path.abspath(args.sarif))
            emit("FILE", "sarif " + os.path.abspath(args.sarif))
    except Exception as e:
        print("Could not write the report:", e)

    emit("STATS", json.dumps(stats, ensure_ascii=False))
    emit("DONE", str(sev_tot[SEV_CRIT]))
    if sev_tot[SEV_CRIT]:
        return 2                                # a possible compromise outranks everything else
    if args.fail_on and audit and audit.get("vulnerabilities"):
        worst = vuln_api.max_severity(audit["vulnerabilities"])
        if vuln_api.meets_threshold(audit["vulnerabilities"], args.fail_on):
            print("ACTION: --fail-on %s: a vulnerability of severity '%s' was found "
                  "(no file finding was [CRITICAL])" % (args.fail_on, worst))
            return 4                            # known vulnerabilities reached the bar
    return 3 if (args.strict and stats["Read errors"]) else 0


if __name__ == "__main__":
    sys.exit(main())
