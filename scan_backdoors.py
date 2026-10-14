#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_backdoors 2.1 - signature scanner for Joomla/PHP sites: backdoors, web shells, malicious code.
Standard library only (Python 3.6+), no pip needed.

Examples:
    python3 scan_backdoors.py /path/to/site        # report: report-data.csv
    python3 scan_backdoors.py . --since 14d --only-critical
    python3 scan_backdoors.py . --baseline-dir /tmp/Joomla_clean --csv out.csv --json out.json --xlsx out.xlsx
    python3 scan_backdoors.py . --whitelist whitelist.txt --workers 4

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
import stat
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime

VERSION = "2.1"

# ---------------------------------------------------------------------------
# 1) CONSTANTS
# ---------------------------------------------------------------------------

SEV_CRIT = "[CRITICAL]"
SEV_OBF = "[OBFUSCATED]"
SEV_WARN = "[WARNING]"
SEV_RANK = {SEV_CRIT: 0, SEV_OBF: 1, SEV_WARN: 2}
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
MALWARE_NAMES = {"moderation.php", "system_log.php", "inputs.php", "chtmlfuns.php", "cjfuns.php", "classsmtps.php",
                 "classfuns.php", "comfunctions.php", "comdofuns.php", "connects.php", "copypaths.php", "delpaths.php",
                 "doiconvs.php", "epinyins.php", "filefuns.php", "gdftps.php", "hinfofuns.php", "hplfuns.php",
                 "memberfuns.php", "moddofuns.php", "onclickfuns.php", "phpzipincs.php", "qfunctions.php",
                 "qinfofuns.php", "schallfuns.php", "tempfuns.php", "txets.php", "thoms.php"}
SHELL_NAMES = {"shell", "c99", "c100", "r57", "r58", "wso", "wsoshell", "b374k", "alfa", "cmd",
               "bypass", "hack", "hacked", "backdoor", "webshell", "filesman", "indoxploit",
               "priv8", "sh3ll", "symlink", "leafmailer", "filemanager", "tinyfilemanager", "fm"}

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
# ---------------------------------------------------------------------------

SIGS_BY_KIND = {}


def S(sev, label, pattern, kinds, weight=None, flags=0, at_end=False):
    rx = re.compile(pattern, flags)
    w = DEFAULT_WEIGHT[sev] if weight is None else weight
    for k in kinds.split():
        SIGS_BY_KIND.setdefault(k, []).append((sev, label, rx, w, at_end))


C, O, W = SEV_CRIT, SEV_OBF, SEV_WARN
RQ = r"\$_(?:POST|GET|REQUEST|COOKIE)"

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
S(C, "system/exec(request data)", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*" + RQ, "php", 25)
S(C, "backticks with request data", r"`[^`\n]{0,200}" + RQ + r"[^`\n]{0,200}`", "php", 25)
S(C, "base64_decode(request data)", r"\bbase64_decode\s*\(\s*@?\s*" + RQ, "php", 25)
S(C, "unserialize(request data)", r"\bunserialize\s*\(\s*(?:@?\s*base64_decode\s*\(\s*)?@?\s*" + RQ, "php", 25)
S(C, "file write with request data", r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;\n]{0,150}" + RQ, "php")
S(C, "preg_replace /e modifier", r"\bpreg_replace\s*\(\s*(['\"])([/#~|@!%])[^'\"\n]{0,200}?\2[a-z]{0,5}e[a-z]{0,5}\1", "php")
S(C, "preg_replace_callback + payload", r"\bpreg_replace_callback\s*\(.{0,200}(?:base64_decode|" + RQ + ")", "php")
S(C, "create_function", r"\bcreate_function\s*\(", "php")
S(C, "shell_exec / passthru / pcntl_exec", r"\b(?:shell_exec|passthru|pcntl_exec)\s*\(", "php")
S(C, "/bin/sh | /etc/passwd", r"/bin/(?:ba)?sh\b|/etc/(?:passwd|shadow)", "php")
S(C, "eval(function from an array element)", r"\beval\s*\(\s*\$\w+\s*\[[^\]\n]{1,40}\]\s*\(", "php", 25)
S(C, "alphabet trick range('~',' ') used to hide names", r"\(\s*[\"'](?:~|\\176|\\x7e)[\"']\s*,\s*[\"'](?: |\\40|\\x20)[\"']\s*\)", "php", 25, re.I)
S(C, "infection marker 'BiaoJiOk' (backdoor family)", r"BiaoJiOk", "php html text", 30)
S(O, "function call via computed array index $a[6 + 4](...)", r"\$\w+\s*\[\s*\d+\s*\+\s*\d+\s*\]\s*\(", "php", 8)
S(O, "nested md5(md5(md5(...))) (hard-coded backdoor password check)", r"\bmd5\s*\(\s*md5\s*\(\s*md5\s*\(", "php", 8)
S(C, "dynamic variable ${$ / ${' (escaped \\$ in a string is NOT one)", r"(?<!\\)\$\{\s*[\$'\"]", "php")
S(C, "known webshell signature", r"\bFilesMan\b|c99shell|r57shell|\bb374k\b|Mini\s*Shell|\bPriv8\b|IndoXploit|Alfa\s*Team|AnonymousFox|\bWSO\s*\d|Sh3ll\b|\bHacked\s+by\b", "php js html text", 30, re.I)
S(C, "Tiny File Manager / webshell", r"tinyfilemanager|embedded_pass_hash|fm_clean_path|H3K\s*\|\s*Tiny", "php html", 30, re.I)
S(C, "malware tag <script id='sggtp'>", r"<script[^>]*\bid\s*=\s*['\"]?sggtp", "php js html text", 30, re.I)
# ---- CRITICAL: JS / HTML ----
S(C, "crypto-miner", r"coinhive|coin-hive|cryptonight|cryptoloot|crypto-loot|webminepool|minero\.cc|authedmine", "php js html", 25, re.I)
S(C, "hidden iframe that loads a payload (src=/srcdoc=)", r"<iframe\b(?=[^>]{0,400}\b(?:src|srcdoc)\s*=)[^>]{0,400}(?:\b(?:width|height)\s*=\s*['\"]?[01](?:px)?['\"]?[\s>/]|display\s*:\s*none|visibility\s*:\s*hidden)", "php js html", 15, re.I)
S(W, "iframe built in JS (createElement / .src=)", r"createElement\s*\(\s*['\"]iframe\b|\biframe\b[^;\n]{0,40}\.src\s*=|innerHTML[^;\n]{0,120}<iframe", "php js html", 1)
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
# Legitimate Joomla code does NOT read $_POST['password'] directly (login goes through the API), so this is a strong indicator
S(C, "credential harvesting: password field read from $_POST", r"\$_POST\b[^\n]{0,80}?\[\s*['\"](?:password|passwd|pass|pwd|userpassword|regpass)['\"]", "php", 12)
# ---- OBFUSCATED: data store hidden in an image (steganography) ----
S(O, "custom X- response header (self-advertising marker)", r"\bheader\s*\(\s*@?\s*['\"]X-[\w\-]{2,40}[:\"]", "php", 8)
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
        notes.append((C, 0, "hidden PHP file (leading dot)", name, 15))
        stem = ""
    else:
        stem = low.split(".")[0]
    if re.search(r"\s", name):
        notes.append((O, 0, "whitespace in filename", name, 5))
    if stem in SHELL_NAMES:
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


def scan_text(text, kinds, enabled):
    hits = []
    seen = set()
    nl = None
    for kind in kinds:
        for sev, label, rx, w, at_end in SIGS_BY_KIND.get(kind, ()):
            if sev not in enabled:
                continue
            n = 0
            for m in rx.finditer(text):
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


def php_anomalies(raw, text, folder=None):
    hits = filemanager_hits(text) + base64_literal_hits(text, folder)
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

HARVEST_POST_RX = re.compile(r"\$_POST\b[^\n]{0,80}?\[\s*['\"](?:password|passwd|pass|pwd|userpassword|regpass)['\"]")
HARVEST_SINKS = [
    ("file write", re.compile(r"\b(?:file_put_contents|fwrite|fputs)\s*\(")),
    ("response-header leak", re.compile(r"\bheader\s*\(\s*@?\s*['\"][^'\n]{0,60}:")),
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
    """Reads a password field from $_POST and stores it somewhere = credential harvester."""
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
    if BACKDATE_RX.search(text):
        return [(C, line, "mtime backdating (sets a fake old date): defeats --since and 'recently modified' checks", "", 15)]
    if MTIME_RX.search(text):
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
    tail = text[text.rfind("}") + 1:].strip()
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
        if DIE_HEADER_RE.match(head):
            return []
        return [(C, 0, "PHP file in /%s/ without Joomla die() header" % parts[-1 if first == "administrator" else 0], rel, 15)]
    if first == "media":
        return [(O, 0, "PHP file in /media/", rel, 6)]
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
            if fnmatch.fnmatch(rel, p):
                return True
        elif rel == p or rel.startswith(p.rstrip("/") + "/"):
            return True
    return False


def make_result(rel, st, sha, hits, max_matches):
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
    if path_whitelisted(rel, cfg["wl_paths"]):
        return None, "whitelisted"

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

    enabled = cfg["enabled"]
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
                    hits.append((O, line_no, "PHP tag inside a %s file" % kind, name, 6))
        else:
            if raw[:4] in (b"GIF8",) or raw[:3] == b"\xff\xd8\xff" or raw[:4] == b"\x89PNG":
                hits.append((C, 1, "image magic bytes at the start of a PHP file", name, 25))
            hits += location_hits(rel, name, st.st_size, text[:300])
            hits += php_anomalies(raw, text, os.path.dirname(path))
            if name.lower() == "configuration.php" and "/" not in rel:
                hits += config_hits(text)
            if cfg["posix"] and (stat.S_IMODE(st.st_mode) & 0o002):
                hits.append((O, 0, "world-writable PHP file (%04o)" % stat.S_IMODE(st.st_mode), name, 4))
        hits += scan_text(text, kinds, enabled)
        hits += blob_hits(rel, name, kind, raw)
        if name.lower().endswith(".xml"):
            hits += manifest_author_hits(rel, text, cfg["baseline_dirs"])

    hits = [h for h in hits if h[0] in enabled]
    if not hits:
        return None, "scanned"
    if sha is None:
        sha = hashlib.sha256(raw).hexdigest()
    return make_result(rel, st, sha, hits, mm), "scanned"


def scan_batch(paths):
    results, counters = [], Counter()
    for p in paths:
        try:
            res, status = scan_file(p)
        except Exception:     # one bad file must not crash the whole scan
            res, status = None, "error"
        counters[status] += 1
        if res:
            results.append(res)
    return results, dict(counters)


# ---------------------------------------------------------------------------
# 5) REPORTS: CSV / JSON / XLSX (xlsx is a zip of XML, built by hand)
# ---------------------------------------------------------------------------

def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def write_csv(path, results):
    with io.open(path, "w", newline="", encoding="utf-8-sig", errors="replace") as f:
        w = csv.writer(f)
        w.writerow(["Score", "Verdict", "Severity", "File", "Line", "Signature", "Snippet",
                    "Size", "Modified", "Delete", "SHA-256"])
        for r in results:
            for sev, line, label, snip, _w in r["hits"]:
                w.writerow([r["score"], r["verdict"], sev, csv_safe(r["path"]), line or "",
                            label, csv_safe(snip), r["size"], fmt_time(r["mtime"]), "No", r["sha256"]])


def write_json(path, results, stats):
    data = {"version": VERSION, "stats": stats, "files": [{
        "path": r["path"], "score": r["score"], "verdict": r["verdict"], "size": r["size"],
        "modified": fmt_time(r["mtime"]), "mode": r["mode"], "sha256": r["sha256"],
        "counts": r["counts"], "hidden_hits": r["hidden"],
        "hits": [{"severity": h[0], "line": h[1], "signature": h[2], "snippet": h[3]} for h in r["hits"]],
    } for r in results]}
    with io.open(path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


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


def build_xlsx(path, results, stats):
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
    write_xlsx(path, [("Files", files[:XLSX_MAX_ROWS], [8, 10, 60, 10, 17, 7, 66, 11, 9, 9, 60]),
                      ("Hits", hits, [8, 14, 60, 7, 42, 90, 17]),
                      ("Summary", summ, [28, 50])])


# ---------------------------------------------------------------------------
# 6) MAIN
# ---------------------------------------------------------------------------

def parse_since(s):
    m = re.match(r"^(\d+)d$", s.strip())
    if m:
        return time.time() - int(m.group(1)) * 86400
    return time.mktime(datetime.strptime(s.strip(), "%Y-%m-%d").timetuple())


def load_whitelist(path):
    hashes, paths = set(), []
    with io.open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if re.match(r"^[0-9a-fA-F]{64}$", line):
                hashes.add(line.lower())
            else:
                paths.append(re.sub(r"^(?:\./|/)+", "", line.replace("\\", "/")))
    return hashes, paths


def build_baseline(clean_dir):
    base = {}
    for root, _dirs, files in os.walk(clean_dir):
        for n in files:
            if n.lower().endswith(".php"):
                p = os.path.join(root, n)
                try:
                    with open(p, "rb") as fh:
                        base[os.path.relpath(p, clean_dir).replace(os.sep, "/")] = hashlib.sha256(fh.read()).hexdigest()
                except OSError:
                    pass
    return base


def baseline_dir_set(clean_dir):
    """Folders that exist in the clean distribution (lower-cased paths relative to its root)."""
    s = set()
    for root, dirs, _files in os.walk(clean_dir):
        for d in dirs:
            s.add(os.path.relpath(os.path.join(root, d), clean_dir).replace(os.sep, "/").lower())
    return s


def iter_paths(start, excl_dirs):
    for root, dirs, files in os.walk(start):
        if excl_dirs:
            dirs[:] = [d for d in dirs if d not in excl_dirs]
        for n in files:
            yield os.path.join(root, n)


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def build_parser():
    ap = argparse.ArgumentParser(description="Backdoor/web shell scanner for Joomla/PHP sites, v" + VERSION)
    ap.add_argument("start", nargs="?", default=".", help="folder to scan (default: the current one)")
    ap.add_argument("--max-matches", type=int, default=60, help="max findings of one level per file in the report (60)")
    ap.add_argument("--max-size", type=float, default=5, help="max file size, MB (5)")
    ap.add_argument("--csv", default="report-data.csv", help="CSV report path (default report-data.csv)")
    ap.add_argument("--no-csv", action="store_true", help="do not create the CSV")
    ap.add_argument("--xlsx", help="additionally save the report as XLSX")
    ap.add_argument("--json", help="save the full report as JSON")
    ap.add_argument("--since", help="only files modified later than: 2026-09-01 or 14d (last 14 days)")
    ap.add_argument("--only-critical", action="store_true", help="search only for [CRITICAL]")
    ap.add_argument("--no-warnings", action="store_true", help="do not search for [WARNING]")
    ap.add_argument("--min-score", type=int, default=0, help="show files with a score not lower than N")
    ap.add_argument("--exclude-ext", default="", help="comma-separated extensions: .js,.json")
    ap.add_argument("--exclude-dir", default="", help="comma-separated folder names (ALL folders are scanned by default)")
    ap.add_argument("--whitelist", help="file: SHA-256, paths, folders (with a trailing /) or masks *; # - comment")
    ap.add_argument("--baseline-dir", help="folder with a CLEAN Joomla of the same version (where index.php lives)")
    ap.add_argument("--workers", type=int, default=0, help="number of processes (0 = auto, 1 = no parallelism)")
    ap.add_argument("--no-progress", action="store_true", help="no progress indicator")
    ap.add_argument("--progress-lines", action="store_true",
                    help="machine-readable lines @@PROGRESS/@@FILE/@@STATS for the GUI (works without a terminal too)")
    ap.add_argument("--version", action="version", version="scan_backdoors " + VERSION)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_csv:
        args.csv = None
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

    wl_hashes, wl_paths = set(), []
    if args.whitelist:
        try:
            wl_hashes, wl_paths = load_whitelist(args.whitelist)
        except OSError as e:
            print("Cannot read the whitelist:", e)
            return 1

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

    out_files = [p for p in (args.csv, args.json, args.xlsx) if p]
    skip_paths = set(os.path.abspath(p) for p in out_files)
    skip_paths.add(os.path.abspath(__file__))     # the script itself contains all the signatures

    cfg = {
        "start": start, "max_size": int(args.max_size * 1024 * 1024), "max_matches": args.max_matches,
        "since": since, "enabled": enabled, "wl_hashes": wl_hashes, "wl_paths": wl_paths,
        "baseline": baseline, "baseline_dirs": base_dirs, "skip_paths": skip_paths,
        "baseline_pkgs": set("/".join(r.split("/")[:4]) for r in (baseline or {}) if r.startswith("libraries/vendor/")), "posix": os.name != "nt",
        "exclude_ext": set(e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
                           for e in args.exclude_ext.split(",") if e.strip()),
    }
    excl_dirs = set(d.strip() for d in args.exclude_dir.split(",") if d.strip())

    print("scan_backdoors %s | scanning '%s' ..." % (VERSION, start))
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
                for b, res in zip(batches, ex.map(scan_batch, batches)):
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
        "Whitelisted": stats_c.get("whitelisted", 0), "Skipped (too big)": stats_c.get("big", 0),
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
    print("=" * 64)
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
        if args.xlsx:
            build_xlsx(args.xlsx, results, stats)
            print("XLSX: %s" % os.path.abspath(args.xlsx))
            emit("FILE", "xlsx " + os.path.abspath(args.xlsx))
        if args.json:
            write_json(args.json, results, stats)
            print("JSON: %s" % os.path.abspath(args.json))
            emit("FILE", "json " + os.path.abspath(args.json))
    except Exception as e:
        print("Could not write the report:", e)

    emit("STATS", json.dumps(stats, ensure_ascii=False))
    emit("DONE", str(sev_tot[SEV_CRIT]))
    return 2 if sev_tot[SEV_CRIT] else 0


if __name__ == "__main__":
    sys.exit(main())
