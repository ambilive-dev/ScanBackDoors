# -*- coding: utf-8 -*-
"""Synthetic sites for the tests - the smallest input that exercises the detector.

Nothing here is a real CMS. It is the SHAPE the scanner keys on (folder layout,
extensions, file names) plus two sets that make a golden test possible:

  CLEAN    - a legitimate-looking Joomla-like tree. It produces no findings at
             all: every signature of the scanner is absent from it by design.
  PLANTED  - backdoors, web shells and a malicious .htaccess of the families the
             scanner and the cleaner implement. Each sample declares the signature
             it must trip and the severity it must reach.

Malicious samples live in tests/payloads/*.b64 and are unsealed here at run time
(see tests/seal_payloads.py for why). Sites are built under one stable folder -
fixtures_root() - never into a checkout, and never into a real site.

Antivirus note: real-time protection may delete a planted sample between the
moment it is written and the moment the scanner reads it. wait_readables()
detects that, and the tests then assert on the samples that are really present
and report the rest as an environment problem instead of a detector failure.
"""

from __future__ import print_function

import base64
import io
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seal_payloads import unseal  # noqa: E402

# ---------------------------------------------------------------------------
# tiny valid images: real magic bytes, no trailing data
# ---------------------------------------------------------------------------
GIF_1PX = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
PNG_1PX = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

INDEX_PHP = """<?php
/**
 * @package     MiniSite
 * @copyright   Copyright (C) 2026 Test Fixture
 * @license     GNU General Public License version 2 or later
 */

define('_JEXEC', 1) or die;
define('JPATH_BASE', __DIR__);
define('JPATH_PLATFORM', JPATH_BASE . '/libraries');

require_once JPATH_BASE . '/includes/defines.php';
require_once JPATH_BASE . '/includes/framework.php';

$app = JFactory::getApplication('site');
$app->initialise();
echo $app->toString(true);
"""

DEFINES_PHP = """<?php
/**
 * @package    MiniSite
 */

defined('_JEXEC') or die;

define('MS_VERSION', '1.0.0');
define('MS_PATH_LIBRARIES', JPATH_PLATFORM);
"""

FRAMEWORK_PHP = """<?php
/**
 * @package    MiniSite
 */

defined('_JEXEC') or die;

require_once MS_PATH_LIBRARIES . '/loader.php';
"""

LOADER_PHP = """<?php
/**
 * @package    MiniSite
 */

defined('_JEXEC') or die;

class Loader
{
    protected static $classes = array();

    public static function register($name, $path)
    {
        self::$classes[$name] = $path;
    }

    public static function load($name)
    {
        if (isset(self::$classes[$name]) && is_file(self::$classes[$name])) {
            require_once self::$classes[$name];

            return true;
        }

        return false;
    }
}
"""

SITE_APPLICATION_PHP = """<?php
/**
 * @package    MiniSite
 * @subpackage SiteApplication
 */

defined('_JEXEC') or die;

class SiteApplication
{
    public function initialise()
    {
        $app = JFactory::getApplication('site');
        $app->triggerEvent('onAfterInitialise');

        return $this;
    }

    public function toString($catchExceptions = false)
    {
        return $this->render('component');
    }

    protected function render($name)
    {
        return 'rendered ' . $name;
    }
}
"""

CONTENT_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  com_content
 */

defined('_JEXEC') or die;

class ContentHelper
{
    /**
     * Article list for a category.
     */
    public static function getArticles($catId)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select($db->quoteName(array('id', 'title', 'alias')))
            ->from($db->quoteName('#__content'))
            ->where($db->quoteName('catid') . ' = ' . (int) $catId)
            ->order('ordering ASC');
        $db->setQuery($query);

        return $db->loadObjectList();
    }

    public static function getState()
    {
        return JFactory::getApplication()->getUserState('com_content.article', 0);
    }
}
"""

ROUTE_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  com_content
 */

defined('_JEXEC') or die;

class ContentRoute
{
    public static function buildArticleRoute($id, $slug, $catid = 0)
    {
        $route = 'content/' . (int) $catid . '/' . (int) $id . '-' . $slug;

        return 'index.php?option=com_content&view=article&layout=default&id=' . (int) $id
            . '&link=' . urlencode($route);
    }

    public static function getArticleId($alias)
    {
        $app = JFactory::getApplication();
        $menu = $app->getMenu()->getActive();

        return $menu ? $menu->query['id'] : 0;
    }
}
"""

ARTICLE_DEFAULT_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  com_content
 */

defined('_JEXEC') or die;

$item = $this->item;
?>
<article class="item-page<?php echo $this->pageclass_sfx; ?>">
    <h2><?php echo htmlspecialchars($item->title, ENT_COMPAT, 'UTF-8'); ?></h2>
    <div class="body"><?php echo $item->text; ?></div>
</article>
"""

MODULE_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  mod_latest
 */

defined('_JEXEC') or die;

require_once __DIR__ . '/helper.php';

$items = ModLatestHelper::getItems($params);
require Module::getLayoutFile('default', __DIR__);
"""

MODULE_HELPER_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  mod_latest
 */

defined('_JEXEC') or die;

class ModLatestHelper
{
    public static function getItems($params)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select('id, title')->from($db->quoteName('#__content'))
            ->where($db->quoteName('state') . ' = 1')
            ->setLimit((int) $params->get('count', 5));
        $db->setQuery($query);

        return $db->loadObjectList();
    }
}
"""

MODULE_DEFAULT_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  mod_latest
 */

defined('_JEXEC') or die;
?>
<ul class="latest">
<?php foreach ($items as $item) : ?>
    <li><?php echo htmlspecialchars($item->title, ENT_COMPAT, 'UTF-8'); ?></li>
<?php endforeach; ?>
</ul>
"""

PLUGIN_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  plg_system_example
 */

defined('_JEXEC') or die;

class PlgSystemExample extends JPlugin
{
    public function onAfterInitialise()
    {
        $app = JFactory::getApplication();

        if ($app->isSite() && $this->params->get('enabled', 1)) {
            $app->setUserState('mini.example', 'on');
        }

        return true;
    }
}
"""

TEMPLATE_INDEX_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  tpl_protostar
 */

defined('_JEXEC') or die;

$jdoc = JFactory::getDocument();
$jdoc->addStyleSheet('templates/' . $this->template . '/css/template.css');
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-gb" lang="en-gb">
<head>
    <jdoc:include type="head" />
</head>
<body class="site">
    <jdoc:include type="modules" name="position-3" style="xhtml" />
    <jdoc:include type="component" />
</body>
</html>
"""

TEMPLATE_JS = """/**
 * @package    MiniSite
 * @subpackage tpl_protostar
 */
document.addEventListener('DOMContentLoaded', function () {
    var items = document.querySelectorAll('.hasTooltip');
    for (var i = 0; i < items.length; i++) {
        items[i].addEventListener('click', function (event) {
            event.preventDefault();
        });
    }
});
"""

TEMPLATE_CSS = """/**
 * @package    MiniSite
 */
body {
    margin: 0;
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    background: #f6f6f6;
}

.item-page h2 {
    font-size: 1.6em;
    line-height: 1.3;
}
"""

CORE_JS = """/**
 * @package    MiniSite
 */
var Joomla = window.Joomla || {};

Joomla.eachNode = function (selector, callback) {
    document.querySelectorAll(selector).forEach(callback);
};

Joomla.renderMessages = function (messages) {
    Object.keys(messages).forEach(function (type) {
        Joomla.eachNode('#messages .' + type, function (node) {
            node.textContent = messages[type].join('\\n');
        });
    });
};
"""

ADMIN_INDEX_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  admin
 */

define('_JEXEC', 1) or die;
define('JPATH_BASE', dirname(__DIR__));

require_once JPATH_BASE . '/includes/defines.php';
require_once JPATH_BASE . '/includes/framework.php';

$app = JFactory::getApplication('administrator');
$app->initialise();
echo JDispatcher::dispatch('onAfterDispatch');
"""

ADMIN_LOGIN_PHP = """<?php
/**
 * @package     MiniSite
 * @subpackage  admin
 */

defined('_JEXEC') or die;

$form = JFactory::getDocument()->getForm('login');
echo $form->render();
"""

CONFIGURATION_PHP = """<?php
class JConfig {
	public $offline = false;
	public $config_file_exists = '1';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'minisite';
	public $db = 'minisite';
	public $password = 'fixture-value-not-a-real-password';
	public $dbprefix = 'ms_';
	public $live_site = '';
	public $secret = 'fixture-secret-not-a-real-secret';
	public $session_handler = 'database';
	public $debug = false;
}
"""

HTACCESS_TXT = """##
# @package    MiniSite
##

Options +FollowSymLinks
RewriteEngine On
RewriteBase /

## Block request to configuration.php - instead use public/index.php
RewriteCond %{REQUEST_METHOD} ^(POST|PUT|PATCH|DELETE|DEBUG|TRACE) [NC]
RewriteCond %{QUERY_STRING} !(option=(sppbslider|AJAXlogin)) [NC]
RewriteRule "(config\\.(php|inc)|configuration\\.php(.*)|update\\.php|cron\\.php)" - [F] [NC]

RewriteCond %{REQUEST_URI} .*\\.(?:htaccess|ini|log|sh|inc|bak|old|sql\\.gz)$ [OR]
RewriteCond %{REQUEST_URI} (^|/)(\\.|_)(?:git|svn|htaccess) [NC,OR]
RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\\[|%59|%88) [OR]
RewriteCond %{QUERY_STRING} (<|%3C)(?:script).*(?:>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} .*(union|insert|eval|base64|require|concat).* [NC]
RewriteRule ^(index2?\\.php|administrator/(?:login|index)\\.php) - [F,L,NC]

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.php [L]
"""

LANGUAGE_INI = """; @package    MiniSite
COM_CONTENT="Content"
COM_CONTENT_ARTICLE_TITLE="Article Title"
COM_CONTENT_READ_MORE="Read more"
COM_CONTENT_CREATED_BY="Created by %s"
"""

HTML_BLANK = "<html><body></body></html>\n"

# A clean site: no signature of the scanner matches any of these files.
CLEAN = {
    "index.php": INDEX_PHP,
    "configuration.php": CONFIGURATION_PHP,
    "htaccess.txt": HTACCESS_TXT,
    ".htaccess": HTACCESS_TXT,
    "README.txt": "MiniSite fixture\n===========\n\nSynthetic site used by the Scan Backdoors test suite.\n",
    "includes/defines.php": DEFINES_PHP,
    "includes/framework.php": FRAMEWORK_PHP,
    "libraries/loader.php": LOADER_PHP,
    "libraries/src/Application/SiteApplication.php": SITE_APPLICATION_PHP,
    "components/com_content/content.php": CONTENT_PHP,
    "components/com_content/helpers/route.php": ROUTE_PHP,
    "components/com_content/views/article/tmpl/default.php": ARTICLE_DEFAULT_PHP,
    "modules/mod_latest/mod_latest.php": MODULE_PHP,
    "modules/mod_latest/helper.php": MODULE_HELPER_PHP,
    "modules/mod_latest/tmpl/default.php": MODULE_DEFAULT_PHP,
    "plugins/system/example/example.php": PLUGIN_PHP,
    "templates/protostar/index.php": TEMPLATE_INDEX_PHP,
    "templates/protostar/js/template.js": TEMPLATE_JS,
    "templates/protostar/css/template.css": TEMPLATE_CSS,
    "administrator/index.php": ADMIN_INDEX_PHP,
    "administrator/components/com_login/view/login/view.html.php": ADMIN_LOGIN_PHP,
    "media/system/js/core.js": CORE_JS,
    "language/en-GB/en-GB.com_content.ini": LANGUAGE_INI,
    "cache/index.html": HTML_BLANK,
    "tmp/index.html": HTML_BLANK,
    "logs/index.html": HTML_BLANK,
}

CLEAN_BINARY = {
    "images/banners/banner.gif": GIF_1PX,
    "media/jui/images/logo.png": PNG_1PX,
}

# ---------------------------------------------------------------------------
# planted samples: rel path -> payload name, signatures it must trip, verdict
# ---------------------------------------------------------------------------
# Metadata-derived signatures (filename, location) survive an antivirus block;
# content-derived ones only show up when the scanner can read the file.
PLANTED = {
    "administrator/components/com_banners/helpers/filefuns.php": {
        "payload": "filefuns.php",
        "signatures": ["BiaoJiOk", "known malicious .htaccess allow-list"],
        "meta": ["known malicious .htaccess allow-list"],
        "verdict": "HIGH",
    },
    "tmp/media_view.php": {
        "payload": "php-in-tmp.php",
        "signatures": ["PHP file in /tmp/", "error_reporting(0)"],
        "meta": ["PHP file in /tmp/"],
        "verdict": "HIGH",
    },
    "templates/protostar/html/tpl.php.jpg": {
        "payload": "tpl.php.jpg",
        "signatures": ["double extension", "system/exec(request data)"],
        "meta": ["double extension"],
        "verdict": "HIGH",
    },
    "configuration.php": {
        "payload": "configuration-injected.php",
        "signatures": ["AFTER class JConfig"],
        "meta": [],
        "verdict": "HIGH",
    },
    ".htaccess": {
        "payload": "htaccess-malicious.txt",
        "signatures": ["known malicious .htaccess template"],
        "meta": [],
        "verdict": "HIGH",
    },
    "connector-filemanager.php": {
        "payload": "connector-filemanager.php",
        "signatures": ["web file manager", "file write with request data"],
        "meta": [],
        "verdict": "HIGH",
    },
    "media/system/js/jquery.min.js": {
        "payload": "packer.js",
        "signatures": ["JS packer"],
        "meta": [],
        "verdict": "MEDIUM",
    },
    # wp2shell campaign drop (July 2026): fake plugin <name>-<6hex>, impersonation
    # author header, hash_equals token gate, command through a local variable.
    "wp-content/plugins/wpeditor-1a2b3c/wpeditor-1a2b3c.php": {
        "payload": "wp2shell-campaign.php",
        "signatures": [
            "exec sink fed by a variable from request data",
            "hash_equals() comparing against request data (token-gated backdoor)",
            "plugin folder named like a campaign drop (<name>-<6 hex> suffix)",
            "plugin header claims 'WordPress.org Community' authorship (impersonation)",
        ],
        "meta": ["plugin folder named like a campaign drop (<name>-<6 hex> suffix)"],
        "verdict": "HIGH",
    },
    # request data into a local variable, then a directory/file read (LFI shell)
    "tmp/fetch_lfi.php": {
        "payload": "lfi-variable.php",
        "signatures": ["PHP file in /tmp/", "file function fed by a variable from request data"],
        "meta": ["PHP file in /tmp/"],
        "verdict": "HIGH",
    },
    # destination path straight from the request (uploader / arbitrary write)
    "connector-up.php": {
        "payload": "upload-dest.php",
        "signatures": ["file write/copy to a path from request data"],
        "meta": [],
        "verdict": "HIGH",
    },
    # classic shell family with a version suffix (c99_madnet.php, r57shell.php, ...)
    "c99_madnet.php": {
        "payload": "c99_madnet.php",
        "signatures": ["typical webshell filename"],
        "meta": ["typical webshell filename"],
        "verdict": "HIGH",
    },
}

# clean_malware.py implements fewer families than the scanner detects; these are
# the planted files it is supposed to plan an action for.
PLANTED_FOR_CLEANER = {
    ".htaccess": ("htaccess", "strip"),
    "administrator/components/com_banners/helpers/filefuns.php": ("backdoor", "remove"),
}


def fixtures_root():
    """Single stable folder for synthetic sites (SBD_FIXTURE_ROOT overrides it).

    It is deliberately fixed so that an antivirus exclusion can be added once for
    the machine instead of for a random temporary directory on every run.
    """
    root = os.environ.get("SBD_FIXTURE_ROOT")
    if not root:
        import tempfile
        root = os.path.join(tempfile.gettempdir(), "sbd-fixtures")
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        os.makedirs(root)
    return root


def payload(name):
    """Bytes of a sealed sample."""
    return unseal(name)


def write(root, rel, body):
    path = os.path.join(root, *rel.split("/"))
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    if isinstance(body, bytes):
        with open(path, "wb") as f:
            f.write(body)
    else:
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
    return path


def read(path):
    with open(path, "rb") as f:
        return f.read()


def build(name, planted=False, extra=None, binaries=True):
    """(Re)create the site `name` under fixtures_root() and return its path.

    `extra` adds {rel path: text or bytes} on top of the chosen set.
    """
    target = os.path.join(fixtures_root(), name)
    if os.path.exists(target):
        shutil.rmtree(target)
    os.makedirs(target)

    files = dict(CLEAN)
    if planted:
        files.update(dict((rel, payload(spec["payload"])) for rel, spec in PLANTED.items()))
    files.update(extra or {})
    for rel, body in files.items():
        write(target, rel, body)
    if binaries:
        for rel, raw in CLEAN_BINARY.items():
            write(target, rel, raw)
    return target


def wait_readables(site, rels, timeout=10.0):
    """(present, vanished) after giving real-time protection a moment to settle.

    A sample that antivirus quarantined right after it was written is not a
    detector failure, so the tests need to know about it explicitly.
    """
    rels = list(rels)
    deadline = time.time() + timeout
    while time.time() < deadline:
        gone = [r for r in rels if not _readable(os.path.join(site, *r.split("/")))]
        if not gone:
            return rels, []
        time.sleep(0.4)
    return [r for r in rels if _readable(os.path.join(site, *r.split("/")))], \
           [r for r in rels if not _readable(os.path.join(site, *r.split("/")))]


def _readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except (OSError, IOError):
        return False
