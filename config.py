MAX_FILE_SIZE=1_024_000

AGENT_REGEX = re.compile("|".join(map(re.escape, BAD_USER_AGENTS)), re.IGNORECASE)

REASON = "You have been blocked by SharkEyes Shield Lite"


BAD_PATHS = [
    # WordPress & CMS
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/wp-config.php", "/xmlrpc.php", "/wp-cron.php",
    "/wp-signup.php", "/wp-trackback.php",
    "/administrator", "/joomla", "/index.php",
    "/typo3", "/sites/default/files",
    "/drupal", "/concrete5", "/bitrix/admin",

    # Config & secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.aws", "/.aws/credentials", "/.git", "/.git/config",
    "/.htaccess", "/.htpasswd", "/.ssh", "/.bashrc",
    "/config.php", "/config.json", "/config.yml",
    "/database.yml", "/settings.py", "/local_settings.py",
    "/secrets.json", "/credentials.json", "/application.yml",
    "/app/config/database.php", "/.DS_Store",

    # Shell & RCE probes
    "/shell.php", "/cmd.php", "/c.php", "/b374k.php",
    "/r57.php", "/c99.php", "/wso.php", "/alfa.php",
    "/phpinfo.php", "/test.php", "/info.php", "/php.php",
    "/eval.php", "/exec.php", "/upload.php",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/php",

    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/admin.php", "/admincp", "/manager", "/panel",
    "/backend", "/cp", "/controlpanel",
    "/phpmyadmin", "/pma", "/myadmin", "/mysql",
    "/dbadmin", "/db/", "/mysqladmin", "/adminer.php",
    "/adminer", "/pgadmin"
]

BAD_PATHS = tuple(BAD_PATHS)
