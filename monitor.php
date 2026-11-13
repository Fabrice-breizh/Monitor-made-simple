<?php
/**
 * Monitor made Simple 1.5.0 — single-file Linux monitoring dashboard.
 * PHP 8.1+, no external assets or database.
 * HTTP Basic authentication is mandatory for the page and JSON API.
 *
 * Endpoints (all behind the same authentication):
 *   monitor.php                  the dashboard
 *   monitor.php?api=stats        JSON used by the dashboard
 *   monitor.php?api=health       JSON health summary; HTTP 503 when critical (&strict=1: also on warnings)
 *   monitor.php?api=metrics      Prometheus text format
 * Command line:
 *   php monitor.php --hash       asks for a password and prints the hash to put in ESM_PASSWORD_HASH
 *   php monitor.php --check      prints the health summary; exit code 0 = ok, 1 = warning, 2 = critical
 *   php monitor.php --check --quiet   prints nothing when everything is fine (handy with cron's MAILTO)
 */
declare(strict_types=1);

// =============================================================
// 01. CONFIGURATION
// =============================================================
const ESM_VERSION = '1.5.0';
const ESM_TITLE = 'Monitor made Simple';
const ESM_REFRESH_SECONDS = 5;
// Refresh interval while the browser tab is in the background (0 = pause until the tab is shown again).
const ESM_BACKGROUND_REFRESH_SECONDS = 30;
// The user name can also be set with the ESM_AUTH_USER environment variable.
const ESM_AUTH_USER = 'admin';
// After a successful login the browser gets a signed, HttpOnly cookie, so the (deliberately slow)
// password hash is not recomputed for every refresh. 0 = check the password on every request.
const ESM_SESSION_HOURS = 12;
// Failed logins allowed per client address in 10 minutes before a 5-minute lockout (0 = no limit).
const ESM_LOGIN_MAX_FAILURES = 8;
// true = refuse plain HTTP (HTTPS, or a reverse proxy sending X-Forwarded-Proto: https, is required).
const ESM_REQUIRE_HTTPS = false;
// Behind a reverse proxy that terminates HTTPS: set to true so its X-Forwarded-Proto header is
// trusted, and only when the request comes from one of these proxy addresses.
const ESM_TRUST_PROXY_HTTPS = false;
const ESM_TRUSTED_PROXIES = ['127.0.0.1', '::1'];

// Set a password hash via the ESM_PASSWORD_HASH environment variable (recommended),
// or paste a password_hash() result below. Never store a plaintext password here.
const ESM_PASSWORD_HASH = '';
// No hash means HTTP 401 for every request, including the JSON API.
// Never bypass authentication based on REMOTE_ADDR: reverse proxies may use loopback.

const ESM_SERVICES = [
    ['name' => 'SSH',   'host' => '127.0.0.1', 'port' => 22],
    ['name' => 'HTTP',  'host' => '127.0.0.1', 'port' => 80],
    ['name' => 'HTTPS', 'host' => '127.0.0.1', 'port' => 443],
];
const ESM_MAX_MOUNTS = 24;
const ESM_MAX_DISK_DEVICES = 24;
const ESM_MAX_PROCESSES = 5000;
const ESM_PROCESS_DETAIL_LIMIT = 20; // processes per list on the detail page (?view=processes)
const ESM_PROCESS_CACHE_SECONDS = 10;
const ESM_SERVICES_CACHE_SECONDS = 12;
const ESM_INODES_CACHE_SECONDS = 45;
const ESM_REMOTE_MOUNT_CACHE_SECONDS = 60;
const ESM_HTTP_CACHE_SECONDS = 60;
const ESM_HTTP_RETRY_SECONDS = 15;   // a failed HTTP check is retried sooner than a successful one
const ESM_HTTP_TIMEOUT_SECONDS = 1.2; // connection + response headers, per HTTP check
const ESM_GPU_CACHE_SECONDS = 10;
const ESM_SYSTEMD_CACHE_SECONDS = 60;
const ESM_REBOOT_CACHE_SECONDS = 120;
const ESM_HTTP_PROBES_PER_REQUEST = 1;
const ESM_MONITOR_REMOTE_MOUNTS = false;
// Keep remote mounts disabled by default; explicitly allow only trusted paths.
// FUSE network calls may still block when a 60-second cache entry expires.
const ESM_REMOTE_MOUNT_ALLOWLIST = [];

// Server-side alert thresholds (the CPU, memory and disk thresholds of the page are set in its settings;
// the values below are used by ?api=health, ?api=metrics and --check).
const ESM_WARN_MEMORY_PERCENT = 85;
const ESM_WARN_DISK_PERCENT = 85;
const ESM_WARN_CPU_CELSIUS = 85;   // critical 10 °C above
const ESM_WARN_DISK_CELSIUS = 60;  // critical 10 °C above
const ESM_WARN_LOAD_PER_CORE = 2.0; // 5-minute load average divided by logical cores; critical at twice this
// Ports listed here never raise the "database or API reachable from the network" warning.
const ESM_PORT_ALERT_IGNORE = [];

// Network page: recent web traffic, read from the access logs (shell patterns allowed).
// The web server's user must be able to read them; the page shows the command when it cannot.
const ESM_ACCESS_LOGS = ['/var/log/apache2/*access*.log', '/var/log/nginx/*access*.log'];
const ESM_ACCESS_LOG_MINUTES = 15;
// Apache's status page (mod_status), fetched from this machine only ('' = disabled).
// Use https://127.0.0.1/server-status and your site's name as host if the plain HTTP site redirects.
const ESM_APACHE_STATUS_URL = 'http://127.0.0.1/server-status';
const ESM_APACHE_STATUS_HOST = 'localhost';

// The local probe connects to a fixed loopback IP, never a user-supplied Host header.
// Set ESM_SELF_CHECK_HOST to the certificate's DNS name for HTTPS virtual hosts.
const ESM_SELF_CHECK = true;
const ESM_SELF_CHECK_IP = '127.0.0.1';
const ESM_SELF_CHECK_HOST = 'auto';
const ESM_SELF_CHECK_PORT = 0;
const ESM_SELF_CHECK_SCHEME = 'auto';

const ESM_HTTP_CHECKS = [
    // ['name' => 'Main site', 'ip' => '127.0.0.1', 'host' => 'example.com',
    //  'scheme' => 'https', 'port' => 443, 'path' => '/health'],
];


// =============================================================
// 02. HTTP AUTHENTICATION AND BROWSER SECURITY
// =============================================================
function esmNonce(): string
{
    static $nonce = null;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(18));
    }
    return $nonce;
}

const ESM_CLI = PHP_SAPI === 'cli';

if (!ESM_CLI) {
header('X-Content-Type-Options: nosniff');
// Marker for the local self-check. It carries no version: it is sent before authentication.
header('X-Monitor-Made-Simple: 1');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Cache-Control: private, no-store, max-age=0');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header(
    "Content-Security-Policy: default-src 'none'; " .
    "script-src 'nonce-" . esmNonce() . "'; " .
    "style-src 'nonce-" . esmNonce() . "'; " .
    "img-src 'self' data:; connect-src 'self'; " .
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
);
}

function esmPasswordHash(): string
{
    $env = getenv('ESM_PASSWORD_HASH');
    return $env !== false && $env !== '' ? $env : ESM_PASSWORD_HASH;
}

function esmAuthUser(): string
{
    $env = getenv('ESM_AUTH_USER');
    return $env !== false && $env !== '' ? $env : ESM_AUTH_USER;
}

// [user, password] sent by the browser, or null when the request carries no credentials.
function esmCredentials(): ?array
{
    $user = (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
    $password = (string) ($_SERVER['PHP_AUTH_PW'] ?? '');
    if ($user === '') {
        $header = (string) ($_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (strlen($header) <= 4096 && preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/i', $header, $m)) {
            $decoded = base64_decode($m[1], true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$user, $password] = explode(':', $decoded, 2);
            }
        }
    }
    return $user === '' && $password === '' ? null : [$user, $password];
}

// Address used to count failed logins. X-Forwarded-For is only read behind a trusted proxy,
// and only its last entry (the one that proxy added itself).
function esmClientAddress(): string
{
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    if (ESM_TRUST_PROXY_HTTPS && in_array($remote, ESM_TRUSTED_PROXIES, true)) {
        $chain = explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
        $last = trim((string) end($chain));
        if (filter_var($last, FILTER_VALIDATE_IP)) return $last;
    }
    return $remote;
}

// Random key that signs session cookies. It lives in the private cache directory.
function esmSessionSecret(): ?string
{
    $dir = esmCacheDirectory();
    if ($dir === null) return null;
    $file = $dir . '/session.key';
    $secret = esmRead($file, 128);
    if ($secret !== null && strlen($secret) === 64 && ctype_xdigit($secret)) return $secret;
    $secret = bin2hex(random_bytes(32));
    $temp = @tempnam($dir, '.tmp-');
    if ($temp === false) return null;
    @chmod($temp, 0600);
    if (@file_put_contents($temp, $secret, LOCK_EX) === false || !@rename($temp, $file)) {
        @unlink($temp);
        return null;
    }
    return $secret;
}
function esmSessionCookieName(): string
{
    return 'mms_session_' . substr(hash('sha256', __FILE__), 0, 8);
}
// The signature covers the password hash: changing the password ends every session.
function esmSessionSignature(int $expires, string $secret): string
{
    return hash_hmac('sha256', $expires . '|' . esmAuthUser() . '|' . esmPasswordHash(), $secret);
}
function esmSessionValid(): bool
{
    if (ESM_SESSION_HOURS <= 0) return false;
    $cookie = (string) ($_COOKIE[esmSessionCookieName()] ?? '');
    if (!preg_match('/\A(\d{10,11})\.([0-9a-f]{64})\z/', $cookie, $m)) return false;
    $expires = (int) $m[1];
    if ($expires < time() || $expires > time() + ESM_SESSION_HOURS * 3600 + 60) return false;
    $secret = esmSessionSecret();
    return $secret !== null && hash_equals(esmSessionSignature($expires, $secret), $m[2]);
}
function esmSessionStart(): void
{
    if (ESM_SESSION_HOURS <= 0 || headers_sent()) return;
    $secret = esmSessionSecret();
    if ($secret === null) return;
    $expires = time() + ESM_SESSION_HOURS * 3600;
    $path = (string) ($_SERVER['SCRIPT_NAME'] ?? '/');
    if (!preg_match('#^/[a-zA-Z0-9/._~-]{0,255}$#', $path)) $path = '/';
    setcookie(esmSessionCookieName(), $expires . '.' . esmSessionSignature($expires, $secret), [
        'expires' => $expires, 'path' => $path, 'secure' => esmIsHttps(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
}

// Failed logins per client address: [count, start of the 10-minute window, locked until].
function esmLoginFailureFile(): ?string
{
    $dir = esmCacheDirectory();
    return $dir === null ? null : $dir . '/login-' . substr(hash('sha256', esmClientAddress()), 0, 24) . '.json';
}
function esmLoginLockedSeconds(): int
{
    if (ESM_LOGIN_MAX_FAILURES <= 0) return 0;
    $file = esmLoginFailureFile();
    $state = $file !== null ? json_decode((string) esmRead($file, 512), true) : null;
    return is_array($state) ? max(0, (int) ($state['until'] ?? 0) - time()) : 0;
}
function esmLoginFailed(): void
{
    if (ESM_LOGIN_MAX_FAILURES <= 0) return;
    $file = esmLoginFailureFile();
    if ($file === null) return;
    $state = json_decode((string) esmRead($file, 512), true);
    if (!is_array($state) || time() - (int) ($state['since'] ?? 0) > 600) $state = ['count' => 0, 'since' => time(), 'until' => 0];
    $state['count'] = (int) $state['count'] + 1;
    if ($state['count'] >= ESM_LOGIN_MAX_FAILURES) $state = ['count' => 0, 'since' => time(), 'until' => time() + 300];
    @file_put_contents($file, json_encode($state), LOCK_EX);
    @chmod($file, 0600);
    if (random_int(1, 50) === 1) { // occasional cleanup of old counters
        foreach (glob(dirname($file) . '/login-*.json') ?: [] as $old) {
            if (time() - (int) @filemtime($old) > 86400) @unlink($old);
        }
    }
}

// 'ok', 'denied' (no or wrong credentials) or 'locked' (too many failures from this address).
function esmAuthenticate(): string
{
    $hash = esmPasswordHash();
    if ($hash === '') return 'denied';
    if (esmSessionValid()) return 'ok';
    $credentials = esmCredentials();
    if ($credentials === null) return 'denied';
    if (esmLoginLockedSeconds() > 0) return 'locked';
    // Both checks always run, so the response time does not reveal whether the user name exists.
    $userOk = hash_equals(esmAuthUser(), $credentials[0]);
    $passwordOk = password_verify($credentials[1], $hash);
    if ($userOk && $passwordOk) {
        esmSessionStart();
        return 'ok';
    }
    esmLoginFailed();
    return 'denied';
}

function esmIsHttps(): bool
{
    $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
    if ($https !== '' && $https !== 'off') return true;
    if ((string) ($_SERVER['REQUEST_SCHEME'] ?? '') === 'https') return true;
    if (!ESM_TRUST_PROXY_HTTPS || !in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), ESM_TRUSTED_PROXIES, true)) return false;
    return strtolower(trim(explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0])) === 'https';
}
// The functions of section 03 are needed by the authentication below; PHP declares top-level
// functions of the file before running it, so they can be called from here.
if (!ESM_CLI) {
    if (ESM_REQUIRE_HTTPS && !esmIsHttps()) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "HTTPS is required for this dashboard.\n";
        exit;
    }
    // Tells the browser to use HTTPS for the next visits (it cannot protect a very first plain HTTP visit).
    if (esmIsHttps()) header('Strict-Transport-Security: max-age=31536000');

    $esmAuth = esmAuthenticate();
    if ($esmAuth !== 'ok') {
        header('Content-Type: text/plain; charset=utf-8');
        if ($esmAuth === 'locked') {
            http_response_code(429);
            header('Retry-After: ' . max(1, esmLoginLockedSeconds()));
            echo "Monitor made Simple: too many failed logins. Try again in a few minutes.\n";
            exit;
        }
        http_response_code(401);
        if (esmPasswordHash() !== '') {
            header('WWW-Authenticate: Basic realm="Monitor made Simple", charset="UTF-8"');
        }
        echo "Monitor made Simple: access denied. Configure ESM_PASSWORD_HASH and use HTTPS.\n";
        exit;
    }
}

// =============================================================
// 03. DEFENSIVE FILE READING AND PARSING
// =============================================================
function esmRead(string $path, int $maxBytes = 1048576): ?string
{
    if (!is_readable($path) || !is_file($path)) {
        return null;
    }
    $handle = @fopen($path, 'rb');
    if ($handle === false) {
        return null;
    }
    $text = @fread($handle, $maxBytes);
    fclose($handle);
    return $text === false ? null : $text;
}

function esmCacheDirectory(): ?string
{
    static $checked = false, $directory = null;
    if ($checked) return $directory;
    $checked = true;
    // One directory per system user: the web server and a cron job never share (or fight over) files.
    $owner = function_exists('posix_geteuid') ? '-' . posix_geteuid() : '';
    $base = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
        . 'monitor-made-simple-' . substr(hash('sha256', __FILE__), 0, 20) . $owner;
    if (!is_dir($base)) @mkdir($base, 0700);
    if (is_link($base) || !is_dir($base) || !is_writable($base)) return null;
    $perms = @fileperms($base);
    if ($perms === false || ($perms & 0077) !== 0) return null;
    if (function_exists('posix_geteuid') && @fileowner($base) !== posix_geteuid()) return null;
    return $directory = $base;
}
function esmCacheRead(string $key): ?array
{
    $dir = esmCacheDirectory();
    if ($dir === null) return null;
    $text = esmRead($dir . '/' . $key . '.json', 2097152);
    if ($text === null) return null;
    $value = json_decode($text, true);
    return is_array($value) ? $value : null;
}
function esmCacheWrite(string $key, array $value): void
{
    $dir = esmCacheDirectory();
    if ($dir === null) return;
    $json = json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE);
    if (!is_string($json) || strlen($json) > 2000000) return;
    $temp = @tempnam($dir, '.tmp-');
    if ($temp === false) return;
    @chmod($temp, 0600);
    $written = @file_put_contents($temp, $json, LOCK_EX);
    if ($written === false || !@rename($temp, $dir . '/' . $key . '.json')) @unlink($temp);
}
// With PHP-FPM, slow collections are refreshed after the response has been sent:
// the page gets the previous result immediately and the next refresh shows the new one.
function esmCanDefer(): bool
{
    return !ESM_CLI && function_exists('fastcgi_finish_request');
}
function esmRunDeferred(): void
{
    $tasks = $GLOBALS['esmDeferredTasks'] ?? [];
    $GLOBALS['esmDeferredTasks'] = [];
    if (!$tasks) return;
    @fastcgi_finish_request();
    @ignore_user_abort(true);
    foreach ($tasks as $task) {
        try { $task(); } catch (Throwable $error) { error_log('Monitor made Simple: deferred refresh failed (' . get_class($error) . ')'); }
    }
}
function esmCachedCollect(string $key, int $seconds, callable $collector, bool $mayDefer = true): array
{
    $fresh = static fn(?array $entry): bool => $entry !== null && isset($entry['at'], $entry['data'])
        && is_array($entry['data']) && (time() - (int) $entry['at']) >= 0 && (time() - (int) $entry['at']) < $seconds;
    $previous = esmCacheRead($key);
    if ($fresh($previous)) return $previous['data'];
    // A recent result exists: serve it now and refresh it once the response is sent.
    if ($mayDefer && esmCanDefer() && $previous !== null && is_array($previous['data'] ?? null)
        && abs(time() - (int) ($previous['at'] ?? 0)) < max(120, 5 * $seconds)) {
        $GLOBALS['esmDeferredTasks'][$key] = static fn(): array => esmCachedCollect($key, $seconds, $collector, false);
        return $previous['data'];
    }
    // Only one request collects at a time. The others reuse the previous result instead of
    // collecting again (this also keeps CPU percentages, which compare two samples, consistent).
    $dir = esmCacheDirectory();
    $lock = $dir !== null ? @fopen($dir . '/' . $key . '.lock', 'c') : false;
    if ($lock !== false) {
        if (!@flock($lock, LOCK_EX | LOCK_NB)) {
            if ($previous !== null && is_array($previous['data'] ?? null)) { fclose($lock); return $previous['data']; }
            @flock($lock, LOCK_EX); // nothing to serve yet: wait for the running collection
        }
        $again = esmCacheRead($key);
        if ($fresh($again)) { @flock($lock, LOCK_UN); fclose($lock); return $again['data']; }
    }
    try {
        $data = $collector();
        if (is_array($data)) esmCacheWrite($key, ['at' => time(), 'data' => $data]);
    } finally {
        if ($lock !== false) { @flock($lock, LOCK_UN); @fclose($lock); }
    }
    return is_array($data) ? $data : [];
}

function esmNumber(?string $text): ?float
{
    return $text !== null && is_numeric(trim($text)) ? (float) trim($text) : null;
}

function esmMountName(string $raw): string
{
    return preg_replace_callback(
        '/\\\\([0-7]{3})/',
        static fn(array $match): string => chr(octdec($match[1])),
        $raw
    ) ?? $raw;
}

function esmMemInfo(): array
{
    $text = esmRead('/proc/meminfo', 65536);
    if ($text === null) {
        return [];
    }
    preg_match_all('/^([A-Za-z_()]+):\s+(\d+)\s+kB/m', $text, $rows, PREG_SET_ORDER);
    $result = [];
    foreach ($rows as $row) {
        $result[$row[1]] = (int) $row[2] * 1024;
    }
    return $result;
}

// =============================================================
// 04. SYSTEM AND CPU IDENTIFICATION
// =============================================================
function esmCpuTopology(?string $contents): array
{
    static $cache = [];
    $key = md5((string) $contents);
    if (isset($cache[$key])) return $cache[$key];
    $sockets = []; $cores = [];
    foreach (preg_split('/\n\s*\n/', (string) $contents) ?: [] as $block) {
        $socket = preg_match('/^physical id\s*:\s*(\d+)/mi', $block, $m) ? $m[1] : null;
        $core = preg_match('/^core id\s*:\s*(\d+)/mi', $block, $n) ? $n[1] : null;
        if ($socket !== null) $sockets[$socket] = true;
        if ($socket !== null && $core !== null) $cores[$socket . ':' . $core] = true;
    }
    return $cache[$key] = [
        'sockets' => $sockets ? count($sockets) : null,
        'cores' => $cores ? count($cores) : null,
    ];
}
function esmCpuModel(?string $contents): ?string
{
    if ($contents === null) {
        return null;
    }
    foreach (['model name', 'Hardware', 'Processor', 'cpu model'] as $key) {
        if (preg_match('/^' . preg_quote($key, '/') . '\s*:\s*(.+)$/mi', $contents, $m)) {
            $candidate = trim($m[1]);
            if ($candidate !== '' && !ctype_digit($candidate)) {
                return mbSafeLimit($candidate, 160);
            }
        }
    }
    return null;
}

function mbSafeLimit(string $value, int $max): string
{
    if (strlen($value) <= $max) return $value;
    $value = substr($value, 0, $max);
    while ($value !== '' && !preg_match('//u', $value)) {
        $value = substr($value, 0, -1);
    }
    return $value;
}

// Facts that only change with a reboot or an upgrade: read once every five minutes.
function esmSystemStatic(): array
{
    return esmCachedCollect('system-static', 300, static function (): array {
        $os = 'Linux';
        $release = esmRead('/etc/os-release', 16384);
        if ($release !== null && preg_match('/^PRETTY_NAME=(.+)$/m', $release, $m)) {
            $os = trim(trim($m[1]), "\"'");
        }
        $cpuInfo = esmRead('/proc/cpuinfo', 4194304);
        $cores = $cpuInfo !== null ? preg_match_all('/^processor\s*:/mi', $cpuInfo) : false;
        $topology = esmCpuTopology($cpuInfo);
        return [
            'os' => mbSafeLimit($os, 160),
            'cpuModel' => esmCpuModel($cpuInfo),
            'logicalCores' => $cores !== false && $cores > 0 ? $cores : null,
            'cpuSockets' => $topology['sockets'],
            'physicalCores' => $topology['cores'],
        ];
    }, false);
}
function esmSystem(): array
{
    $static = esmSystemStatic();
    $uptimeText = esmRead('/proc/uptime', 64);
    $uptime = $uptimeText !== null && preg_match('/^([\d.]+)/', $uptimeText, $m)
        ? (int) (float) $m[1] : null;
    $load = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
    return [
        'hostname' => function_exists('gethostname') ? (gethostname() ?: null) : null,
        'os' => $static['os'] ?? 'Linux',
        'kernel' => function_exists('php_uname') ? php_uname('r') : null,
        'architecture' => function_exists('php_uname') ? php_uname('m') : null,
        'php' => PHP_VERSION,
        'uptimeSeconds' => $uptime,
        'cpuModel' => $static['cpuModel'] ?? null,
        'logicalCores' => $static['logicalCores'] ?? null,
        'cpuSockets' => $static['cpuSockets'] ?? null,
        'physicalCores' => $static['physicalCores'] ?? null,
        'load' => is_array($load) ? array_map('floatval', $load) : null,
        'time' => date(DATE_ATOM),
    ];
}

// =============================================================
// 05. CPU COUNTERS FROM /proc/stat
// =============================================================
function esmCpu(): array
{
    $text = esmRead('/proc/stat', 1048576);
    if ($text === null) {
        return ['total' => null, 'idle' => null, 'cores' => []];
    }
    $aggregate = ['total' => null, 'idle' => null];
    $cores = [];
    foreach (explode("\n", $text) as $line) {
        if (!preg_match('/^(cpu\d*)\s+(.+)$/', $line, $m)) {
            continue;
        }
        $parts = preg_split('/\s+/', trim($m[2]));
        $values = array_map('intval', $parts ?: []);
        if (count($values) < 4) {
            continue;
        }
        $sample = [
            'total' => array_sum(array_slice($values, 0, min(8, count($values)))),
            'idle' => $values[3] + ($values[4] ?? 0),
        ];
        if ($m[1] === 'cpu') {
            $aggregate = $sample;
        } else {
            $cores[] = ['id' => $m[1]] + $sample;
        }
    }
    return $aggregate + ['cores' => $cores];
}

// =============================================================
// 06. MEMORY AND SWAP
// =============================================================
function esmMemory(): array
{
    $values = esmMemInfo();
    $total = $values['MemTotal'] ?? null;
    $available = $values['MemAvailable'] ?? null;
    if ($available === null && isset($values['MemFree'])) {
        $available = $values['MemFree'] + ($values['Buffers'] ?? 0) + ($values['Cached'] ?? 0);
    }
    $swapTotal = $values['SwapTotal'] ?? null;
    $swapFree = $values['SwapFree'] ?? null;
    return [
        'ram' => $total !== null && $available !== null ? [
            'total' => $total,
            'used' => max(0, $total - $available),
            'available' => $available,
            'cached' => $values['Cached'] ?? null,
        ] : null,
        'swap' => $swapTotal !== null && $swapFree !== null ? [
            'total' => $swapTotal,
            'used' => max(0, $swapTotal - $swapFree),
            'available' => $swapFree,
        ] : null,
        'swapActivity' => esmSwapActivity(),
    ];
}

function esmSwapActivity(): ?array
{
    $text = esmRead('/proc/vmstat', 131072);
    if ($text === null) {
        return null;
    }
    $in = preg_match('/^pswpin\s+(\d+)$/m', $text, $mIn) ? (float) $mIn[1] : null;
    $out = preg_match('/^pswpout\s+(\d+)$/m', $text, $mOut) ? (float) $mOut[1] : null;
    return $in !== null && $out !== null ? ['pageIn' => $in, 'pageOut' => $out] : null;
}

// =============================================================
// 07. FILESYSTEM CAPACITY AND MOUNT DEDUPLICATION
// =============================================================
function esmDisks(): array
{
    if (!function_exists('disk_total_space') || !function_exists('disk_free_space')) {
        return [];
    }
    $text = esmRead('/proc/mounts', 524288);
    if ($text === null) {
        return [];
    }
    $excluded = [
        'proc', 'sysfs', 'devtmpfs', 'devpts', 'tmpfs', 'cgroup', 'cgroup2',
        'securityfs', 'debugfs', 'tracefs', 'configfs', 'fusectl', 'mqueue',
        'hugetlbfs', 'pstore', 'autofs', 'rpc_pipefs', 'binfmt_misc',
        'nsfs', 'squashfs', 'bpf', 'efivarfs', 'ramfs', 'selinuxfs',
    ];
    $groups = [];
    $seenMounts = [];
    foreach (explode("\n", $text) as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if (!$fields || count($fields) < 3) {
            continue;
        }
        [$device, $rawPoint, $type] = $fields;
        if (in_array($type, $excluded, true)) continue;
        $mount = esmMountName($rawPoint);
        $remote = in_array($type, [
            'nfs','nfs4','cifs','smbfs','sshfs','9p','ceph','glusterfs',
            'davfs','fuse.sshfs','fuse.rclone','fuse.ceph','fuse.glusterfs',
        ], true) || str_starts_with($type, 'fuse.');
        if ($remote && !ESM_MONITOR_REMOTE_MOUNTS
            && !in_array($mount, ESM_REMOTE_MOUNT_ALLOWLIST, true)) continue;
        if ($type === 'overlay' && $mount !== '/') {
            continue;
        }
        if (isset($seenMounts[$mount])) {
            continue;
        }
        $seenMounts[$mount] = true;
        if ($remote) {
            // Remote statvfs can block: cache the entire set of filesystem calls.
            $cacheKey = 'remote-disk-' . substr(hash('sha256', $mount . "\0" . $type), 0, 24);
            $space = esmCachedCollect($cacheKey, ESM_REMOTE_MOUNT_CACHE_SECONDS,
                static function () use ($mount): array {
                    if (!is_dir($mount) || !is_readable($mount)) return [];
                    $total = @disk_total_space($mount);
                    $free = @disk_free_space($mount);
                    $stat = @stat($mount);
                    if (!is_numeric($total) || !is_numeric($free) || $total <= 0) return [];
                    return ['total' => (int) $total, 'free' => (int) $free,
                        'dev' => $stat !== false ? (string) $stat['dev'] : null];
                });
            if (!$space) continue;
            $total = $space['total'];
            $free = $space['free'];
            $dev = $space['dev'];
        } else {
            if (!is_dir($mount) || !is_readable($mount)) continue;
            $total = @disk_total_space($mount);
            $free = @disk_free_space($mount);
            $stat = @stat($mount);
            if (!is_numeric($total) || !is_numeric($free) || $total <= 0) continue;
            $total = (int) $total;
            $free = (int) $free;
            $dev = $stat !== false ? (string) $stat['dev'] : null;
        }
        // Same filesystem id = same filesystem (bind mounts...). Free space is not part of the key:
        // it can change between two measurements of the same filesystem.
        $key = $dev !== null ? 'dev:' . $dev . '|' . $total : $device . '|' . $type . '|' . $total . '|' . $free;
        if (!isset($groups[$key])) {
            if (count($groups) >= ESM_MAX_MOUNTS) {
                continue;
            }
            $groups[$key] = [
                'device' => esmMountName($device),
                'mount' => $mount,
                'mounts' => [$mount],
                'type' => $type,
                'total' => $total,
                'used' => max(0, $total - $free),
                'free' => $free,
            ];
        } else {
            $groups[$key]['mounts'][] = $mount;
            if ($mount === '/' || strlen($mount) < strlen($groups[$key]['mount'])) {
                $groups[$key]['mount'] = $mount;
            }
        }
    }
    $out = array_values($groups);
    $inodes = esmInodes();
    foreach ($out as &$disk) {
        $disk['inodes'] = $inodes[$disk['mount']] ?? null;
        if ($disk['inodes'] === null) {
            foreach ($disk['mounts'] as $alias) {
                if (isset($inodes[$alias])) { $disk['inodes'] = $inodes[$alias]; break; }
            }
        }
    }
    unset($disk);
    usort($out, static function (array $a, array $b): int {
        if ($a['mount'] === '/') return -1;
        if ($b['mount'] === '/') return 1;
        return strnatcasecmp($a['mount'], $b['mount']);
    });
    return array_slice($out, 0, ESM_MAX_MOUNTS);
}

// Runs a fixed command (never built from the request) with a hard timeout and output cap.
function esmRunCommand(array $command, float $timeout, int $maxBytes): ?string
{
    if (!function_exists('proc_open')) return null;
    $spec = [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']];
    // Fixed environment: the output is parsed, so it must not depend on the server's language.
    $environment = ['LC_ALL' => 'C', 'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'];
    $proc = @proc_open($command, $spec, $pipes, null, $environment);
    if (!is_resource($proc)) return null;
    stream_set_blocking($pipes[1], false);
    $text = '';
    $deadline = microtime(true) + $timeout;
    $timedOut = false;
    while (true) {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) { $timedOut = true; break; }
        $reads = [$pipes[1]]; $writes = null; $except = null;
        @stream_select($reads, $writes, $except, 0, min(150000, (int) ($remaining * 1000000)));
        if ($reads) {
            $chunk = @fread($pipes[1], 8192);
            if (is_string($chunk)) $text .= $chunk;
            if (strlen($text) > $maxBytes) { $timedOut = true; break; }
        }
        if (feof($pipes[1])) break;
        $status = @proc_get_status($proc);
        if (is_array($status) && !$status['running'] && !$reads) break;
    }
    if ($timedOut) {
        @proc_terminate($proc);
        usleep(20000);
        $status = @proc_get_status($proc);
        if (is_array($status) && $status['running']) @proc_terminate($proc, 9);
    }
    fclose($pipes[1]);
    @proc_close($proc);
    return $timedOut ? null : $text;
}

// =============================================================
// 08. INODE METRICS
// =============================================================
function esmInodes(): array
{
    return esmCachedCollect('inodes', ESM_INODES_CACHE_SECONDS, static function (): array {
        $binary = is_executable('/usr/bin/df') ? '/usr/bin/df'
            : (is_executable('/bin/df') ? '/bin/df' : null);
        if ($binary === null || !function_exists('proc_open')) return [];
        $text = esmRunCommand([$binary, '-Pi', '-l'], 0.9, 131072);
        if ($text === null) return [];
        $out = [];
        foreach (explode("\n", $text) as $line) {
            if (!preg_match('/^\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+%\s+(.+)$/', trim($line), $m)) continue;
            $out[$m[4]] = ['total' => (float) $m[1], 'used' => (float) $m[2], 'free' => (float) $m[3]];
        }
        return $out;
    });
}

// =============================================================
// 09. DISK I/O
// =============================================================
function esmDiskIo(): array
{
    $text = esmRead('/proc/diskstats', 524288);
    if ($text === null) {
        return [];
    }
    $out = [];
    foreach (explode("\n", $text) as $line) {
        $fields = preg_split('/\s+/', trim($line));
        if (!$fields || count($fields) < 14) {
            continue;
        }
        $name = $fields[2];
        if (!preg_match('/^[a-zA-Z0-9_.-]{1,48}$/', $name)
            || !is_dir('/sys/block/' . $name)
            || preg_match('/^(loop|ram|zram|fd)\d+$/', $name)) {
            continue;
        }
        if (!ctype_digit($fields[5]) || !ctype_digit($fields[9])) {
            continue;
        }
        $out[] = [
            'name' => $name,
            'readBytes' => (float) $fields[5] * 512,
            'writeBytes' => (float) $fields[9] * 512,
            'readOps' => (float) $fields[3],
            'writeOps' => (float) $fields[7],
            'busyMs' => (float) $fields[12],
            'virtual' => (bool) preg_match('/^(dm-|md)/', $name),
        ];
    }
    usort($out, static fn(array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));
    return array_slice($out, 0, ESM_MAX_DISK_DEVICES);
}

// =============================================================
// 09b. NETWORK INTERFACES
// =============================================================
function esmNetworkCategory(string $name): string
{
    if ($name === 'lo') return 'loopback';
    if (preg_match('/^(wg\d*|tun\w*|tap\w*|tailscale\w*|zt\w*|ppp\w*)$/i', $name)) return 'vpn';
    if (is_dir('/sys/class/net/' . $name . '/device')) return 'physical';
    return 'virtual';
}

function esmNetwork(): array
{
    $text = esmRead('/proc/net/dev', 262144);
    if ($text === null) {
        return [];
    }
    $out = [];
    $metadata = function_exists('net_get_interfaces') ? @net_get_interfaces() : [];
    if (!is_array($metadata)) $metadata = [];
    foreach (array_slice(explode("\n", $text), 2) as $line) {
        if (!str_contains($line, ':')) continue;
        [$rawName, $rawCounters] = explode(':', $line, 2);
        $name = trim($rawName);
        if (!preg_match('/^[a-zA-Z0-9_.:-]{1,48}$/', $name)) continue;
        $fields = preg_split('/\s+/', trim($rawCounters));
        if (!$fields || count($fields) < 16 || !ctype_digit($fields[0]) || !ctype_digit($fields[8])) continue;
        $state = trim(esmRead('/sys/class/net/' . $name . '/operstate', 32) ?? 'unknown');
        if ($state === 'unknown' && esmNetworkCategory($name) === 'vpn') {
            $flagsText = esmRead('/sys/class/net/' . $name . '/flags', 32);
            if ($flagsText !== null && preg_match('/\A0x[0-9a-f]+\z/i', trim($flagsText))) {
                $flags = hexdec(trim($flagsText));
                if (((int) $flags & 0x1) !== 0) $state = 'enabled';
            }
        }
        $details = $metadata[$name] ?? [];
        $ipv4 = []; $ipv6 = [];
        foreach (($details['unicast'] ?? []) as $address) {
            $ip = $address['address'] ?? null;
            if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) continue;
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ipv4[] = $ip;
            else $ipv6[] = $ip;
        }
        $mac = esmRead('/sys/class/net/' . $name . '/address', 64);
        $mtu = esmNumber(esmRead('/sys/class/net/' . $name . '/mtu', 64));
        $linkSpeed = esmNumber(esmRead('/sys/class/net/' . $name . '/speed', 64));
        $out[] = [
            'name' => $name,
            'rx' => (float) $fields[0],
            'tx' => (float) $fields[8],
            'rxErrors' => (float) $fields[2],
            'txErrors' => (float) $fields[10],
            'rxDropped' => (float) $fields[3],
            'txDropped' => (float) $fields[11],
            'state' => $state,
            'category' => esmNetworkCategory($name),
            'ipv4' => array_slice(array_values(array_unique($ipv4)), 0, 4),
            'ipv6' => array_slice(array_values(array_unique($ipv6)), 0, 4),
            'mac' => $mac !== null && preg_match('/^[0-9a-f:]{17}$/i', trim($mac)) ? trim($mac) : null,
            'mtu' => $mtu !== null && $mtu > 0 ? (int) $mtu : null,
            'linkMbps' => $linkSpeed !== null && $linkSpeed > 0 && $linkSpeed <= 800000 ? $linkSpeed : null,
        ];
    }
    return $out;
}

// =============================================================
// 10. PRESSURE STALL INFORMATION
// =============================================================
function esmPressure(): array
{
    $out = [];
    foreach (['cpu', 'memory', 'io'] as $type) {
        $text = esmRead('/proc/pressure/' . $type, 2048);
        if ($text === null || !preg_match('/^some\s+avg10=([\d.]+)\s+avg60=([\d.]+)\s+avg300=([\d.]+)/m', $text, $m)) {
            $out[$type] = null;
            continue;
        }
        $full = preg_match('/^full\s+avg10=([\d.]+)\s+avg60=([\d.]+)\s+avg300=([\d.]+)/m', $text, $f)
            ? ['avg10' => (float) $f[1], 'avg60' => (float) $f[2], 'avg300' => (float) $f[3]] : null;
        $out[$type] = ['avg10' => (float)$m[1], 'avg60' => (float)$m[2], 'avg300' => (float)$m[3], 'full' => $full];
    }
    return $out;
}

// =============================================================
// 11. HARDWARE SENSORS
// =============================================================
function esmTemperatures(string $root = ''): array
{
    if (!function_exists('glob')) return [];
    $cpu = [];
    $other = [];
    $chips = glob($root . '/sys/class/hwmon/hwmon*', GLOB_ONLYDIR) ?: [];
    natsort($chips);
    foreach ($chips as $dir) {
        $chip = strtolower(trim((string) esmRead($dir . '/name', 128)));
        if (in_array($chip, ['amdgpu', 'radeon', 'nouveau', 'i915', 'xe'], true)) continue; // shown with the GPU
        $sensors = [];
        foreach (glob($dir . '/temp*_input') ?: [] as $path) {
            $value = esmNumber(esmRead($path, 64));
            if ($value === null) continue;
            $celsius = $value / 1000;
            if ($celsius < -40 || $celsius > 130) continue;
            $label = trim((string) esmRead(substr($path, 0, -6) . '_label', 128));
            $sensors[] = ['label' => $label, 'celsius' => $celsius];
        }
        if (!$sensors) continue;
        $hottest = max(array_column($sensors, 'celsius'));
        $pick = static function (string $pattern) use ($sensors): ?float {
            foreach ($sensors as $sensor) if (preg_match($pattern, $sensor['label'])) return $sensor['celsius'];
            return null;
        };
        if (in_array($chip, ['coretemp', 'k10temp', 'zenpower', 'cpu_thermal', 'cpu-thermal', 'soc_thermal', 'scpi_sensors'], true)) {
            // One value per processor package: the package sensor if there is one, else the hottest core.
            $value = $pick('/^(package id|tdie)/i') ?? $pick('/^tctl/i') ?? $hottest;
            $cpu[] = ['kind' => 'cpu', 'celsius' => round($value, 1)];
            continue;
        }
        $link = @readlink($dir . '/device');
        $device = is_string($link) ? basename($link) : '';
        $kind = match (true) {
            in_array($chip, ['nvme', 'drivetemp'], true) => 'disk',
            $chip === 'acpitz' => 'board',
            str_starts_with($chip, 'pch_') => 'chipset',
            str_starts_with($chip, 'iwlwifi') || str_starts_with($chip, 'mt7') || str_starts_with($chip, 'ath') => 'wifi',
            default => 'other',
        };
        $value = $kind === 'disk' ? ($pick('/^composite/i') ?? $hottest) : $hottest;
        $name = $kind === 'disk' && preg_match('/^(nvme\d+|\d+:\d+:\d+:\d+)$/', $device) ? $device : ($kind === 'other' ? $chip : '');
        $other[] = ['kind' => $kind, 'name' => mbSafeLimit($name, 40), 'celsius' => round($value, 1)];
    }
    if (!$cpu && !$other) {
        // No hwmon (some ARM boards, containers): fall back to thermal zones.
        $zones = glob($root . '/sys/class/thermal/thermal_zone*', GLOB_ONLYDIR) ?: [];
        natsort($zones);
        foreach ($zones as $zone) {
            $value = esmNumber(esmRead($zone . '/temp', 64));
            if ($value === null) continue;
            $celsius = abs($value) >= 1000 ? $value / 1000 : $value;
            if ($celsius < -40 || $celsius > 130) continue;
            $type = strtolower(trim((string) esmRead($zone . '/type', 128)));
            if (preg_match('/^(x86_pkg_temp|cpu|soc)/', $type)) $cpu[] = ['kind' => 'cpu', 'celsius' => round($celsius, 1)];
            else $other[] = ['kind' => $type === 'acpitz' ? 'board' : 'other', 'name' => mbSafeLimit($type, 40), 'celsius' => round($celsius, 1)];
        }
    }
    foreach ($cpu as $index => &$entry) $entry['index'] = $index;
    unset($entry);
    return array_slice(array_merge($cpu, $other), 0, 16);
}

// =============================================================
// 11b. GRAPHICS CARDS (sysfs; nvidia-smi for the NVIDIA driver)
// =============================================================
function esmGpus(): array
{
    return esmCachedCollect('gpus', ESM_GPU_CACHE_SECONDS, static fn(): array => esmCollectGpus());
}
function esmGpuVendor(string $id): ?string
{
    return [
        '0x10de' => 'NVIDIA', '0x1002' => 'AMD', '0x8086' => 'Intel', '0x1a03' => 'ASPEED',
        '0x102b' => 'Matrox', '0x15ad' => 'VMware', '0x1af4' => 'Virtio', '0x1234' => 'QEMU',
        '0x1414' => 'Microsoft', '0x80ee' => 'VirtualBox', '0x5143' => 'Qualcomm', '0x14e4' => 'Broadcom',
    ][$id] ?? null;
}
function esmPciName(string $vendor, string $device, string $root = ''): ?string
{
    if (!preg_match('/^0x([0-9a-f]{4})$/', $vendor, $v) || !preg_match('/^0x([0-9a-f]{4})$/', $device, $d)) return null;
    $lookup = static function () use ($v, $d, $root): array {
        foreach ([$root . '/usr/share/misc/pci.ids', $root . '/usr/share/hwdata/pci.ids', $root . '/usr/share/pci.ids'] as $file) {
            $handle = @fopen($file, 'rb');
            if ($handle === false) continue;
            $inVendor = false;
            $name = null;
            while (($line = fgets($handle, 512)) !== false) {
                if ($line === '' || $line[0] === '#') continue;
                if ($line[0] !== "\t") {
                    if ($inVendor) break;
                    $inVendor = strncasecmp($line, $v[1] . '  ', 6) === 0;
                } elseif ($inVendor && $line[1] !== "\t" && strncasecmp(substr($line, 1), $d[1] . '  ', 6) === 0) {
                    $name = trim(substr($line, 7));
                    break;
                }
            }
            fclose($handle);
            if ($name !== null) return ['name' => $name];
        }
        return ['name' => null];
    };
    $result = $root === '' ? esmCachedCollect('pci-' . $v[1] . '-' . $d[1], 86400, $lookup) : $lookup();
    return isset($result['name']) && is_string($result['name']) ? mbSafeLimit($result['name'], 100) : null;
}
function esmNvidiaSmi(): array
{
    $binary = null;
    foreach (['/usr/bin/nvidia-smi', '/usr/local/bin/nvidia-smi'] as $candidate) {
        if (@is_executable($candidate)) { $binary = $candidate; break; }
    }
    if ($binary === null) return [];
    $text = esmRunCommand([$binary,
        '--query-gpu=pci.bus_id,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,clocks.sm,clocks.max.sm',
        '--format=csv,noheader,nounits'], 2.0, 65536);
    if ($text === null) return [];
    $value = static fn(string $field): ?float => is_numeric(trim($field)) ? (float) trim($field) : null;
    $out = [];
    foreach (explode("\n", trim($text)) as $line) {
        $f = array_map('trim', explode(',', $line));
        if (count($f) < 9) continue;
        $out[strtolower(substr($f[0], -12))] = [
            'name' => mbSafeLimit($f[1], 100),
            'busyPercent' => $value($f[2]),
            'vramUsed' => ($m = $value($f[3])) !== null ? $m * 1048576 : null,
            'vramTotal' => ($m = $value($f[4])) !== null ? $m * 1048576 : null,
            'celsius' => $value($f[5]),
            'watts' => $value($f[6]),
            'mhz' => $value($f[7]),
            'maxMhz' => $value($f[8]),
        ];
    }
    return $out;
}
function esmCollectGpus(string $root = ''): array
{
    if (!function_exists('glob')) return [];
    $cards = glob($root . '/sys/class/drm/card*', GLOB_ONLYDIR) ?: [];
    natsort($cards);
    $out = [];
    $seen = [];
    $hasNvidia = false;
    foreach ($cards as $card) {
        if (!preg_match('#/card\d+$#', $card)) continue; // skip connectors such as card0-HDMI-A-1
        $dev = $card . '/device';
        $real = @realpath($dev) ?: $dev;
        if (isset($seen[$real])) continue;
        $seen[$real] = true;
        $vendorId = strtolower(trim((string) esmRead($dev . '/vendor', 16)));
        $deviceId = strtolower(trim((string) esmRead($dev . '/device', 16)));
        $driverLink = @readlink($dev . '/driver');
        $driver = is_string($driverLink) ? basename($driverLink) : null;
        if (in_array($driver, ['simple-framebuffer', 'simpledrm', 'efi-framebuffer', 'vesafb'], true)) continue;
        $vendor = esmGpuVendor($vendorId);
        $model = $vendorId !== '' ? esmPciName($vendorId, $deviceId, $root) : null;
        $name = $model !== null && $vendor !== null && stripos($model, $vendor) === 0
            ? $model : trim(($vendor ?? '') . ' ' . ($model ?? ''));
        if ($name === '') $name = $driver ?? basename($card);
        $number = static fn(string $file): ?float => esmNumber(esmRead($file, 64));
        $gpu = [
            'name' => mbSafeLimit($name, 120),
            'driver' => $driver,
            'pciId' => $vendorId !== '' ? substr($vendorId, 2) . ':' . substr($deviceId, 2) : null,
            'busyPercent' => $number($dev . '/gpu_busy_percent'),
            'vramUsed' => $number($dev . '/mem_info_vram_used'),
            'vramTotal' => $number($dev . '/mem_info_vram_total'),
            'celsius' => null, 'watts' => null,
            'mhz' => $number($card . '/gt_cur_freq_mhz'),
            'maxMhz' => $number($card . '/gt_max_freq_mhz'),
        ];
        foreach (glob($dev . '/hwmon/hwmon*', GLOB_ONLYDIR) ?: [] as $hwmon) {
            $temp = $number($hwmon . '/temp1_input');
            if ($temp !== null && $gpu['celsius'] === null) $gpu['celsius'] = round($temp / 1000, 1);
            $power = $number($hwmon . '/power1_average') ?? $number($hwmon . '/power1_input');
            if ($power !== null && $gpu['watts'] === null) $gpu['watts'] = round($power / 1000000, 1);
            $clock = $number($hwmon . '/freq1_input');
            if ($clock !== null && $gpu['mhz'] === null) $gpu['mhz'] = round($clock / 1000000);
        }
        if ($vendorId === '0x10de' && $driver === 'nvidia') {
            $hasNvidia = true;
            $gpu['busId'] = strtolower(substr(basename($real), -12));
        }
        $out[] = $gpu;
    }
    if ($hasNvidia && $root === '') {
        $smi = esmNvidiaSmi();
        foreach ($out as &$gpu) {
            $extra = isset($gpu['busId']) ? ($smi[$gpu['busId']] ?? null) : null;
            if ($extra) $gpu = array_merge($gpu, array_filter($extra, static fn($v): bool => $v !== null));
        }
        unset($gpu);
    }
    foreach ($out as &$gpu) unset($gpu['busId']);
    unset($gpu);
    return array_slice($out, 0, 8);
}

// =============================================================
// 11c. MAINTENANCE: RESTART REQUIRED, FAILED SYSTEMD UNITS, LISTENING PORTS
// =============================================================
function esmReboot(): array
{
    return esmCachedCollect('reboot', ESM_REBOOT_CACHE_SECONDS, static fn(): array => esmCheckReboot());
}
function esmCheckReboot(string $root = '', ?string $running = null): array
{
    $reasons = [];
    $packages = [];
    foreach ([$root . '/run/reboot-required', $root . '/var/run/reboot-required'] as $file) {
        if (!@is_file($file)) continue;
        $reasons[] = 'file';
        $list = esmRead($file . '.pkgs', 16384);
        foreach (explode("\n", (string) $list) as $package) {
            $package = trim($package);
            if (preg_match('/^[a-zA-Z0-9.+_:-]{1,64}$/', $package)) $packages[$package] = true;
        }
        break;
    }
    $running ??= function_exists('php_uname') ? php_uname('r') : '';
    $installed = [];
    foreach (glob($root . '/lib/modules/*', GLOB_ONLYDIR) ?: [] as $dir) {
        if (@is_file($dir . '/modules.dep') || @is_dir($dir . '/kernel')) $installed[] = basename($dir);
    }
    // Where kernel images are versioned (/boot/vmlinuz-<version>), only count kernels whose image exists.
    $images = glob($root . '/boot/vmlinuz-*') ?: [];
    $imageVersions = array_map(static fn(string $file): string => substr(basename($file), 8), $images);
    if (array_intersect($imageVersions, $installed)) {
        $installed = array_values(array_filter($installed, static fn(string $version): bool =>
            in_array($version, $imageVersions, true) || @is_file($root . '/lib/modules/' . $version . '/vmlinuz')));
    }
    usort($installed, 'version_compare');
    $latest = $installed ? end($installed) : null;
    if ($latest !== null && $running !== '' && version_compare($latest, $running, '>')) $reasons[] = 'kernel';
    return [
        'required' => (bool) $reasons,
        'reasons' => $reasons,
        'packages' => array_slice(array_keys($packages), 0, 12),
        'runningKernel' => $running !== '' ? $running : null,
        'latestKernel' => $latest,
    ];
}
function esmFailedUnits(): array
{
    return esmCachedCollect('failed-units', ESM_SYSTEMD_CACHE_SECONDS, static function (): array {
        $binary = null;
        foreach (['/usr/bin/systemctl', '/bin/systemctl'] as $candidate) {
            if (@is_executable($candidate)) { $binary = $candidate; break; }
        }
        if ($binary === null) return ['available' => false, 'units' => []];
        // With its legend, systemctl always prints something when it works ("0 loaded units listed.").
        $text = esmRunCommand([$binary, 'list-units', '--state=failed', '--all', '--plain', '--no-pager'], 2.0, 131072);
        return esmParseFailedUnits($text);
    });
}
function esmParseFailedUnits(?string $text): array
{
    if ($text === null || trim($text) === '') return ['available' => false, 'units' => []];
    $units = [];
    foreach (explode("\n", $text) as $line) {
        $line = trim(preg_replace('/^[\s\x{25CF}*]+/u', '', $line) ?? $line);
        if (!preg_match('/^(\S+\.(?:service|socket|mount|automount|timer|path|target|swap|scope|slice|device))\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/', $line, $m)) continue;
        $units[] = ['unit' => mbSafeLimit($m[1], 120), 'sub' => mbSafeLimit($m[4], 30), 'description' => mbSafeLimit(trim($m[5]), 160)];
    }
    return ['available' => true, 'units' => array_slice($units, 0, 30)];
}
function esmPortName(int $port): ?string
{
    return [
        21 => 'FTP', 22 => 'SSH', 25 => 'SMTP', 53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 111 => 'rpcbind', 139 => 'NetBIOS',
        143 => 'IMAP', 389 => 'LDAP', 443 => 'HTTPS', 445 => 'SMB', 465 => 'SMTPS', 587 => 'SMTP submission', 631 => 'CUPS',
        636 => 'LDAPS', 853 => 'DNS over TLS', 993 => 'IMAPS', 995 => 'POP3S', 1433 => 'SQL Server', 1883 => 'MQTT',
        2049 => 'NFS', 2375 => 'Docker API', 2376 => 'Docker API (TLS)', 3000 => 'Gitea / Grafana', 3306 => 'MySQL / MariaDB',
        3389 => 'RDP', 5432 => 'PostgreSQL', 5900 => 'VNC', 5984 => 'CouchDB', 6379 => 'Redis', 8080 => 'HTTP (alt)',
        8086 => 'InfluxDB', 8096 => 'Jellyfin', 8443 => 'HTTPS (alt)', 9000 => 'PHP-FPM', 9042 => 'Cassandra',
        9090 => 'Prometheus / Cockpit', 9091 => 'Transmission', 9100 => 'Node exporter', 9200 => 'Elasticsearch',
        10050 => 'Zabbix agent', 10051 => 'Zabbix server', 11211 => 'Memcached', 27017 => 'MongoDB', 32400 => 'Plex',
    ][$port] ?? null;
}
function esmProcNetIp(string $hex): ?string
{
    if (!ctype_xdigit($hex) || !in_array(strlen($hex), [8, 32], true)) return null;
    $littleEndian = pack('L', 1) === pack('V', 1);
    $binary = '';
    foreach (str_split($hex, 8) as $word) {
        $bytes = (string) hex2bin($word);
        $binary .= $littleEndian ? strrev($bytes) : $bytes;
    }
    $ip = @inet_ntop($binary);
    return is_string($ip) ? $ip : null;
}
function esmListeningPorts(): array
{
    return esmCachedCollect('ports', 10, static fn(): array => esmParseListeningPorts(
        esmRead('/proc/net/tcp', 4194304), esmRead('/proc/net/tcp6', 4194304)));
}
function esmIsPublicIp(string $ip): bool
{
    if (str_starts_with($ip, '::ffff:')) $ip = substr($ip, 7);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
        $long = ip2long($ip);
        return !($long >= ip2long('100.64.0.0') && $long <= ip2long('100.127.255.255')); // CGNAT, Tailscale
    }
    $binary = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? @inet_pton($ip) : false;
    if (!is_string($binary) || strlen($binary) !== 16) return false;
    $first = ord($binary[0]);
    return ($first & 0xE0) === 0x20; // global unicast 2000::/3 (excludes ::1, fe80::/10, fc00::/7)
}
function esmParseListeningPorts(?string ...$tables): array
{
    $sensitive = [1433, 2375, 3306, 5432, 5984, 6379, 8086, 9042, 9200, 11211, 27017];
    $found = [];
    foreach ($tables as $text) {
        foreach (explode("\n", (string) $text) as $line) {
            $f = preg_split('/\s+/', trim($line));
            if (!$f || count($f) < 4 || $f[3] !== '0A' || !str_contains($f[1], ':')) continue; // 0A = LISTEN
            [$hexIp, $hexPort] = explode(':', $f[1], 2);
            if (!ctype_xdigit($hexPort)) continue;
            $ip = esmProcNetIp($hexIp);
            if ($ip === null) continue;
            $port = (int) hexdec($hexPort);
            $plain = str_starts_with($ip, '::ffff:') ? substr($ip, 7) : $ip;
            $scope = in_array($plain, ['0.0.0.0', '::'], true) ? 'all'
                : ((str_starts_with($plain, '127.') || $plain === '::1') ? 'local' : 'address');
            $found[$port][$scope][$scope === 'address' ? $plain : ''] = true;
        }
    }
    ksort($found);
    $out = [];
    foreach ($found as $port => $scopes) {
        $name = esmPortName((int) $port);
        if (isset($scopes['all'])) {
            $out[] = ['port' => $port, 'scope' => 'all', 'address' => null, 'service' => $name, 'sensitive' => in_array($port, $sensitive, true)];
            continue; // listening everywhere already covers loopback and specific addresses
        }
        foreach (array_keys($scopes['address'] ?? []) as $address) {
            $out[] = ['port' => $port, 'scope' => 'address', 'address' => $address, 'service' => $name,
                'sensitive' => in_array($port, $sensitive, true) && esmIsPublicIp($address)];
        }
        if (isset($scopes['local'])) $out[] = ['port' => $port, 'scope' => 'local', 'address' => null, 'service' => $name, 'sensitive' => false];
    }
    return array_slice($out, 0, 80);
}

// =============================================================
// 11d. NETWORK ACTIVITY: CONNECTIONS, SESSIONS, WEB TRAFFIC, APACHE STATUS
// =============================================================
function esmIsLoopbackIp(string $ip): bool
{
    return $ip === '::1' || $ip === '::' || $ip === '0.0.0.0' || str_starts_with($ip, '127.');
}
// Established TCP connections, read from the kernel's tables (nothing is scanned).
// A connection is "incoming" when its local port is one this server listens on. $tables: tests only.
function esmConnections(?string ...$tables): array
{
    if (!$tables) $tables = [esmRead('/proc/net/tcp', 8388608), esmRead('/proc/net/tcp6', 8388608)];
    $listening = [];
    $rows = [];
    foreach ($tables as $text) {
        foreach (explode("\n", (string) $text) as $line) {
            $f = preg_split('/\s+/', trim($line));
            if (!$f || count($f) < 4 || !str_contains($f[1], ':') || !str_contains($f[2], ':')) continue;
            $localPortHex = explode(':', $f[1], 2)[1];
            if (!ctype_xdigit($localPortHex)) continue;
            $localPort = (int) hexdec($localPortHex);
            if ($f[3] === '0A') { $listening[$localPort] = true; continue; } // 0A = LISTEN
            if ($f[3] !== '01') continue; // 01 = ESTABLISHED
            [$remoteHex, $remotePortHex] = explode(':', $f[2], 2);
            $ip = esmProcNetIp($remoteHex);
            if ($ip === null || !ctype_xdigit($remotePortHex)) continue;
            if (str_starts_with($ip, '::ffff:')) $ip = substr($ip, 7);
            $rows[] = [$localPort, $ip, (int) hexdec($remotePortHex)];
        }
    }
    $incoming = [];
    $outgoing = [];
    $local = 0;
    foreach ($rows as [$localPort, $ip, $remotePort]) {
        if (esmIsLoopbackIp($ip)) { $local++; continue; }
        if (isset($listening[$localPort])) $incoming[$localPort][$ip] = ($incoming[$localPort][$ip] ?? 0) + 1;
        else $outgoing[$ip . ' ' . $remotePort] = ($outgoing[$ip . ' ' . $remotePort] ?? 0) + 1;
    }
    ksort($incoming);
    $services = [];
    $addresses = [];
    $incomingTotal = 0;
    foreach ($incoming as $port => $clients) {
        arsort($clients);
        $incomingTotal += array_sum($clients);
        $addresses += $clients;
        $list = [];
        foreach (array_slice($clients, 0, 8, true) as $ip => $count) {
            $list[] = ['ip' => (string) $ip, 'count' => $count, 'public' => esmIsPublicIp((string) $ip)];
        }
        $services[] = ['port' => $port, 'service' => esmPortName((int) $port), 'connections' => array_sum($clients),
            'addresses' => count($clients), 'clients' => $list];
    }
    arsort($outgoing);
    $destinations = [];
    foreach (array_slice($outgoing, 0, 15, true) as $key => $count) {
        [$ip, $port] = explode(' ', (string) $key);
        $destinations[] = ['ip' => $ip, 'port' => (int) $port, 'service' => esmPortName((int) $port), 'count' => $count, 'public' => esmIsPublicIp($ip)];
    }
    return [
        'incoming' => $incomingTotal, 'incomingAddresses' => count($addresses),
        'outgoing' => array_sum($outgoing), 'outgoingDestinations' => count($outgoing), 'local' => $local,
        'services' => array_slice($services, 0, 30), 'destinations' => $destinations,
    ];
}
// Who is logged in (SSH, console), as reported by "who". $text: tests only.
function esmSessions(?string $text = null): array
{
    if ($text === null) {
        $binary = null;
        foreach (['/usr/bin/who', '/bin/who'] as $candidate) {
            if (@is_executable($candidate)) { $binary = $candidate; break; }
        }
        if ($binary === null) return ['available' => false, 'sessions' => []];
        $text = esmRunCommand([$binary], 0.9, 32768);
        if ($text === null) return ['available' => false, 'sessions' => []];
    }
    $sessions = [];
    foreach (explode("\n", $text) as $line) {
        if (!preg_match('/^(\S+)\s+(\S+)\s+(.*?)\s*(?:\(([^)]*)\))?\s*$/', $line, $m) || $m[3] === '') continue;
        $since = strtotime($m[3]);
        if ($since !== false && $since > time() + 86400) $since = strtotime('-1 year', $since); // date without a year
        $sessions[] = ['user' => mbSafeLimit($m[1], 40), 'line' => mbSafeLimit($m[2], 20),
            'from' => mbSafeLimit($m[4] ?? '', 80), 'since' => $since === false ? null : $since];
    }
    return ['available' => true, 'sessions' => array_slice($sessions, 0, 20)];
}

// The end of a log file: [text made of whole lines, true when the beginning of the file was skipped].
function esmLogTail(string $file, int $maxBytes): ?array
{
    $handle = @fopen($file, 'rb');
    if ($handle === false) return null;
    $size = (int) (@fstat($handle)['size'] ?? 0);
    $skipped = $size > $maxBytes;
    if ($skipped) @fseek($handle, $size - $maxBytes);
    $text = (string) @stream_get_contents($handle, $maxBytes);
    fclose($handle);
    if ($skipped) {
        $cut = strpos($text, "\n");
        $text = $cut === false ? '' : substr($text, $cut + 1);
    }
    return [$text, $skipped];
}
function esmLogTime(string $text): ?int
{
    static $cache = [];
    if (array_key_exists($text, $cache)) return $cache[$text];
    if (count($cache) > 5000) $cache = [];
    $date = DateTime::createFromFormat('d/M/Y:H:i:s O', $text);
    return $cache[$text] = $date === false ? null : $date->getTimestamp();
}
// One line of an access log in the "combined" format (Apache, nginx) or Apache's "vhost_combined".
function esmParseAccessLine(string $line): ?array
{
    static $pattern = '/^(\S+) (?:(\S+) )?\S+ \S+ \[([^\]]+)\] "((?:[^"\\\\]|\\\\.)*)" (\d{3}) (\d+|-)(?: "(?:[^"\\\\]|\\\\.)*" "((?:[^"\\\\]|\\\\.)*)")?/';
    if (!preg_match($pattern, $line, $m)) return null;
    $time = esmLogTime($m[3]);
    if ($time === null) return null;
    $vhost = '';
    $ip = $m[1];
    if ($m[2] !== '') { // vhost_combined: "site:port address ..."
        $vhost = (string) preg_replace('/:\d+$/', '', $m[1]);
        $ip = $m[2];
    }
    if (!preg_match('/^[\w.:-]{2,60}$/', $ip)) return null;
    $request = explode(' ', $m[4], 3);
    $method = preg_match('/^[A-Z]{3,10}$/', $request[0]) ? $request[0] : '';
    $path = $method !== '' && isset($request[1]) ? explode('?', $request[1], 2)[0] : ''; // query strings may hold secrets
    return ['time' => $time, 'ip' => $ip, 'vhost' => mbSafeLimit($vhost, 80), 'method' => $method,
        'path' => mbSafeLimit($path, 120), 'status' => (int) $m[5], 'bytes' => $m[6] === '-' ? 0 : (float) $m[6],
        'agent' => $m[7] ?? ''];
}
function esmIsBotAgent(string $agent): bool
{
    return $agent === '' || $agent === '-'
        || (bool) preg_match('/bot\b|bot[\/;) ]|crawl|spider|slurp|scan|curl\/|wget|python|go-http-client|libwww|zgrab|masscan|nmap|nikto|censys|headless|uptime|monitor|facebookexternalhit|feedfetcher|preview/i', $agent);
}
// Requests of the last minutes, from the access logs. Nothing is stored: the logs are read again each time.
// $ownPath: requests for this dashboard are left out, or it would top its own statistics.
function esmWebTraffic(string $ownPath = ''): array
{
    $minutes = max(1, min(60, ESM_ACCESS_LOG_MINUTES));
    $files = [];
    $blocked = [];
    foreach (ESM_ACCESS_LOGS as $pattern) {
        $readable = 0;
        $unreadable = 0;
        foreach (@glob($pattern, GLOB_NOSORT) ?: [] as $file) {
            if (preg_match('/\.(?:gz|bz2|xz|zst|\d+)$/', $file) || !@is_file($file)) continue; // rotated files
            if (@is_readable($file)) { $files[$file] = (int) @filemtime($file); $readable++; } else $unreadable++;
        }
        $directory = dirname($pattern);
        if ($readable === 0 && !preg_match('/[*?\[]/', $directory) && @is_dir($directory)
            && ($unreadable > 0 || !@is_readable($directory))) {
            $blocked[] = ['directory' => $directory, 'pattern' => $pattern];
        }
    }
    if (!$files) {
        if (!$blocked) return ['state' => 'missing', 'minutes' => $minutes];
        $account = function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '') : '';
        if (!preg_match('/^[a-z_][a-z0-9_-]{0,31}$/i', $account)) $account = 'www-data';
        $commands = [];
        foreach ($blocked as $entry) {
            if (!preg_match('#^[\w/.*?-]+$#', $entry['pattern'])) continue;
            // Read access to the access logs only, kept when the logs are rotated (default ACL of the folder).
            // The pattern is expanded by a root shell: an administrator who cannot list the folder would get "no such file".
            $commands[] = "sudo setfacl -m u:$account:rx,d:u:$account:r {$entry['directory']} && sudo sh -c 'setfacl -m u:$account:r {$entry['pattern']}'";
        }
        $undo = [];
        foreach ($blocked as $entry) {
            if (preg_match('#^[\w/.-]+$#', $entry['directory'])) $undo[] = "sudo setfacl -b {$entry['directory']} && sudo sh -c 'setfacl -b {$entry['pattern']}'";
        }
        return ['state' => 'unreadable', 'minutes' => $minutes, 'user' => $account,
            'command' => implode("\n", $commands), 'undo' => $commands ? implode("\n", $undo) : ''];
    }
    arsort($files);
    $now = time();
    $start = $now - 60 * $minutes;
    $series = array_fill(0, $minutes, 0);
    $status = ['2' => 0, '3' => 0, '4' => 0, '5' => 0];
    $clients = [];
    $pages = [];
    $errors = [];
    $requests = 0;
    $bytes = 0.0;
    $coveredFrom = $start;
    foreach (array_slice(array_keys($files), 0, 6) as $file) {
        $tail = esmLogTail($file, 1048576);
        if ($tail === null) continue;
        $lines = explode("\n", $tail[0]);
        $reachedStart = !$tail[1];
        $oldest = null;
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            if ($lines[$i] === '') continue;
            $entry = esmParseAccessLine($lines[$i]);
            if ($entry === null) continue;
            if ($entry['time'] < $start) { $reachedStart = true; break; }
            if ($entry['time'] > $now + 5) continue;
            $oldest = $entry['time'];
            if (esmIsLoopbackIp($entry['ip']) || ($ownPath !== '' && $entry['path'] === $ownPath)) continue;
            $requests++;
            $bytes += $entry['bytes'];
            $series[min($minutes - 1, max(0, intdiv($entry['time'] - $start, 60)))]++;
            $class = (string) intdiv($entry['status'], 100);
            if (isset($status[$class])) $status[$class]++;
            $bot = esmIsBotAgent($entry['agent']);
            $page = $entry['vhost'] . ($entry['path'] !== '' ? $entry['path'] : ($entry['vhost'] !== '' ? ' ' : '') . '—');
            $client = &$clients[$entry['ip']];
            $client ??= ['requests' => 0, 'human' => 0, 'last' => 0, 'page' => '', 'errors' => 0];
            $client['requests']++;
            if (!$bot) $client['human']++;
            if ($entry['status'] >= 400) $client['errors']++;
            if ($entry['time'] >= $client['last']) { $client['last'] = $entry['time']; $client['page'] = $page; }
            unset($client);
            if (count($pages) < 4000 || isset($pages[$page])) $pages[$page] = ($pages[$page] ?? 0) + 1;
            if ($entry['status'] >= 400) {
                $key = $entry['status'] . ' ' . $page;
                if (count($errors) < 4000 || isset($errors[$key])) $errors[$key] = ($errors[$key] ?? 0) + 1;
            }
        }
        // A very busy log: the part that was read does not go back to the start of the period.
        if (!$reachedStart && $oldest !== null) $coveredFrom = max($coveredFrom, $oldest);
    }
    $bots = count(array_filter($clients, static fn(array $client): bool => $client['human'] === 0));
    uasort($clients, static fn(array $a, array $b): int => $b['requests'] <=> $a['requests']);
    $top = [];
    foreach (array_slice($clients, 0, 8, true) as $ip => $client) {
        $top[] = ['ip' => (string) $ip, 'requests' => $client['requests'], 'errors' => $client['errors'],
            'bot' => $client['human'] === 0, 'last' => $client['last'], 'page' => $client['page']];
    }
    arsort($pages);
    arsort($errors);
    $list = static function (array $counts, int $limit, bool $withStatus): array {
        $out = [];
        foreach (array_slice($counts, 0, $limit, true) as $key => $count) {
            $key = (string) $key;
            $out[] = $withStatus ? ['status' => (int) substr($key, 0, 3), 'page' => substr($key, 4), 'count' => $count]
                : ['page' => $key, 'count' => $count];
        }
        return $out;
    };
    return [
        'state' => 'ok', 'minutes' => $minutes, 'coveredSeconds' => $now - $coveredFrom,
        'requests' => $requests, 'lastMinute' => $series[$minutes - 1], 'bytes' => $bytes, 'series' => $series, 'status' => $status,
        'visitors' => count($clients), 'bots' => $bots,
        'clients' => $top, 'pages' => $list($pages, 8, false), 'errors' => $list($errors, 6, true),
    ];
}

// Small HTTP GET to this machine only (used for Apache's status page): [status, body] or null.
function esmLoopbackFetch(string $url, string $hostHeader, float $timeout, int $maxBytes): ?array
{
    $parts = parse_url($url);
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = trim((string) ($parts['host'] ?? ''), '[]');
    if (!in_array($scheme, ['http', 'https'], true)) return null;
    if ($host === 'localhost') $host = '127.0.0.1';
    if ($host !== '::1' && !preg_match('/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $host)) return null; // loopback only
    $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
    $target = (string) ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
    if (!preg_match('#^/[\w/.?=&~%-]*$#', $target) || !preg_match('/^[\w.-]{1,120}$/', $hostHeader)) return null;
    // The certificate is not checked: the connection never leaves this machine.
    $context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'peer_name' => $hostHeader, 'SNI_enabled' => true]]);
    $endpoint = ($scheme === 'https' ? 'tls://' : 'tcp://') . (str_contains($host, ':') ? "[$host]" : $host) . ':' . $port;
    $client = @stream_socket_client($endpoint, $errno, $errorText, $timeout, STREAM_CLIENT_CONNECT, $context);
    if (!is_resource($client)) return null;
    stream_set_timeout($client, (int) $timeout, (int) (($timeout - (int) $timeout) * 1000000));
    @fwrite($client, "GET $target HTTP/1.0\r\nHost: $hostHeader\r\nUser-Agent: Monitor-made-Simple/" . ESM_VERSION . "\r\nConnection: close\r\n\r\n");
    $response = '';
    $deadline = microtime(true) + 2 * $timeout;
    while (!feof($client) && strlen($response) < $maxBytes && microtime(true) < $deadline) {
        $chunk = @fread($client, 65536);
        if ($chunk === false || ($chunk === '' && (stream_get_meta_data($client)['timed_out'] ?? false))) break;
        $response .= $chunk;
    }
    fclose($client);
    if (!preg_match('#^HTTP/\d(?:\.\d)? (\d{3})#', $response, $m)) return null;
    $split = strpos($response, "\r\n\r\n");
    return [(int) $m[1], $split === false ? '' : substr($response, $split + 4)];
}
// Requests being served right now: the table of Apache's status page (mod_status). $html: tests only.
function esmParseApacheWorkers(string $html, string $ownPath = ''): array
{
    $columns = null;
    $out = [];
    if (!preg_match_all('#<tr[^>]*>(.*?)</tr>#s', $html, $rows)) return [];
    foreach ($rows[1] as $rowHtml) {
        if (!preg_match_all('#<t[dh][^>]*>(.*?)</t[dh]>#s', $rowHtml, $cells)) continue;
        $cells = array_map(static fn(string $cell): string => trim(html_entity_decode(strip_tags($cell), ENT_QUOTES | ENT_HTML5, 'UTF-8')), $cells[1]);
        if (in_array('Srv', $cells, true) && in_array('Request', $cells, true)) { $columns = array_flip($cells); continue; }
        if ($columns === null || count($cells) < count($columns)) continue;
        $cell = static fn(string $name): string => isset($columns[$name]) ? (string) ($cells[$columns[$name]] ?? '') : '';
        $mode = $cell('M');
        if (!in_array($mode, ['W', 'R', 'C', 'L', 'G'], true)) continue; // serving, reading, closing, logging, finishing
        $request = explode(' ', $cell('Request'), 3);
        $path = explode('?', (string) ($request[1] ?? ''), 2)[0];
        if ($path === '' && $mode !== 'R') continue;
        if ($path === '/server-status' || ($ownPath !== '' && $path === $ownPath) || esmIsLoopbackIp($cell('Client'))) continue;
        $out[] = ['client' => mbSafeLimit($cell('Client'), 60), 'vhost' => mbSafeLimit((string) preg_replace('/:\d+$/', '', $cell('VHost')), 80),
            'method' => mbSafeLimit((string) $request[0], 10), 'path' => mbSafeLimit($path, 120), 'mode' => $mode,
            'seconds' => is_numeric($cell('SS')) ? (int) $cell('SS') : null];
    }
    usort($out, static fn(array $a, array $b): int => ($b['seconds'] ?? 0) <=> ($a['seconds'] ?? 0));
    return array_slice($out, 0, 25);
}
function esmApacheStatus(string $ownPath = ''): array
{
    if (ESM_APACHE_STATUS_URL === '') return ['state' => 'disabled'];
    $auto = esmLoopbackFetch(ESM_APACHE_STATUS_URL . '?auto', ESM_APACHE_STATUS_HOST, 0.8, 262144);
    if ($auto === null) return ['state' => 'unreachable', 'httpStatus' => null];
    if ($auto[0] !== 200 || !str_contains($auto[1], 'Scoreboard:')) return ['state' => 'unreachable', 'httpStatus' => $auto[0]];
    $values = [];
    foreach (explode("\n", $auto[1]) as $line) {
        if (str_contains($line, ': ')) { [$name, $value] = explode(': ', $line, 2); $values[trim($name)] = trim($value); }
    }
    $number = static fn(string $name): ?float => is_numeric($values[$name] ?? null) ? (float) $values[$name] : null;
    $board = count_chars((string) ($values['Scoreboard'] ?? ''), 1);
    $extended = isset($values['Total Accesses']);
    $workers = [];
    if ($extended) {
        $page = esmLoopbackFetch(ESM_APACHE_STATUS_URL, ESM_APACHE_STATUS_HOST, 0.8, 2097152);
        if ($page !== null && $page[0] === 200) $workers = esmParseApacheWorkers($page[1], $ownPath);
    }
    return [
        'state' => 'ok', 'extended' => $extended, 'atMs' => round(microtime(true) * 1000),
        'version' => mbSafeLimit((string) ($values['ServerVersion'] ?? ''), 80),
        'busy' => $number('BusyWorkers'), 'idle' => $number('IdleWorkers'),
        'keepalive' => $number('ConnsAsyncKeepAlive') ?? (float) ($board[ord('K')] ?? 0),
        'connections' => $number('ConnsTotal'),
        'totalAccesses' => $number('Total Accesses'), 'totalKBytes' => $number('Total kBytes'),
        'uptimeSeconds' => $number('Uptime'), 'requests' => $workers,
    ];
}
function esmNetworkActivity(): array
{
    $ownPath = (string) ($_SERVER['SCRIPT_NAME'] ?? '');
    return [
        'connections' => esmCachedCollect('connections', 4, static fn(): array => esmConnections(), false),
        'sessions' => esmCachedCollect('sessions', 10, static fn(): array => esmSessions()),
        'web' => esmCachedCollect('web-traffic', 10, static fn(): array => esmWebTraffic($ownPath)),
        'apache' => esmCachedCollect('apache-status', 3, static fn(): array => esmApacheStatus($ownPath), false),
    ];
}

// =============================================================
// 12. LOCAL TCP SERVICE CHECKS
// =============================================================
function esmServices(): array
{
    return esmCachedCollect('services', ESM_SERVICES_CACHE_SECONDS, 'esmProbeServices');
}
function esmProbeServices(): array
{
    if (!function_exists('stream_socket_client')) return [];
    $out = [];
    foreach (array_slice(ESM_SERVICES, 0, 12) as $item) {
        $host = (string) ($item['host'] ?? '127.0.0.1');
        $port = (int) ($item['port'] ?? 0);
        if (!filter_var($host, FILTER_VALIDATE_IP) || $port < 1 || $port > 65535) continue;
        $endpoint = (str_contains($host, ':') ? '[' . $host . ']' : $host) . ':' . $port;
        $start = microtime(true);
        $socket = @stream_socket_client('tcp://' . $endpoint, $errno, $errstr, 0.25, STREAM_CLIENT_CONNECT);
        $online = is_resource($socket);
        if ($online) fclose($socket);
        $out[] = [
            'name' => mbSafeLimit((string) ($item['name'] ?? $endpoint), 80),
            'endpoint' => $endpoint,
            'online' => $online,
            'latencyMs' => $online ? round((microtime(true) - $start) * 1000, 1) : null,
        ];
    }
    return $out;
}

// =============================================================
// 13. PROCESS METRICS
// =============================================================
function esmProcesses(): array
{
    return esmCachedCollect('processes-swap-v4', ESM_PROCESS_CACHE_SECONDS, 'esmSampleProcesses');
}
// One shared sample feeds both the dashboard (top 5) and the detail page (top 20):
// CPU percentages compare two consecutive samples, so a second sampler would skew them.
function esmProcessTop(array $data, int $limit): array
{
    $items = $data['items'] ?? null;
    if (!is_array($items)) return $data;
    $pick = [];
    foreach ([['cpuPercent', false], ['rssBytes', false], ['swapBytes', true]] as [$key, $positive]) {
        $list = array_values(array_filter($items, static fn($item): bool =>
            is_array($item) && is_numeric($item[$key] ?? null) && (!$positive || $item[$key] > 0)));
        usort($list, static fn($a, $b): int => $b[$key] <=> $a[$key]);
        foreach (array_slice($list, 0, $limit) as $item) $pick[(int) $item['pid']] = $item;
    }
    $data['items'] = array_values($pick);
    return $data;
}
function esmSampleProcesses(): array
{
    $previous = esmCacheRead('process-baseline') ?? [];
    $before = is_array($previous['snapshot'] ?? null) ? $previous['snapshot'] : [];
    $oldTotal = (float) ($previous['cpuTotal'] ?? 0);
    $now = microtime(true);
    $snapshot = [];
    $names = @scandir('/proc');
    if (!is_array($names)) return [];
    $pids = array_values(array_filter($names, static fn($v): bool => ctype_digit($v) && (int) $v > 0));
    usort($pids, static fn($a, $b): int => (int) $a <=> (int) $b);
    $alive = array_flip($pids);
    $partial = count($pids) > ESM_MAX_PROCESSES;
    if ($partial) {
        $offset = ((int) floor($now / ESM_PROCESS_CACHE_SECONDS) * ESM_MAX_PROCESSES) % count($pids);
        $count = count($pids);
        $remaining = ESM_MAX_PROCESSES;
        $rotated = [];
        for ($i = 0; $i < $remaining; $i++) $rotated[] = $pids[($offset + $i) % $count];
        $pids = $rotated;
    }
    $records = [];
    foreach ($pids as $pidText) {
        $pid = (int) $pidText;
        $text = esmRead('/proc/' . $pid . '/stat', 8192);
        if ($text === null) continue;
        $open = strpos($text, '(');
        $close = strrpos($text, ') ');
        if ($open === false || $close === false || $close <= $open) continue;
        $parts = preg_split('/\s+/', trim(substr($text, $close + 2)));
        if (!is_array($parts) || count($parts) < 22
            || !ctype_digit($parts[11]) || !ctype_digit($parts[12])
            || !ctype_digit($parts[19]) || !is_numeric($parts[21])) continue;
        $name = substr($text, $open + 1, $close - $open - 1);
        $name = preg_replace('/[\x00-\x1f\x7f]/', '', $name) ?? $name;
        $id = $pid . ':' . $parts[19];
        $ticks = (float) $parts[11] + (float) $parts[12];
        $rssPages = max(0, (float) $parts[21]);
        $records[] = [
            'pid' => $pid, 'name' => mbSafeLimit($name, 64), 'start' => $parts[19],
            'ticks' => $ticks, 'rssPages' => $rssPages, 'id' => $id,
        ];
    }
    $cpu = esmCpu();
    $total = (float) ($cpu['total'] ?? 0);
    $coreCount = max(1, count($cpu['cores'] ?? []));
    // Each process is compared with its own previous measurement (its CPU time and the total CPU
    // time at that moment). When there are more processes than ESM_MAX_PROCESSES, only a part is
    // read each time: a process read a few rounds ago still has a valid comparison point.
    foreach ($records as &$record) {
        $old = $before[$record['id']] ?? null;
        $oldTicks = is_array($old) ? ($old[0] ?? null) : $old;
        $baseTotal = is_array($old) ? (float) ($old[1] ?? 0) : $oldTotal;
        $delta = $oldTicks === null ? null : $record['ticks'] - (float) $oldTicks;
        $span = $total - $baseTotal;
        $record['cpuPercent'] = $delta !== null && $delta >= 0 && $span > 0
            ? round(min(100 * $coreCount, 100 * $coreCount * $delta / $span), 1) : null;
        $snapshot[$record['id']] = [$record['ticks'], $total];
    }
    unset($record);
    if ($partial) {
        foreach ($before as $id => $old) {
            if (count($snapshot) >= 4 * ESM_MAX_PROCESSES) break;
            if (isset($snapshot[$id]) || !is_array($old) || !isset($alive[explode(':', (string) $id)[0]])) continue;
            $snapshot[$id] = $old;
        }
    }
    $cpuSorted = $records;
    usort($cpuSorted, static fn($a, $b): int => ($b['cpuPercent'] ?? -1) <=> ($a['cpuPercent'] ?? -1));
    $ramSorted = $records;
    usort($ramSorted, static fn($a, $b): int => $b['rssPages'] <=> $a['rssPages']);
    $keep = max(5, min(50, ESM_PROCESS_DETAIL_LIMIT));
    $memory = esmMemInfo();
    $swapInUse = ($memory['SwapTotal'] ?? 0) > 0 && ($memory['SwapTotal'] ?? 0) - ($memory['SwapFree'] ?? 0) > 0;
    // The status file is the only source of per-process swap, so it is read for every process
    // when swap is in use; otherwise only for the processes that can be listed.
    $candidates = $swapInUse ? null
        : array_flip(array_column(array_merge(array_slice($cpuSorted, 0, $keep), array_slice($ramSorted, 0, $keep)), 'id'));
    foreach ($records as &$rec) {
        if ($candidates !== null && !isset($candidates[$rec['id']])) { $rec['swapBytes'] = null; $rec['rssBytes'] = null; continue; }
        $status = esmRead('/proc/' . $rec['pid'] . '/status', 16384);
        $rec['swapBytes'] = ($status !== null && preg_match('/^VmSwap:\s+(\d+)\s+kB/m', $status, $m))
            ? (float) $m[1] * 1024 : null;
        $rec['rssBytes'] = ($status !== null && preg_match('/^VmRSS:\s+(\d+)\s+kB/m', $status, $rssMatch))
            ? (float) $rssMatch[1] * 1024 : null;
    }
    unset($rec);
    $swapSorted = array_values(array_filter($records, static fn($r): bool => ($r['swapBytes'] ?? 0) > 0));
    usort($swapSorted, static fn($a, $b): int => $b['swapBytes'] <=> $a['swapBytes']);
    $selected = [];
    $recordById = array_column($records, null, 'id');
    foreach (array_merge(array_slice($cpuSorted, 0, $keep), array_slice($ramSorted, 0, $keep), array_slice($swapSorted, 0, $keep)) as $rec) {
        $selected[$rec['id']] = $recordById[$rec['id']];
    }
    foreach ($selected as &$rec) {
        $pid = $rec['pid'];
        $rec['pssBytes'] = null;
        $rec['detail'] = null;
        if (str_contains(strtolower((string) $rec['name']), 'php-fpm')) {
            $command = esmRead('/proc/' . $pid . '/cmdline', 512);
            if ($command !== null) {
                $command = str_replace("\0", ' ', $command);
                if (preg_match('/php-fpm:\s*pool\s+([a-zA-Z0-9_.-]{1,40})/i', $command, $pool)) {
                    $rec['detail'] = 'pool ' . $pool[1];
                }
            }
        }
        if (in_array($rec['id'], array_column(array_slice($ramSorted, 0, 5), 'id'), true)) {
            $rollup = esmRead('/proc/' . $pid . '/smaps_rollup', 131072);
            if ($rollup !== null && preg_match('/^Pss:\s+(\d+)\s+kB/m', $rollup, $m)) {
                $rec['pssBytes'] = (float) $m[1] * 1024;
            }
        }
        unset($rec['ticks'], $rec['rssPages'], $rec['id'], $rec['start']);
    }
    unset($rec);
    esmCacheWrite('process-baseline', ['at' => time(), 'cpuTotal' => $total, 'snapshot' => $snapshot]);
    return ['items' => array_values($selected), 'partial' => $partial, 'sampledAt' => time()];
}

// =============================================================
// 14. HTTP, HTTPS AND TLS CHECKS
// =============================================================
function esmSelfCheckHostname(): string
{
    if (ESM_SELF_CHECK_HOST !== 'auto') return ESM_SELF_CHECK_HOST;
    $name = strtolower(trim((string) ($_SERVER['SERVER_NAME'] ?? '')));
    if (strlen($name) <= 253
        && preg_match('/\A(?=.{1,253}\z)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/', $name)
        && !str_contains($name, '..')) return $name;
    return 'localhost';
}
// $allowProbe: null = probe now unless the refresh can be done after the response (PHP-FPM).
function esmHttpChecks(?bool $allowProbe = null): array
{
    $allowProbe ??= !esmCanDefer();
    $checks = [];
    if (ESM_SELF_CHECK && !ESM_CLI) {
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/monitor.php');
        if (!preg_match('#^/[a-zA-Z0-9/._~-]{1,255}\.php$#', $script)) $script = '/monitor.php';
        $serverPort = (int) ($_SERVER['SERVER_PORT'] ?? 80);
        if ($serverPort < 1 || $serverPort > 65535) $serverPort = 80;
        $scheme = ESM_SELF_CHECK_SCHEME === 'auto'
            ? (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
            : ESM_SELF_CHECK_SCHEME;
        $checks[] = [
            'name' => 'Monitor made Simple', 'ip' => ESM_SELF_CHECK_IP, 'host' => esmSelfCheckHostname(),
            'scheme' => $scheme,
            'port' => ESM_SELF_CHECK_PORT > 0 ? ESM_SELF_CHECK_PORT : $serverPort,
            'path' => $script, 'self' => true,
        ];
    }
    foreach (array_slice(ESM_HTTP_CHECKS, 0, 8) as $item) {
        if (is_array($item)) $checks[] = $item;
    }
    $previous = esmCacheRead('http-checks') ?? [];
    $saved = is_array($previous['checks'] ?? null) ? $previous['checks'] : [];
    $results = [];
    $probed = 0;
    $changed = false;
    $due = false;
    $keys = [];
    foreach ($checks as $check) {
        $key = hash('sha256', json_encode($check) ?: '');
        $keys[$key] = true;
        $cached = $saved[$key] ?? null;
        $lifetime = !empty($cached['online']) ? ESM_HTTP_CACHE_SECONDS : ESM_HTTP_RETRY_SECONDS;
        $age = is_array($cached) && isset($cached['checkedAt']) ? time() - (int) $cached['checkedAt'] : null;
        $fresh = $age !== null && $age >= 0 && $age < $lifetime;
        if ($fresh) {
            $results[] = $cached;
        } elseif ($allowProbe && $probed < ESM_HTTP_PROBES_PER_REQUEST) {
            $result = esmHttpProbe($check);
            if ($result !== null) {
                $result['checkedAt'] = time();
                $saved[$key] = $result;
                $results[] = $result;
                $probed++;
                $changed = true;
            }
        } elseif (is_array($cached)) {
            $due = true;
            // A result that is only waiting for its refresh is not "stale" yet.
            $cached['stale'] = $age === null || $age < 0 || $age > 3 * ESM_HTTP_CACHE_SECONDS;
            $results[] = $cached;
        } else {
            $due = true;
            $results[] = [
                'name' => mbSafeLimit((string) ($check['name'] ?? 'HTTP'), 80),
                'endpoint' => '—', 'online' => null, 'reachable' => null,
                'httpStatus' => null, 'latencyMs' => null,
                'tls' => ($check['scheme'] ?? '') === 'https',
                'tlsDays' => null, 'tlsExpiry' => null,
                'self' => !empty($check['self']), 'error' => 'httpPending',
                'checkedAt' => null, 'stale' => false,
            ];
        }
    }
    // Write only when something changed, and forget checks that were removed from the configuration.
    $kept = array_intersect_key($saved, $keys);
    if ($changed || count($kept) !== count($saved)) esmCacheWrite('http-checks', ['checks' => $kept]);
    if ($due && !$allowProbe && esmCanDefer()) {
        $GLOBALS['esmDeferredTasks']['http-checks'] = static fn(): array => esmHttpChecks(true);
    }
    return $results;
}
// Expiry time of the certificate presented on an open TLS connection.
function esmCertificateExpiry($client): ?int
{
    if (!function_exists('openssl_x509_parse')) return null;
    $params = @stream_context_get_params($client);
    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    if ($cert === null) return null;
    $parsed = @openssl_x509_parse($cert, false);
    return is_array($parsed) && isset($parsed['validTo_time_t']) ? (int) $parsed['validTo_time_t'] : null;
}
// A rejected certificate is read anyway (nothing is sent on that connection), so the page can say
// when it expired. This is exactly when the date is most useful.
function esmRejectedCertificateExpiry(string $endpoint, string $hostname, float $timeout): ?int
{
    $context = stream_context_create(['ssl' => [
        'verify_peer' => false, 'verify_peer_name' => false,
        'peer_name' => $hostname, 'SNI_enabled' => true, 'capture_peer_cert' => true,
    ]]);
    $client = @stream_socket_client('tls://' . $endpoint, $errno, $errorString, $timeout, STREAM_CLIENT_CONNECT, $context);
    if (!is_resource($client)) return null;
    $expiry = esmCertificateExpiry($client);
    fclose($client);
    return $expiry;
}
function esmHttpProbe(array $item): ?array
{
    $ip = (string) ($item['ip'] ?? '');
    $hostname = (string) ($item['host'] ?? '');
    $scheme = (string) ($item['scheme'] ?? 'https');
    $port = (int) ($item['port'] ?? ($scheme === 'https' ? 443 : 80));
    $path = (string) ($item['path'] ?? '/');
    if (!filter_var($ip, FILTER_VALIDATE_IP)
        || !preg_match('/^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:]+\])\z/i', $hostname)
        || !in_array($scheme, ['http','https'], true)
        || $port < 1 || $port > 65535
        || strlen($path) > 512 || !preg_match('#^/[a-zA-Z0-9/._~%?=&+;:@!$,-]*\z#', $path)) return null;
    $endpoint = (str_contains($ip, ':') ? '[' . $ip . ']' : $ip) . ':' . $port;
    $tls = $scheme === 'https';
    $isSelf = !empty($item['self']);
    $result = [
        'name' => mbSafeLimit((string) ($item['name'] ?? $hostname), 80),
        'endpoint' => $scheme . '://' . $hostname . ':' . $port . $path,
        'online' => false, 'reachable' => false, 'httpStatus' => null,
        'latencyMs' => null, 'tlsDays' => null, 'tlsExpiry' => null,
        'error' => 'connectionFailed', 'tls' => $tls, 'self' => $isSelf,
    ];
    $options = ['ssl' => [
        'verify_peer' => true, 'verify_peer_name' => true,
        'peer_name' => $hostname, 'SNI_enabled' => true,
        'capture_peer_cert' => true,
    ]];
    $context = stream_context_create($options);
    $start = microtime(true);
    $messages = [];
    set_error_handler(static function (int $level, string $message) use (&$messages): bool {
        $messages[] = $message;
        return true;
    });
    try {
        $client = @stream_socket_client(
            ($tls ? 'tls://' : 'tcp://') . $endpoint,
            $errno, $errorString, max(0.2, ESM_HTTP_TIMEOUT_SECONDS / 2), STREAM_CLIENT_CONNECT, $context
        );
    } finally {
        restore_error_handler();
    }
    if (!is_resource($client)) {
        // Name the cause only when it is certain; otherwise keep the generic message.
        $details = $errorString . "\n" . implode("\n", $messages);
        if ($tls && preg_match('/certificate verify failed|did not match expected CN|peer certificate/i', $details)) {
            $result['error'] = 'tlsCertificateError';
            $expiry = esmRejectedCertificateExpiry($endpoint, $hostname, max(0.2, ESM_HTTP_TIMEOUT_SECONDS / 2));
            if ($expiry !== null) {
                $result['tlsExpiry'] = gmdate('Y-m-d', $expiry);
                $result['tlsDays'] = (int) floor(($expiry - time()) / 86400);
            }
        } elseif ($errno === 111 || stripos($errorString, 'refused') !== false) {
            $result['error'] = 'connectionRefused';
        } elseif ($errno === 110 || stripos($errorString, 'timed out') !== false) {
            $result['error'] = 'httpTimeout';
        }
        return $result;
    }
    $defaultPort = $tls ? 443 : 80;
    $request = "GET " . $path . " HTTP/1.1\r\nHost: " . $hostname . ($port !== $defaultPort ? ':' . $port : '')
        . "\r\nConnection: close\r\nUser-Agent: Monitor-made-Simple/" . ESM_VERSION . "\r\nAccept: */*\r\n\r\n";
    stream_set_blocking($client, false);
    $pending = $request;
    $headers = '';
    $deadline = microtime(true) + max(0.2, ESM_HTTP_TIMEOUT_SECONDS - (microtime(true) - $start));
    while (microtime(true) < $deadline && strlen($headers) < 8192) {
        $wantRead = $pending === '' ? [$client] : null;
        $wantWrite = $pending !== '' ? [$client] : null;
        $except = null;
        $remainingUs = max(0, min(150000, (int) (($deadline - microtime(true)) * 1000000)));
        $count = @stream_select($wantRead, $wantWrite, $except, 0, $remainingUs);
        if (!$count) continue;
        if ($wantWrite) {
            $countWrite = @fwrite($client, $pending);
            if ($countWrite === false) break;
            $pending = substr($pending, $countWrite);
        }
        if ($wantRead) {
            $chunk = @fread($client, 2048);
            if (!is_string($chunk)) break;
            $headers .= $chunk;
            if (str_contains($headers, "\r\n\r\n") || str_contains($headers, "\n\n")) break;
            if ($chunk === '' && feof($client)) break;
        }
    }
    $line = strtok($headers, "\r\n");
    $headEnd = strpos($headers, "\r\n\r\n");
    if ($headEnd === false) $headEnd = strpos($headers, "\n\n");
    $headerOnly = $headEnd === false ? $headers : substr($headers, 0, $headEnd);
    $marker = $isSelf && (bool) preg_match('/(?:^|\r?\n)X-Monitor-Made-Simple:\s*1/i', $headerOnly);
    $result['latencyMs'] = round((microtime(true) - $start) * 1000, 1);
    if (is_string($line) && preg_match('~^HTTP/\d(?:\.\d)?\s+(\d{3})~i', $line, $m)) {
        $status = (int) $m[1];
        $result['httpStatus'] = $status;
        $result['reachable'] = true;
        // The local probe carries no password (401), and may arrive in plain HTTP on a server that
        // requires HTTPS (403): with the monitor's marker, both prove that the page is being served.
        $result['online'] = ($status >= 200 && $status < 400) || ($isSelf && in_array($status, [401, 403], true));
        $result['error'] = $result['online'] ? null : 'httpFailure';
        if ($isSelf && !$marker) {
            $result['online'] = false;
            $result['error'] = 'selfProbeMismatch';
        }
    } else {
        $complete = str_contains($headers, "\r\n\r\n") || str_contains($headers, "\n\n");
        $result['reachable'] = $headers !== '';
        $result['error'] = ($headers === '' && !$complete && microtime(true) >= $deadline) ? 'httpTimeout' : 'invalidResponse';
    }
    if ($tls && ($end = esmCertificateExpiry($client)) !== null) {
        $result['tlsExpiry'] = gmdate('Y-m-d', $end);
        $result['tlsDays'] = (int) floor(($end - time()) / 86400);
    }
    fclose($client);
    return $result;
}

// =============================================================
// 14b. PHP RUNTIME, KERNEL LIMITS AND SOFTWARE RAID
// =============================================================
// Remembers when a counter last went up (out-of-memory kills, PHP-FPM process limit reached...).
// The first observation, or a counter that went back down (reboot, restart), is not an event.
function esmCounterChangedAt(string $name, ?float $value): ?int
{
    if ($value === null) return null;
    $state = esmCacheRead('counter-' . $name);
    if (!is_array($state) || !is_numeric($state['value'] ?? null) || $value < (float) $state['value']) {
        esmCacheWrite('counter-' . $name, ['value' => $value, 'changedAt' => null]);
        return null;
    }
    if ($value > (float) $state['value']) {
        esmCacheWrite('counter-' . $name, ['value' => $value, 'changedAt' => time()]);
        return time();
    }
    return is_numeric($state['changedAt'] ?? null) ? (int) $state['changedAt'] : null;
}
function esmKernel(): array
{
    $vmstat = esmRead('/proc/vmstat', 131072);
    $oom = $vmstat !== null && preg_match('/^oom_kill\s+(\d+)$/m', $vmstat, $m) ? (float) $m[1] : null;
    $pair = static function (?string $usedText, ?string $maxText): ?array {
        $used = esmNumber($usedText);
        $max = esmNumber($maxText);
        return $used !== null && $max !== null && $max > 0 ? ['used' => $used, 'max' => $max] : null;
    };
    $fileNr = preg_split('/\s+/', trim((string) esmRead('/proc/sys/fs/file-nr', 128))) ?: [];
    return [
        'oomKills' => $oom,
        'oomLastAt' => esmCounterChangedAt('oom', $oom),
        'openFiles' => count($fileNr) >= 3 ? $pair($fileNr[0], $fileNr[2]) : null,
        'conntrack' => $pair(esmRead('/proc/sys/net/netfilter/nf_conntrack_count', 64),
            esmRead('/proc/sys/net/netfilter/nf_conntrack_max', 64)),
    ];
}
// Linux software RAID (md). $text is only passed by tests.
function esmRaid(?string $text = null): array
{
    $text ??= esmRead('/proc/mdstat', 65536);
    if ($text === null) return [];
    $out = [];
    $current = null;
    foreach (explode("\n", $text) as $line) {
        if (preg_match('/^(md[\w-]*)\s*:\s*(\S+)(?:\s+\([^)]*\))?(?:\s+(raid\d+|linear|multipath|faulty))?/', $line, $m)) {
            $out[] = ['name' => $m[1], 'state' => $m[2], 'level' => $m[3] ?? null,
                'devices' => null, 'working' => null, 'degraded' => $m[2] !== 'active', 'sync' => null];
            $current = count($out) - 1;
            continue;
        }
        if ($current === null) continue;
        if (preg_match('/\[(\d+)\/(\d+)\]\s*\[([U_]+)\]/', $line, $m)) {
            $out[$current]['devices'] = (int) $m[1];
            $out[$current]['working'] = (int) $m[2];
            if ((int) $m[2] < (int) $m[1] || str_contains($m[3], '_')) $out[$current]['degraded'] = true;
        }
        if (preg_match('/\b(recovery|resync|reshape|check)\s*=\s*([\d.]+)%/', $line, $m)) {
            $out[$current]['sync'] = ['action' => $m[1], 'percent' => (float) $m[2]];
        }
    }
    return array_slice($out, 0, 16);
}
function esmPhpRuntime(): array
{
    $out = [
        'version' => PHP_VERSION, 'sapi' => PHP_SAPI,
        'memoryLimit' => mbSafeLimit((string) ini_get('memory_limit'), 20),
        'fpm' => null, 'opcache' => null,
    ];
    if (function_exists('fpm_get_status')) {
        $status = @fpm_get_status();
        if (is_array($status)) {
            $int = static fn(string $key): ?int => is_numeric($status[$key] ?? null) ? (int) $status[$key] : null;
            $out['fpm'] = [
                'pool' => mbSafeLimit((string) ($status['pool'] ?? ''), 60),
                'manager' => mbSafeLimit((string) ($status['process-manager'] ?? ''), 20),
                'active' => $int('active-processes'), 'idle' => $int('idle-processes'), 'total' => $int('total-processes'),
                'listenQueue' => $int('listen-queue'), 'maxListenQueue' => $int('max-listen-queue'),
                'maxChildrenReached' => $int('max-children-reached'), 'slowRequests' => $int('slow-requests'),
                'accepted' => $int('accepted-conn'), 'startedSeconds' => $int('start-since'),
            ];
            $reached = $out['fpm']['maxChildrenReached'];
            $out['fpm']['maxChildrenReachedAt'] = esmCounterChangedAt('fpm-max-' . substr(hash('sha256', $out['fpm']['pool']), 0, 12),
                $reached === null ? null : (float) $reached);
        }
    }
    if (function_exists('opcache_get_status')) {
        $status = @opcache_get_status(false);
        if (is_array($status) && !empty($status['opcache_enabled'])) {
            $memory = is_array($status['memory_usage'] ?? null) ? $status['memory_usage'] : [];
            $stats = is_array($status['opcache_statistics'] ?? null) ? $status['opcache_statistics'] : [];
            $number = static fn($value): ?float => is_numeric($value) ? (float) $value : null;
            $out['opcache'] = [
                'used' => $number($memory['used_memory'] ?? null),
                'free' => $number($memory['free_memory'] ?? null),
                'wasted' => $number($memory['wasted_memory'] ?? null),
                'scripts' => $number($stats['num_cached_scripts'] ?? null),
                'keys' => $number($stats['num_cached_keys'] ?? null),
                'maxKeys' => $number($stats['max_cached_keys'] ?? null),
                'hitRate' => $number($stats['opcache_hit_rate'] ?? null),
                'full' => !empty($status['cache_full']),
            ];
        }
    }
    return $out;
}
function esmTemperaturesCached(): array
{
    return esmCachedCollect('temperatures', 10, static fn(): array => esmTemperatures());
}
// HTTPS, or a direct connection from the machine itself (SSH tunnel, local browser).
function esmTransportSecure(): bool
{
    if (ESM_CLI || esmIsHttps()) return true;
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $forwarded = isset($_SERVER['HTTP_X_FORWARDED_FOR']) || isset($_SERVER['HTTP_X_FORWARDED_PROTO']) || isset($_SERVER['HTTP_FORWARDED']);
    return !$forwarded && ($remote === '::1' || str_starts_with($remote, '127.'));
}

// =============================================================
// 14c. ALERTS
// =============================================================
// One list of alerts for the page, ?api=health, ?api=metrics and --check.
// level 1 = warning, 2 = critical. "key" is a text key of the page; "args" fills its {placeholders}
// ("detail" is appended after a colon). $withUsage adds memory and disk usage with the server-side
// thresholds; the page checks those itself, with the thresholds chosen in its settings.
function esmAlerts(array $data, bool $withUsage): array
{
    $alerts = [];
    $add = static function (int $level, string $key, array $args = [], ?string $view = null) use (&$alerts): void {
        $alerts[] = ['level' => $level, 'key' => $key, 'args' => $args, 'view' => $view];
    };
    $percent = static fn(float $value): string => rtrim(rtrim(number_format($value, 1, '.', ''), '0'), '.') . '%';
    $names = static fn(array $list): string => implode(', ', array_slice($list, 0, 3)) . (count($list) > 3 ? '…' : '');

    if (($data['secure'] ?? true) === false) $add(1, 'alertInsecure');
    if (($data['cache'] ?? true) === false) $add(1, 'alertNoCache');

    if ($withUsage) {
        $ram = $data['memory']['ram'] ?? null;
        if (is_array($ram) && ($ram['total'] ?? 0) > 0) {
            $used = 100 * $ram['used'] / $ram['total'];
            if ($used >= ESM_WARN_MEMORY_PERCENT) $add($used >= min(99, ESM_WARN_MEMORY_PERCENT + 10) ? 2 : 1, 'memory', ['detail' => $percent($used)], 'processes');
        }
        foreach ($data['disks'] ?? [] as $disk) {
            if (($disk['total'] ?? 0) <= 0) continue;
            $used = 100 * $disk['used'] / $disk['total'];
            if ($used >= ESM_WARN_DISK_PERCENT) $add($used >= min(99, ESM_WARN_DISK_PERCENT + 10) ? 2 : 1, 'alertDisk', ['mount' => $disk['mount'], 'detail' => $percent($used)], 'hardware');
            $inodes = $disk['inodes'] ?? null;
            if (is_array($inodes) && ($inodes['total'] ?? 0) > 0 && 100 * $inodes['used'] / $inodes['total'] >= 90) {
                $add(100 * $inodes['used'] / $inodes['total'] >= 99 ? 2 : 1, 'alertInodes', ['mount' => $disk['mount'], 'detail' => $percent(100 * $inodes['used'] / $inodes['total'])], 'hardware');
            }
        }
    }

    $cores = (int) ($data['system']['logicalCores'] ?? 0);
    $load = $data['system']['load'][1] ?? null;
    if ($cores > 0 && is_numeric($load) && $load / $cores >= ESM_WARN_LOAD_PER_CORE) {
        $add($load / $cores >= 2 * ESM_WARN_LOAD_PER_CORE ? 2 : 1, 'alertLoad', ['load' => number_format((float) $load, 2, '.', ''), 'cores' => $cores], 'processes');
    }
    foreach (['memory' => 'pressureMemory', 'io' => 'pressureIo'] as $field => $key) {
        $avg = $data['pressure'][$field]['avg10'] ?? null;
        if (is_numeric($avg) && $avg >= 10) $add($avg >= 30 ? 2 : 1, $key, ['detail' => 'PSI ' . $percent((float) $avg)], 'system');
    }
    $kernel = $data['kernel'] ?? [];
    if (is_numeric($kernel['oomLastAt'] ?? null) && time() - (int) $kernel['oomLastAt'] < 3600) $add(2, 'alertOom', [], 'system');
    foreach (['openFiles' => 'alertFiles', 'conntrack' => 'alertConntrack'] as $field => $key) {
        $limit = $kernel[$field] ?? null;
        if (is_array($limit) && $limit['max'] > 0 && 100 * $limit['used'] / $limit['max'] >= 80) {
            $add(100 * $limit['used'] / $limit['max'] >= 95 ? 2 : 1, $key, ['detail' => $percent(100 * $limit['used'] / $limit['max'])], $field === 'conntrack' ? 'network' : 'system');
        }
    }
    foreach ($data['raid'] ?? [] as $array) {
        if (!empty($array['degraded'])) $add(2, 'alertRaidDegraded', ['detail' => $array['name']], 'hardware');
        elseif (is_array($array['sync'] ?? null) && $array['sync']['action'] !== 'check') {
            $add(1, 'alertRaidSync', ['detail' => $array['name'] . ' ' . $percent((float) $array['sync']['percent'])], 'hardware');
        }
    }
    foreach ($data['temperatures'] ?? [] as $sensor) {
        $limit = match ($sensor['kind'] ?? '') { 'cpu' => ESM_WARN_CPU_CELSIUS, 'disk' => ESM_WARN_DISK_CELSIUS, default => null };
        if ($limit === null || !is_numeric($sensor['celsius'] ?? null) || $sensor['celsius'] < $limit) continue;
        $label = trim(($sensor['kind'] === 'disk' ? (string) ($sensor['name'] ?? '') . ' ' : '') . round((float) $sensor['celsius']) . ' °C');
        $add($sensor['celsius'] >= $limit + 10 ? 2 : 1, $sensor['kind'] === 'cpu' ? 'tempCpu' : 'tempDisk', ['detail' => $label], 'hardware');
    }

    if (!empty($data['reboot']['required'])) $add(1, 'healthReboot', [], 'system');
    $failed = array_column($data['failedUnits']['units'] ?? [], 'unit');
    if ($failed) $add(1, 'healthFailedUnits', ['detail' => $names($failed)], 'system');
    $fpm = $data['php']['fpm'] ?? null;
    if (is_array($fpm)) {
        if (($fpm['listenQueue'] ?? 0) > 0) $add(1, 'alertFpmQueue', ['detail' => (string) $fpm['listenQueue']], 'system');
        if (is_numeric($fpm['maxChildrenReachedAt'] ?? null) && time() - (int) $fpm['maxChildrenReachedAt'] < 3600) $add(1, 'alertFpmMax', [], 'system');
    }
    if (!empty($data['php']['opcache']['full'])) $add(1, 'alertOpcacheFull', [], 'system');

    foreach ($data['ports'] ?? [] as $port) {
        if (empty($port['sensitive']) || in_array((int) $port['port'], ESM_PORT_ALERT_IGNORE, true)) continue;
        $args = ['service' => (string) ($port['service'] ?? 'TCP'), 'port' => (int) $port['port']];
        if (($port['scope'] ?? '') === 'all') $add(1, 'alertPortAll', $args, 'network');
        else $add(1, 'alertPortPublic', $args + ['address' => (string) $port['address']], 'network');
    }
    $down = array_column(array_filter($data['services'] ?? [], static fn($s): bool => empty($s['online'])), 'name');
    if ($down) $add(1, 'services', ['detail' => $names($down)], 'network');
    $httpDown = array_filter($data['httpChecks'] ?? [], static fn($c): bool => ($c['online'] ?? null) === false && empty($c['stale']));
    $realDown = array_column(array_filter($httpDown, static fn($c): bool => empty($c['self'])), 'name');
    if ($realDown) $add(2, 'httpChecks', ['detail' => $names($realDown)], 'network');
    if (array_filter($httpDown, static fn($c): bool => !empty($c['self']))) $add(1, 'selfCheckNeedsConfig', [], 'network');
    foreach ($data['httpChecks'] ?? [] as $check) {
        $days = $check['tlsDays'] ?? null;
        if (!empty($check['stale']) || !is_numeric($days) || $days >= 14) continue;
        if ($days < 0) $add(2, 'alertTlsExpired', ['name' => (string) $check['name']], 'network');
        elseif (!empty($check['online'])) $add($days < 3 ? 2 : 1, 'alertTls', ['name' => (string) $check['name'], 'days' => (int) $days], 'network');
    }
    return $alerts;
}
// English wording, for ?api=health and --check (the page has its own translations).
function esmAlertText(array $alert): string
{
    static $english = [
        'alertInsecure' => 'This page is served without HTTPS: the password travels unencrypted',
        'alertNoCache' => 'The temporary directory is not writable: caches and per-process CPU are disabled',
        'memory' => 'Memory', 'alertDisk' => 'Disk {mount}', 'alertInodes' => 'Inodes on {mount}',
        'alertLoad' => 'High load average: {load} for {cores} cores',
        'pressureMemory' => 'Memory pressure', 'pressureIo' => 'I/O pressure',
        'alertOom' => 'The kernel killed a process for lack of memory in the last hour',
        'alertFiles' => 'Open files close to the system limit',
        'alertConntrack' => 'Connection tracking table almost full',
        'alertRaidDegraded' => 'RAID array degraded', 'alertRaidSync' => 'RAID array rebuilding',
        'tempCpu' => 'CPU temperature', 'tempDisk' => 'Disk temperature',
        'healthReboot' => 'Restart required', 'healthFailedUnits' => 'Failed services',
        'alertFpmQueue' => 'PHP-FPM: requests are waiting for a free worker',
        'alertFpmMax' => 'PHP-FPM reached its process limit (pm.max_children) in the last hour',
        'alertOpcacheFull' => 'OPcache memory is full',
        'alertPortAll' => '{service} (port {port}) is listening on all interfaces',
        'alertPortPublic' => '{service} (port {port}) is listening on the public address {address}',
        'services' => 'Services down', 'httpChecks' => 'HTTP checks failing',
        'selfCheckNeedsConfig' => 'Local HTTP probe failed: check the local port and virtual host configuration',
        'alertTls' => '{name}: certificate expires in {days} d', 'alertTlsExpired' => '{name}: certificate has expired',
    ];
    $text = $english[$alert['key']] ?? $alert['key'];
    foreach ($alert['args'] ?? [] as $name => $value) {
        if ($name !== 'detail') $text = str_replace('{' . $name . '}', (string) $value, $text);
    }
    $detail = (string) ($alert['args']['detail'] ?? '');
    return $detail !== '' ? $text . ': ' . $detail : $text;
}
function esmHealthSummary(array $data): array
{
    $alerts = $data['alerts'] ?? [];
    usort($alerts, static fn(array $a, array $b): int => $b['level'] <=> $a['level']);
    $level = $alerts ? max(array_column($alerts, 'level')) : 0;
    return [
        'ok' => true,
        'status' => ['ok', 'warning', 'critical'][$level],
        'host' => $data['system']['hostname'] ?? null,
        'time' => date(DATE_ATOM),
        'alerts' => array_map(static fn(array $alert): array => [
            'level' => ['ok', 'warning', 'critical'][$alert['level']],
            'key' => $alert['key'],
            'message' => esmAlertText($alert),
        ], $alerts),
    ];
}

// =============================================================
// 15. DATA COLLECTION, JSON API, PROMETHEUS METRICS AND COMMAND LINE
// =============================================================
function esmSafeCollect(string $module, callable $collector, array $fallback): array
{
    try {
        $result = $collector();
        return is_array($result) ? $result : $fallback;
    } catch (Throwable $error) {
        error_log('Monitor made Simple: collector ' . $module . ' failed (' . get_class($error) . ')');
        return $fallback;
    }
}

// $complete = everything, with the server-side usage thresholds (health, metrics, command line).
// Otherwise the heavier modules are only collected for the page that shows them.
function esmCollect(string $view, bool $complete = false): array
{
    $collectStart = microtime(true);
    $payload = [
        'ok' => true,
        'view' => $view,
        'version' => ESM_VERSION,
        'sampleTimeMs' => round(microtime(true) * 1000),
        'system' => esmSafeCollect('system', 'esmSystem', []),
        'cpu' => esmSafeCollect('cpu', 'esmCpu', ['total'=>null, 'idle'=>null, 'cores'=>[]]),
        'memory' => esmSafeCollect('memory', 'esmMemory', ['ram'=>null, 'swap'=>null, 'swapActivity'=>null]),
        'disks' => esmSafeCollect('disks', 'esmDisks', []),
        'diskIo' => esmSafeCollect('diskIo', 'esmDiskIo', []),
        'network' => esmSafeCollect('network', 'esmNetwork', []),
        'pressure' => esmSafeCollect('pressure', 'esmPressure', []),
        'services' => esmSafeCollect('services', 'esmServices', []),
        'httpChecks' => esmSafeCollect('httpChecks', 'esmHttpChecks', []),
        'reboot' => esmSafeCollect('reboot', 'esmReboot', ['required' => false, 'reasons' => []]),
        'failedUnits' => esmSafeCollect('failedUnits', 'esmFailedUnits', ['available' => false, 'units' => []]),
        'ports' => esmSafeCollect('ports', 'esmListeningPorts', []),
        'kernel' => esmSafeCollect('kernel', 'esmKernel', []),
        'raid' => esmSafeCollect('raid', 'esmRaid', []),
        'php' => esmSafeCollect('php', 'esmPhpRuntime', []),
        'secure' => esmTransportSecure(),
        'cache' => esmCacheDirectory() !== null,
    ];
    $temperatures = esmSafeCollect('temperatures', 'esmTemperaturesCached', []);
    if (!ESM_CLI && ($view === 'overview' || $view === 'processes')) {
        $payload['limit'] = $view === 'processes' ? ESM_PROCESS_DETAIL_LIMIT : 5;
        $payload['processes'] = esmProcessTop(esmSafeCollect('processes', 'esmProcesses', []), $payload['limit']);
    }
    if ($view === 'network' && !$complete) {
        $payload['traffic'] = esmSafeCollect('traffic', 'esmNetworkActivity', []);
    }
    if ($view === 'hardware' || $complete) {
        $payload['temperatures'] = $temperatures;
        $payload['gpus'] = esmSafeCollect('gpus', 'esmGpus', []);
    }
    $payload['alerts'] = esmSafeCollect('alerts', static fn(): array => esmAlerts($payload + ['temperatures' => $temperatures], $complete), []);
    $payload['collectionMs'] = round((microtime(true) - $collectStart) * 1000, 1);
    return $payload;
}

function esmPrometheus(array $data): string
{
    $lines = [];
    $declared = [];
    $metric = static function (string $name, string $type, string $help, $value, array $labels = []) use (&$lines, &$declared): void {
        if (!is_numeric($value)) return;
        if (!isset($declared[$name])) {
            $declared[$name] = true;
            $lines[] = '# HELP mms_' . $name . ' ' . $help;
            $lines[] = '# TYPE mms_' . $name . ' ' . $type;
        }
        $pairs = [];
        foreach ($labels as $label => $text) {
            $pairs[] = $label . '="' . str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], (string) $text) . '"';
        }
        $lines[] = 'mms_' . $name . ($pairs ? '{' . implode(',', $pairs) . '}' : '') . ' ' . (is_float($value) && floor($value) !== $value ? rtrim(sprintf('%.6F', $value), '0') : sprintf('%.0F', (float) $value));
    };
    $system = $data['system'] ?? [];
    $metric('info', 'gauge', 'Monitor made Simple version and host.', 1, ['version' => ESM_VERSION, 'hostname' => (string) ($system['hostname'] ?? '')]);
    $metric('uptime_seconds', 'gauge', 'Seconds since boot.', $system['uptimeSeconds'] ?? null);
    foreach ([1 => 0, 5 => 1, 15 => 2] as $minutes => $index) {
        $metric('load_average', 'gauge', 'Load average.', $system['load'][$index] ?? null, ['minutes' => $minutes]);
    }
    $metric('cpu_logical_cores', 'gauge', 'Logical CPU cores.', $system['logicalCores'] ?? null);
    $metric('cpu_ticks_total', 'counter', 'CPU time of all cores, in clock ticks.', $data['cpu']['total'] ?? null);
    $metric('cpu_idle_ticks_total', 'counter', 'Idle and I/O wait CPU time, in clock ticks.', $data['cpu']['idle'] ?? null);
    $ram = $data['memory']['ram'] ?? null;
    $metric('memory_total_bytes', 'gauge', 'Installed memory.', $ram['total'] ?? null);
    $metric('memory_used_bytes', 'gauge', 'Memory in use (total minus available).', $ram['used'] ?? null);
    $metric('memory_available_bytes', 'gauge', 'Memory available to programs.', $ram['available'] ?? null);
    $swap = $data['memory']['swap'] ?? null;
    $metric('swap_total_bytes', 'gauge', 'Swap size.', $swap['total'] ?? null);
    $metric('swap_used_bytes', 'gauge', 'Swap in use.', $swap['used'] ?? null);
    foreach ($data['disks'] ?? [] as $disk) {
        $labels = ['mount' => $disk['mount'], 'type' => $disk['type']];
        $metric('filesystem_size_bytes', 'gauge', 'Filesystem size.', $disk['total'], $labels);
        $metric('filesystem_used_bytes', 'gauge', 'Filesystem space in use.', $disk['used'], $labels);
        $metric('filesystem_inodes', 'gauge', 'Filesystem inodes.', $disk['inodes']['total'] ?? null, $labels);
        $metric('filesystem_inodes_used', 'gauge', 'Filesystem inodes in use.', $disk['inodes']['used'] ?? null, $labels);
    }
    foreach ($data['diskIo'] ?? [] as $device) {
        $metric('disk_read_bytes_total', 'counter', 'Bytes read from the device.', $device['readBytes'], ['device' => $device['name']]);
        $metric('disk_written_bytes_total', 'counter', 'Bytes written to the device.', $device['writeBytes'], ['device' => $device['name']]);
    }
    foreach ($data['network'] ?? [] as $link) {
        $metric('network_receive_bytes_total', 'counter', 'Bytes received.', $link['rx'], ['interface' => $link['name']]);
        $metric('network_transmit_bytes_total', 'counter', 'Bytes sent.', $link['tx'], ['interface' => $link['name']]);
        $metric('network_errors_total', 'counter', 'Receive and transmit errors.', $link['rxErrors'] + $link['txErrors'], ['interface' => $link['name']]);
    }
    foreach ($data['pressure'] ?? [] as $resource => $pressure) {
        $metric('pressure_avg10_percent', 'gauge', 'Share of time tasks waited for the resource, 10-second average.', $pressure['avg10'] ?? null, ['resource' => $resource]);
    }
    foreach ($data['temperatures'] ?? [] as $sensor) {
        $metric('temperature_celsius', 'gauge', 'Temperature sensor.', $sensor['celsius'] ?? null,
            ['kind' => $sensor['kind'] ?? '', 'name' => (string) ($sensor['name'] ?? ($sensor['index'] ?? ''))]);
    }
    foreach ($data['services'] ?? [] as $service) {
        $metric('service_up', 'gauge', 'TCP service check (1 = online).', empty($service['online']) ? 0 : 1, ['name' => $service['name']]);
    }
    foreach ($data['httpChecks'] ?? [] as $check) {
        if (($check['online'] ?? null) !== null) $metric('http_check_up', 'gauge', 'HTTP check (1 = online).', $check['online'] ? 1 : 0, ['name' => $check['name']]);
        $metric('tls_certificate_days', 'gauge', 'Days before the certificate expires.', $check['tlsDays'] ?? null, ['name' => $check['name']]);
    }
    if (!empty($data['failedUnits']['available'])) $metric('systemd_failed_units', 'gauge', 'Failed systemd units.', count($data['failedUnits']['units'] ?? []));
    $metric('reboot_required', 'gauge', 'A restart is required (1 = yes).', empty($data['reboot']['required']) ? 0 : 1);
    $metric('oom_kills_total', 'counter', 'Processes killed by the kernel for lack of memory, since boot.', $data['kernel']['oomKills'] ?? null);
    $metric('open_files', 'gauge', 'Open file handles.', $data['kernel']['openFiles']['used'] ?? null);
    $metric('conntrack_entries', 'gauge', 'Tracked connections.', $data['kernel']['conntrack']['used'] ?? null);
    foreach ($data['raid'] ?? [] as $array) {
        $metric('raid_degraded', 'gauge', 'Software RAID array degraded (1 = yes).', empty($array['degraded']) ? 0 : 1, ['array' => $array['name']]);
    }
    $fpm = $data['php']['fpm'] ?? [];
    $metric('php_fpm_active_processes', 'gauge', 'PHP-FPM workers serving a request.', $fpm['active'] ?? null);
    $metric('php_fpm_total_processes', 'gauge', 'PHP-FPM workers.', $fpm['total'] ?? null);
    $metric('php_fpm_listen_queue', 'gauge', 'Requests waiting for a PHP-FPM worker.', $fpm['listenQueue'] ?? null);
    $metric('php_fpm_max_children_reached_total', 'counter', 'Times the PHP-FPM process limit was reached.', $fpm['maxChildrenReached'] ?? null);
    $metric('php_opcache_used_bytes', 'gauge', 'OPcache memory in use.', $data['php']['opcache']['used'] ?? null);
    $levels = array_column($data['alerts'] ?? [], 'level');
    $metric('health_status', 'gauge', 'Overall health: 0 = ok, 1 = warning, 2 = critical.', $levels ? max($levels) : 0);
    $metric('alerts', 'gauge', 'Active alerts.', count($levels));
    return implode("\n", $lines) . "\n";
}

function esmCommandLine(array $arguments): int
{
    $options = array_slice($arguments, 1);
    if (in_array('--hash', $options, true)) {
        $terminal = function_exists('posix_isatty') && @posix_isatty(STDIN);
        fwrite(STDERR, 'Password: ');
        if ($terminal) @shell_exec('stty -echo 2>/dev/null');
        $password = rtrim((string) fgets(STDIN), "\r\n");
        if ($terminal) { @shell_exec('stty echo 2>/dev/null'); fwrite(STDERR, "\n"); }
        if ($password === '') { fwrite(STDERR, "Empty password.\n"); return 2; }
        echo password_hash($password, PASSWORD_DEFAULT), "\n";
        return 0;
    }
    if (in_array('--check', $options, true)) {
        $summary = esmHealthSummary(esmCollect('overview', true));
        $code = ['ok' => 0, 'warning' => 1, 'critical' => 2][$summary['status']];
        if (in_array('--json', $options, true)) {
            echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), "\n";
        } elseif ($code > 0 || !in_array('--quiet', $options, true)) {
            echo strtoupper($summary['status']), ' - ', $summary['host'] ?? 'server', ' - ', $summary['time'], "\n";
            foreach ($summary['alerts'] as $alert) echo '  [', $alert['level'], '] ', $alert['message'], "\n";
        }
        return $code;
    }
    echo "Monitor made Simple " . ESM_VERSION . "\n",
        "  php " . basename(__FILE__) . " --hash             ask for a password, print the hash for ESM_PASSWORD_HASH\n",
        "  php " . basename(__FILE__) . " --check            health summary; exit code 0 = ok, 1 = warning, 2 = critical\n",
        "  php " . basename(__FILE__) . " --check --quiet    print nothing when everything is fine\n",
        "  php " . basename(__FILE__) . " --check --json     same summary as ?api=health\n";
    return 0;
}
if (ESM_CLI) {
    exit(esmCommandLine($_SERVER['argv'] ?? []));
}

if (isset($_GET['api'])) {
    $api = is_string($_GET['api']) ? $_GET['api'] : '';
    if (!in_array($api, ['stats', 'health', 'metrics'], true)) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Not found']);
        exit;
    }
    $apiView = in_array($_GET['view'] ?? '', ['overview', 'system', 'network', 'hardware', 'processes'], true)
        ? (string) $_GET['view'] : 'overview';
    try {
        if ($api === 'metrics') {
            $body = esmPrometheus(esmCollect('overview', true));
            header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
        } elseif ($api === 'health') {
            $summary = esmHealthSummary(esmCollect('overview', true));
            $body = json_encode($summary, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            header('Content-Type: application/json; charset=utf-8');
            if ($summary['status'] === 'critical' || ($summary['status'] === 'warning' && !empty($_GET['strict']))) http_response_code(503);
        } else {
            $body = json_encode(esmCollect($apiView), JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
            header('Content-Type: application/json; charset=utf-8');
        }
        echo $body;
    } catch (Throwable $error) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Metrics unavailable']);
        error_log('Monitor made Simple statistics error: ' . $error->getMessage());
    }
    esmRunDeferred();
    exit;
}

// =============================================================
// 16. HTML INTERFACE
// =============================================================
header('Content-Type: text/html; charset=utf-8');
$nonce = htmlspecialchars(esmNonce(), ENT_QUOTES, 'UTF-8');
$title = htmlspecialchars(ESM_TITLE, ENT_QUOTES, 'UTF-8');
$refresh = max(2, min(60, ESM_REFRESH_SECONDS));
$view = in_array($_GET['view'] ?? '', ['overview', 'system', 'network', 'hardware', 'processes'], true)
    ? (string) $_GET['view'] : 'overview';
?><!doctype html>
<html lang="en" data-style="operations" data-view="<?= $view ?>">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title><?= $title ?> · Linux dashboard</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3QgeD0iNCIgeT0iNCIgd2lkdGg9IjU2IiBoZWlnaHQ9IjU2IiByeD0iMTIiIGZpbGw9IiMwMjA3MTEiLz48cmVjdCB4PSIxNCIgeT0iMTYuNSIgd2lkdGg9IjM1LjUiIGhlaWdodD0iMjguNSIgcng9IjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIyLjYiLz48cGF0aCBkPSJNMTggMzAuNGg3LjRsMy44LTcuNiA1LjYgMTIuNiA0LjQtNWg3IiBmaWxsPSJub25lIiBzdHJva2U9IiMzYWZmZWMiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz48cmVjdCB4PSIyOSIgeT0iMzciIHdpZHRoPSIyMy41IiBoZWlnaHQ9IjExIiByeD0iNS41IiBmaWxsPSIjNTk1N2I1IiBzdHJva2U9IiMwMjA3MTEiIHN0cm9rZS13aWR0aD0iMS42Ii8+PHRleHQgeD0iNDAuNzUiIHk9IjQ1LjYiIGZpbGw9IiNmZmYiIGZvbnQtZmFtaWx5PSJBcmlhbCxIZWx2ZXRpY2Esc2Fucy1zZXJpZiIgZm9udC1zaXplPSI4LjYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZvbnQtc3R5bGU9Iml0YWxpYyIgdGV4dC1hbmNob3I9Im1pZGRsZSI+UEhQPC90ZXh0Pjwvc3ZnPg==">
  <style nonce="<?= $nonce ?>">

:root, [data-style="operations"] {
  color-scheme:dark;
  --bg:#0a111b;--surface:#131e2c;--soft:#1c2a3b;
  --text:#edf4fc;--muted:#9aafc7;--border:#304155;
  --accent:#58c7dc;--good:#59d8a1;--warn:#edbd72;--bad:#f07e88;
  --grid:#5e98c00e;--shadow:0 10px 28px #00000030;
  --surface-hi:#18283a;--surface-border:#476079;
  --accent-glow:#56c6db1c;--chart-wash:#101b29;
}
[data-style="pro"] {
  color-scheme:light;
  --bg:#f5f7f9;--surface:#ffffff;--soft:#f1f4f7;
  --text:#182635;--muted:#637487;--border:#d9e1e8;
  --accent:#21658d;--good:#247a59;--warn:#a46b24;--bad:#bd4350;
  --grid:transparent;--shadow:none;
  --surface-hi:#ffffff;--surface-border:#bccbd6;
  --accent-glow:transparent;--chart-wash:#f8fafc;
}
[data-style="zen"] {
  color-scheme:dark;
  --bg:#273649;--surface:#324559;--soft:#3c5168;
  --text:#f3f7fc;--muted:#bccbdc;--border:#52677f;
  --accent:#72d5e7;--good:#6fe2b1;--warn:#f3c98a;--bad:#f6939c;
  --grid:#9cc7e812;--shadow:0 10px 28px #0000002a;
  --surface-hi:#384d64;--surface-border:#647d98;
  --accent-glow:#72d5e724;--chart-wash:#2d3f53;
}


* { box-sizing:border-box; }
html { font-family:system-ui, -apple-system, "Segoe UI", sans-serif; }
body {
  margin:0; min-height:100vh; color:var(--text); background:var(--bg);
  background-image:radial-gradient(var(--grid) 1.4px, transparent 1.4px);
  background-size:24px 24px;
}
button, select { font:inherit; color:inherit; }
button, select, summary { cursor:pointer; }
button:focus-visible, select:focus-visible, summary:focus-visible {
  outline:3px solid var(--accent); outline-offset:3px;
}
.wrap { width:min(2220px,calc(100% - 30px)); margin:0 auto; }
.header {
  display:flex; justify-content:space-between; align-items:center;
  flex-wrap:wrap; gap:16px; padding:24px 0 16px;
}
.brand { display:flex; align-items:center; gap:12px; }
.logo {
  width:48px; height:48px; border-radius:14px;
  display:grid; place-items:center; background:var(--accent);
  color:var(--surface); font-size:24px; font-weight:850;
}
h1 { font-size:clamp(1.3rem,3vw,1.85rem); margin:0; letter-spacing:.01em; }
.subtitle, .muted { color:var(--muted); }
.subtitle { font-size:.8rem; margin-top:2px; }
.toolbar { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.control {
  min-height:40px; border:1px solid var(--border); border-radius:9px;
  padding:8px 11px; background:var(--surface);
}
.control:hover { border-color:var(--accent); }
.status {
  display:inline-flex; gap:7px; align-items:center; padding:9px 11px;
  border:1px solid var(--border); background:var(--surface);
  border-radius:10px; font-size:.82rem;
}
.dot { width:8px; height:8px; border-radius:50%; background:var(--muted); }
.dot.ok { background:var(--good); }
.dot.error { background:var(--bad); }
.system-head {
  display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap;
  gap:6px 16px; margin:0 0 14px; color:var(--muted); font-size:.83rem;
}
.system-head strong { color:var(--text); }
.error-banner {
  display:none; margin:0 0 12px; padding:12px; border-radius:10px;
  color:var(--bad); border:1px solid var(--bad); background:var(--surface);
}
.error-banner.show { display:block; }
.metric, .panel {
  min-width:0; border:1px solid var(--border);
  background:var(--surface); border-radius:15px; box-shadow:var(--shadow);
}
.eyebrow {
  color:var(--muted); font-size:.7rem; font-weight:750;
  letter-spacing:.11em; text-transform:uppercase;
}
.big { font-size:clamp(1.35rem,2.6vw,2rem); font-weight:760; margin:8px 0; letter-spacing:-.035em; }
.tiny { color:var(--muted); font-size:.78rem; line-height:1.4; overflow-wrap:anywhere; }
.progress { height:7px; border-radius:9px; overflow:hidden; margin:10px 0 8px; background:var(--soft); }
.progress > i { display:block; width:0; height:100%; background:var(--accent); transition:width .4s ease; }
.progress > i.warn { background:var(--warn); }
.progress > i.bad { background:var(--bad); }
.summary {
  display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-bottom:14px;
}
.metric { padding:18px; }
.panel { padding:19px; margin-bottom:14px; }
.panel h2 {
  display:flex; align-items:center; gap:9px;
  margin:0 0 17px; font-size:.98rem; font-weight:700;
}
.icon {
  display:inline-grid; place-items:center; flex:0 0 auto;
  width:28px; height:28px; border-radius:8px; font-size:16px;
  background:var(--soft); color:var(--accent);
}
.dashboard { display:grid; grid-template-columns:repeat(var(--dashboard-cols,2),minmax(0,1fr)); align-items:start; gap:14px; }
.column { min-width:0; }
.rows { display:grid; gap:11px; }
.r { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; font-size:.85rem; }
.r .label { color:var(--muted); }
.r .value { min-width:0; max-width:65%; text-align:right; font-weight:650; overflow-wrap:anywhere; }
.hr { height:1px; background:var(--border); margin:15px 0; }
.note { color:var(--muted); font-size:.76rem; margin:10px 0 0; line-height:1.5; }
.empty { color:var(--muted); font-size:.85rem; }
.smalltext { color:var(--muted); font-size:.76rem; line-height:1.5; overflow-wrap:anywhere; margin-top:6px; }
.pill {
  display:inline-block; border-radius:999px; background:var(--surface);
  padding:4px 9px; white-space:nowrap; color:var(--muted);
  font-size:.72rem; font-weight:750;
}
.pill.up { color:var(--good); }
.pill.down { color:var(--bad); }
.pill.enabled { color:var(--accent); }
.meter-row { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.meter-row strong { font-size:.87rem; overflow-wrap:anywhere; }
.item { border-radius:10px; padding:12px; background:var(--soft); min-width:0; }
.item + .item { margin-top:9px; }
.meter-list { display:grid; gap:10px; }
.meter-list .item + .item { margin-top:0; }
.foot { padding:14px 0 27px; text-align:center; color:var(--muted); font-size:.75rem; }


.charts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.chart-card { min-width:0; }
.chart-card:last-child:nth-child(odd) { grid-column:1 / -1; }
.chart-title { display:flex; align-items:center; justify-content:space-between; gap:6px; margin:0 0 7px; color:var(--muted); font-size:.76rem; }
.legend { display:inline-flex; gap:9px; align-items:center; flex-wrap:wrap; }
.legend span { white-space:nowrap; }
.legend i { display:inline-block; width:11px; height:3px; background:var(--accent); border-radius:3px; vertical-align:middle; margin-right:3px; }
.legend i.second { background:var(--good); }
.chart {
  width:100%; height:98px; display:block; background:var(--soft);
  border:1px solid var(--border); border-radius:9px;
}
.details { margin-top:12px; border-top:1px solid var(--border); padding-top:11px; }
.details summary { font-size:.83rem; color:var(--accent); font-weight:650; }
.details[open] summary { margin-bottom:10px; }
.core-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:8px; }
.core { border-radius:9px; background:var(--soft); padding:8px; }
.core .meter-row { font-size:.78rem; }
.core .progress { height:5px; margin:7px 0 0; }
.details .item { margin-bottom:8px; }
.network-item > summary { list-style:none; cursor:pointer; }
.network-item > summary::-webkit-details-marker { display:none; }
.network-item > summary::before { content:'▸'; color:var(--accent); margin-right:6px; }
.network-item > summary > strong { margin-right:auto; text-align:left; }
.network-item[open] > summary::before { content:'▾'; }
.network-item > .network-quick { margin-left:14px; }
.network-item > .network-detail { margin-top:9px; border-top:1px solid var(--border); padding-top:5px; }
.network-item > .network-detail .smalltext { margin-top:5px; }
.notice { font-size:.77rem; color:var(--muted); margin-top:8px; }
.pressure-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:9px; }
.pressure-item { background:var(--soft); border-radius:9px; padding:12px; }
.pressure-item strong { display:block; margin-top:6px; font-size:1.1rem; }
.pressure-item small { display:block; color:var(--muted); font-size:.72rem; line-height:1.45; }
.pressure-item small + small { margin-top:3px; }


.help-cluster { display:flex; justify-content:flex-end; align-items:center; gap:5px; min-height:23px; margin-top:5px; }
.help-button { display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border:1px solid var(--border); border-radius:50%; color:var(--muted); background:var(--surface); font-size:.78rem; font-weight:800; cursor:help; touch-action:manipulation; }
.help-button[hidden],.help-cluster[hidden] { display:none!important; }
.help-button:hover,.help-button:focus-visible { color:var(--accent); border-color:var(--accent); outline-offset:2px; }
.help-popover { position:fixed; z-index:4000; width:min(345px,calc(100vw - 24px)); max-height:min(60vh,380px); overflow:auto; padding:11px 13px; border:1px solid var(--border); border-radius:10px; color:var(--text); background:var(--surface); box-shadow:0 15px 45px #0005; font-size:.78rem; line-height:1.5; white-space:pre-line; pointer-events:none; }
.help-popover[hidden] { display:none!important; }
.dialog .help-popover { z-index:10; }
.chart-tooltip {position:fixed;z-index:4100;pointer-events:none;max-width:min(350px,calc(100vw - 16px));padding:7px 10px;background:var(--surface);color:var(--text);border:1px solid var(--accent);border-radius:8px;box-shadow:0 10px 30px #0005;font-size:.75rem;line-height:1.4;white-space:normal;}
.chart-tooltip[hidden] {display:none!important;}
.dialog .chart-tooltip {z-index:12;}
.chart-stats { font-size:.69rem; color:var(--muted); margin:5px 1px 0; line-height:1.4; overflow-wrap:normal; }

.health-banner { border:1px solid var(--border); background:var(--surface); border-radius:13px; padding:12px 17px; margin:0 0 13px; }
.health-main { display:flex; flex-wrap:wrap; gap:9px; align-items:center; }
.health-main strong { font-size:.9rem; }
.health-dot { flex:0 0 auto; border-radius:50%; width:10px; height:10px; background:var(--muted); }
.health-banner.ok { border-left:4px solid var(--good); }
.health-banner.warn { border-left:4px solid var(--warn); }
.health-banner.bad { border-left:4px solid var(--bad); }
.health-banner.ok .health-dot { background:var(--good); }
.health-banner.warn .health-dot { background:var(--warn); }
.health-banner.bad .health-dot { background:var(--bad); }
.health-reasons { display:flex; flex-wrap:wrap; gap:5px 13px; margin-top:7px; font-size:.77rem; }
.health-reasons span { color:var(--text); }
.health-disclaimer { color:var(--muted); margin:6px 0 0; font-size:.68rem; }
.process-columns { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.process-group { min-width:0; }
.process-group h3 { font-size:.82rem; color:var(--muted); margin:0 0 8px; }
.process-item { display:grid; grid-template-columns:minmax(0,1fr) auto; column-gap:8px; padding:8px 9px; border-radius:8px; background:var(--soft); margin-bottom:6px; }
.process-name { font-size:.79rem; font-weight:650; text-overflow:ellipsis; white-space:nowrap; overflow:hidden; min-width:0; }
.process-detail { color:var(--muted); font-size:.7rem; margin-top:3px; }
.process-value { font-size:.8rem; font-weight:700; align-self:center; white-space:nowrap; }
.chart-title { min-height:25px; }
.chart-expand { flex-shrink:0; background:var(--surface); border:1px solid var(--border); border-radius:6px; min-width:26px; height:25px; color:var(--accent); font-size:1rem; }
.chart-expand:hover { background:var(--soft); }
[data-chart-card][hidden], .panel[hidden] { display:none !important; }
.dialog { border:1px solid var(--border); border-radius:15px; background:var(--surface); color:var(--text); padding:20px; width:min(690px,calc(100% - 22px)); max-height:calc(100vh - 34px); max-height:calc(100dvh - 34px); overflow:auto; box-shadow:0 30px 90px #0007; }
.dialog::backdrop { background:#030712ad; backdrop-filter:blur(4px); }
.dialog-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; position:sticky; top:0; background:var(--surface); padding:6px 0 10px; z-index:2; }
.dialog-head h2 { margin:0; font-size:1.18rem; }
.dialog h3 { font-size:.89rem; margin:18px 0 10px; }
.settings-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.settings-field { display:grid; gap:5px; font-size:.78rem; color:var(--muted); }
.settings-field .control { width:100%; color:var(--text); }
.settings-checks { display:flex; flex-wrap:wrap; gap:7px 16px; }
.settings-checks label, .panel-option label { display:inline-flex; align-items:center; gap:7px; font-size:.8rem; }
.settings-checks input, .panel-option input { accent-color:var(--accent); }
.settings-panels { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
.settings-panels h4 { color:var(--muted); font-size:.78rem; margin:0 0 8px; }
.panel-option { display:flex; justify-content:space-between; gap:6px; align-items:center; background:var(--soft); border-radius:8px; margin:5px 0; padding:6px 8px; }
.panel-option label { overflow-wrap:anywhere; }
.order-buttons { display:inline-flex; gap:4px; }
.order-buttons button { border:1px solid var(--border); background:var(--surface); border-radius:5px; min-width:25px; min-height:26px; }
.order-buttons button:disabled { opacity:.3; cursor:default; }
.dialog-actions { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:8px; margin-top:20px; }
.control.primary { color:var(--surface); background:var(--accent); border-color:var(--accent); font-weight:700; }
.zoom-dialog { width:min(900px,calc(100% - 22px)); }
.zoom-dialog .chart { height:clamp(220px,42vh,370px); }
.inode-line { margin-top:7px; font-size:.75rem; color:var(--muted); }
.pill.warn { color:var(--warn); }
.pill.critical { color:var(--bad); }
@media (max-width:620px) {
 .settings-panels, .settings-grid, .process-columns { grid-template-columns:1fr; }
 .health-banner { padding:10px 12px; }
 .dialog { padding:13px; }
}


@media (max-width:1020px) {
  .summary { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .core-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
}
@media (max-width:800px) {
   .summary { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .summary .metric:last-child { grid-column:1 / -1; }
}
@media (max-width:520px) {
  .wrap { width:calc(100% - 20px); }
  .header { padding:13px 0; }
  .toolbar { width:100%; }
  .toolbar select { flex:1; min-width:100px; }
  .metric, .panel { padding:13px; border-radius:12px; }
  .summary { gap:8px; }
  .big { font-size:1.45rem; }
  .charts { grid-template-columns:1fr; }
  .chart-card:last-child:nth-child(odd) { grid-column:auto; }
  .core-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .r { font-size:.8rem; }
  .pressure-grid { gap:6px; }
  .pressure-item { padding:8px; }
}
@media (prefers-reduced-motion:reduce) {
  *, *::before, *::after { animation:none !important; transition:none !important; }
}


html { font-size:15px; scroll-behavior:smooth; }
body {
  background-color:var(--bg);
  background-image:radial-gradient(ellipse at 0% 0%,var(--accent-glow),transparent 42%),
                   radial-gradient(var(--grid) .85px,transparent .85px);
  background-size:auto,26px 26px;
  background-attachment:fixed;
  line-height:1.45;
  -webkit-font-smoothing:antialiased;
}
.wrap { width:min(2220px,calc(100% - 44px)); }
.header {
  position:relative; margin-top:18px; margin-bottom:15px;
  padding:17px 20px; gap:18px;
  border:1px solid var(--border); border-radius:20px;
  background:var(--surface); box-shadow:var(--shadow);
}
.brand { gap:14px; min-width:0; }
.logo {
  position:relative; width:54px; height:54px; border-radius:16px;
  color:white; font-size:29px; font-weight:780; flex:0 0 auto;
  background:linear-gradient(145deg,var(--accent),color-mix(in srgb,var(--accent) 76%,#362c22));
  box-shadow:0 8px 21px var(--accent-glow);
  letter-spacing:-.08em;
}
.logo > span:first-child { transform:translate(-1px,-1px); }
.logo-pulse { position:absolute; right:9px; top:10px; width:7px; height:7px; border-radius:50%; background:#d8f7df; box-shadow:0 0 0 3px #ffffff29; }
h1 { font-size:clamp(1.4rem,2.2vw,1.8rem); font-weight:780; letter-spacing:-.045em; line-height:1.16; }
.subtitle { font-size:.78rem; margin-top:5px; letter-spacing:.015em; }
.toolbar { gap:8px; }
.control {
  min-height:39px; padding:8px 12px; border-radius:11px;
  background:var(--surface-hi); border-color:var(--border);
  transition:background .18s,border-color .18s,transform .18s,box-shadow .18s;
}
button.control { min-width:41px; font-weight:650; }
.control:hover { background:var(--soft); border-color:var(--accent); }
button.control:active { transform:translateY(1px); }
.status { min-height:39px; border-radius:999px; border-color:var(--border); background:var(--soft); font-weight:650; padding:8px 14px; }
.dot { width:9px; height:9px; box-shadow:0 0 0 3px var(--accent-glow); }
.dot.ok { box-shadow:0 0 0 3px color-mix(in srgb,var(--good) 18%,transparent); }
.dot.error { box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 18%,transparent); }
.system-head {
  padding:0 5px; margin-bottom:11px; font-size:.79rem; gap:6px 16px;
}
.system-head strong { font-weight:720; }
.health-banner {
  position:relative; border-radius:15px; padding:13px 18px;
  margin-bottom:14px; box-shadow:var(--shadow);
  background:var(--surface); border-color:var(--border);
}
.health-banner.ok { border-left:3px solid var(--good); }
.health-banner.warn { border-left:3px solid var(--warn); }
.health-banner.bad { border-left:3px solid var(--bad); }
.health-main { gap:10px; }
.health-main strong { font-size:.95rem; letter-spacing:-.01em; }
.health-reasons { margin-top:6px; font-size:.75rem; color:var(--muted); }
.health-reasons span { color:var(--muted); }
.health-banner .help-cluster { position:absolute; right:11px; top:9px; min-height:22px; margin:0; }
.health-banner .health-main { padding-right:24px; }
.summary { gap:12px; margin-bottom:15px; }
.metric, .panel { border-radius:17px; border-color:var(--border); box-shadow:var(--shadow); background:var(--surface); }
.metric {
  position:relative; min-height:140px; padding:17px 18px;
  overflow:hidden; display:flex; flex-direction:column; justify-content:flex-start;
  transition:border-color .2s,transform .2s,box-shadow .2s;
}
.metric::before { content:""; position:absolute; inset:0 auto 0 0; width:3px; background:var(--accent); opacity:.68; }
.metric:nth-child(2)::before { background:var(--good); }
.metric:nth-child(3)::before { background:var(--warn); }
.metric:nth-child(4)::before { background:#7f8ec5; }
.metric:nth-child(5)::before { background:var(--muted); }
.eyebrow { font-size:.72rem; font-weight:700; letter-spacing:.055em; text-transform:none; }
.metric-value-row { display:flex; align-items:center; justify-content:space-between; gap:7px; margin:3px 0 1px; }
.big { margin:4px 0 5px; font-size:clamp(1.45rem,2.35vw,2.18rem); font-weight:780; letter-spacing:-.055em; font-variant-numeric:tabular-nums; white-space:nowrap; }
.progress { height:6px; margin:8px 0 8px; background:var(--soft); }
.progress > i { border-radius:100px; }
.metric .tiny { margin-top:auto; font-size:.73rem; line-height:1.35; }
.panel { padding:18px; margin-bottom:14px; }
.panel h2 {
  gap:9px; margin-bottom:16px; font-size:.95rem; font-weight:750;
  letter-spacing:-.015em; line-height:1.25;
}
.icon { width:30px; height:30px; border-radius:10px; font-size:17px; background:var(--soft); color:var(--accent); }
.dashboard { gap:14px; }
.item { border:1px solid transparent; border-radius:11px; padding:11px 12px; background:var(--soft); }
.item + .item { margin-top:8px; }
.r { align-items:baseline; font-size:.81rem; gap:9px; }
.r .value { font-variant-numeric:tabular-nums; font-weight:650; }
.rows { gap:10px; }
.pill { background:var(--soft); font-weight:680; padding:4px 9px; }
.pill.up { background:color-mix(in srgb,var(--good) 9%,var(--surface)); }
.pill.down { background:color-mix(in srgb,var(--bad) 9%,var(--surface)); }
.charts { gap:10px; }
.chart-card { border:1px solid var(--border); background:var(--chart-wash); border-radius:12px; padding:10px 11px 8px; min-width:0; }
.chart-title { min-height:25px; color:var(--text); margin-bottom:7px; font-size:.75rem; font-weight:650; }
.chart { background:transparent; border:0; border-radius:6px; height:106px; }
.chart-stats { font-size:.69rem; margin:3px 0 0; }
.legend { font-size:.7rem; font-weight:500; color:var(--muted); }
.chart-expand { min-width:26px; border-color:var(--border); border-radius:8px; background:var(--surface); }
.chart-expand:hover { border-color:var(--accent); }
.process-group h3 { font-size:.79rem; font-weight:760; }
.process-item { background:var(--soft); border-radius:10px; margin-bottom:6px; padding:9px 10px; }
.process-value { font-variant-numeric:tabular-nums; }
.pressure-item, .core { border-radius:10px; }
.network-item > summary { align-items:center; }
.network-item > summary > strong { margin-right:auto; }
.help-button { background:var(--soft); border-color:var(--border); font-weight:800; }
.help-button:hover, .help-button:focus-visible { background:var(--accent-glow); }
.help-popover { border-radius:14px; padding:14px 16px; box-shadow:0 20px 50px #0003; }
.dialog { border-radius:19px; border-color:var(--border); }
.dialog-head { border-bottom:1px solid var(--border); }
.dialog .control.primary { color:#fff; }
.foot { padding:14px 0 26px; font-size:.73rem; }
@media (hover:hover) and (pointer:fine) {
  .metric:hover, .panel:hover { border-color:var(--surface-border); }
  .metric:hover { transform:translateY(-2px); box-shadow:0 7px 20px #0000000a,0 20px 50px #0000000e; }
}
@media (max-width:1020px) {
  .metric { min-height:132px; }
}
@media (max-width:800px) {
  .header { margin-top:12px; }
}
@media (max-width:520px) {
  .wrap { width:calc(100% - 22px); }
  .header { margin-top:11px; padding:14px; border-radius:16px; gap:12px; }
  .logo { width:44px; height:44px; border-radius:13px; font-size:23px; }
  .toolbar { gap:6px; }
  .toolbar .status { flex:1; justify-content:center; }
  .control { min-height:40px; }
  .metric { min-height:123px; padding:13px; border-radius:14px; }
  .big { font-size:clamp(1.23rem,5.5vw,1.6rem); }
  .metric .tiny { font-size:.68rem; }
  .panel { padding:14px; border-radius:14px; }
  .chart-card { padding:9px 10px; }
  .chart { height:116px; }
  .health-banner { padding:12px 14px; }
}
@media (prefers-reduced-motion:reduce) {
  html { scroll-behavior:auto; }
  .metric { transform:none !important; }
}



.logo {background:#05070b !important; border:1px solid #333c49; border-radius:14px; box-shadow:none; overflow:hidden; padding:6px;}
.logo svg {width:100%;height:100%;display:block;}
.style-picker {display:flex;gap:7px;align-items:center;color:var(--muted);font-size:.75rem;font-weight:680;}
.style-picker select {min-width:132px;font-size:.83rem;}
.process-columns {grid-template-columns:repeat(2,minmax(0,1fr));}
.process-swap-group {grid-column:1 / -1;}
.process-swap-group #processSwapList {display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;}
.process-swap-group .process-item {margin-bottom:0;}
@media (max-width:620px) {
  .process-columns {grid-template-columns:1fr;}
  .process-swap-group {grid-column:auto;}
  .process-swap-group #processSwapList {grid-template-columns:1fr;}
  .style-picker span {display:none;}
  .style-picker select {min-width:108px;}
}

[data-style="operations"] body {background-image:none;}
[data-style="operations"] .header {border-radius:13px;background:#152235;border:1px solid #344960;}
[data-style="operations"] .metric,[data-style="operations"] .panel {border-radius:12px;}
[data-style="operations"] .metric {border-top:1px solid var(--border);}
[data-style="operations"] .metric::before {width:0;}
[data-style="operations"] .big {font-variant-numeric:tabular-nums;letter-spacing:-.06em;}
[data-style="operations"] .chart-card {border-radius:7px;}
[data-style="operations"] .process-item,[data-style="operations"] .item {border-radius:6px;}
[data-style="operations"] .health-banner {border-radius:8px;background:#172536;}
[data-style="operations"] .status {background:#1b3140;}

[data-style="pro"] body {background-image:none;}
[data-style="pro"] .header {border-radius:5px;box-shadow:none;padding:13px 16px;margin-top:12px;}
[data-style="pro"] .metric,[data-style="pro"] .panel {border-radius:5px;box-shadow:none;}
[data-style="pro"] .metric {min-height:119px;padding:13px 15px;}
[data-style="pro"] .metric::before {width:0;}
[data-style="pro"] .big {font-weight:720;}
[data-style="pro"] .icon {border-radius:4px;}
[data-style="pro"] .item,[data-style="pro"] .process-item,[data-style="pro"] .chart-card {border-radius:4px;}
[data-style="pro"] .chart-card {background:var(--surface);}
[data-style="pro"] .control {border-radius:5px;}
[data-style="pro"] .health-banner {border-radius:5px;box-shadow:none;}
[data-style="pro"] .status {border-radius:5px;}
[data-style="pro"] .panel h2 {border-bottom:1px solid var(--border);padding-bottom:10px;}
[data-style="pro"] .metric:hover {transform:none;box-shadow:none;}

/* "Dusk": the night style, lightened */
[data-style="zen"] body {background-image:none;}
[data-style="zen"] .header {border-radius:13px;background:#33495f;border:1px solid #5a7390;}
[data-style="zen"] .metric,[data-style="zen"] .panel {border-radius:12px;}
[data-style="zen"] .metric {border-top:1px solid var(--border);}
[data-style="zen"] .metric::before {width:0;}
[data-style="zen"] .big {font-variant-numeric:tabular-nums;letter-spacing:-.06em;}
[data-style="zen"] .chart-card {border-radius:7px;}
[data-style="zen"] .process-item,[data-style="zen"] .item {border-radius:6px;}
[data-style="zen"] .health-banner {border-radius:8px;background:#30445a;}
[data-style="zen"] .status {background:#355168;}

  
/* Process detail page (?view=processes) */
.process-view { display:none; }
[data-view="processes"] .process-view { display:block; }
[data-view="processes"] .dashboard { display:none !important; }
html:not([data-view="overview"]) .summary { display:none !important; }
.process-view-head { display:flex; align-items:baseline; flex-wrap:wrap; gap:6px 14px; margin:2px 0 14px; }
.process-view-head h2 { margin:0; font-size:1.15rem; }
.detail-columns { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; align-items:start; }
.detail-columns .panel { margin-bottom:0; }
.detail-list { list-style:none; margin:0; padding:0; }
.detail-list .process-item { grid-template-columns:2em minmax(0,1fr) auto; }
.process-rank { align-self:center; color:var(--muted); font-size:.76rem; font-variant-numeric:tabular-nums; }

/* View tabs */
.view-tabs { display:flex; flex-wrap:wrap; gap:6px; margin:14px 0 10px; }
@media (max-width:620px) {
  .view-tabs { flex-wrap:nowrap; overflow-x:auto; scrollbar-width:none; margin-inline:-2px; padding:0 2px 2px; }
  .view-tabs a { flex:0 0 auto; padding:7px 12px; }
}
.view-tabs a {
  padding:8px 15px; border-radius:999px; border:1px solid var(--border); background:var(--surface);
  color:var(--muted); text-decoration:none; font-size:.86rem; font-weight:680;
}
.view-tabs a:hover, .view-tabs a:focus-visible { color:var(--text); border-color:var(--surface-border); }
.view-tabs a[aria-current="page"] { background:var(--accent); border-color:var(--accent); color:var(--bg); }
[data-style="pro"] .view-tabs a { border-radius:5px; }
.panel-action {
  margin-left:auto; display:inline-flex; align-items:center; gap:6px; padding:5px 12px; border-radius:999px;
  border:1px solid var(--accent); color:var(--accent); text-decoration:none; font-size:.76rem; font-weight:720; white-space:nowrap;
}
.panel-action:hover, .panel-action:focus-visible { background:var(--accent); color:var(--bg); }
[data-style="pro"] .panel-action { border-radius:5px; }
.health-reasons a { color:inherit; text-decoration:underline dotted; text-underline-offset:3px; }
.health-reasons a:hover, .health-reasons a:focus-visible { color:var(--accent); }
.check-row { display:flex; justify-content:space-between; align-items:center; gap:10px; padding:8px 10px; border-radius:8px; background:var(--soft); font-size:.84rem; min-width:0; }
.check-row + .check-row { margin-top:6px; }
.check-row .check-name { min-width:0; overflow-wrap:anywhere; }
.check-row .check-name small { display:block; color:var(--muted); font-size:.72rem; margin-top:2px; }
.check-row strong { font-variant-numeric:tabular-nums; }
.pill.warn { color:var(--warn); }
.ok-message { color:var(--good); font-size:.85rem; font-weight:650; }
@media (max-width:1100px) { .detail-columns { grid-template-columns:1fr; } }

/* Source code and support footer */
.site-footer {
  display:flex; align-items:center; justify-content:center; flex-wrap:wrap; gap:.45rem;
  width:max-content; max-width:100%; margin:0 auto 26px; padding:9px 16px; border-radius:999px;
  background:rgba(9,13,22,.78); color:rgba(245,247,255,.72); border:1px solid rgba(255,255,255,.12);
  box-shadow:0 10px 28px rgba(0,0,0,.18); backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px);
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; font-size:.92rem; line-height:1.25;
}
.site-footer[hidden] { display:none; }
.site-footer a { color:#d7c8ff; text-decoration:none; font-weight:700; }
.site-footer a:hover, .site-footer a:focus-visible { text-decoration:underline; }
.site-footer .footer-sep { color:rgba(245,247,255,.45); }
.footer-support { display:inline-flex; align-items:center; gap:.28rem; color:#f5d987 !important; }
.footer-support strong { color:#ffe68d; font-weight:800; }
.footer-strike { color:#e7c0a0; text-decoration-line:line-through; text-decoration-color:#d76a7d; text-decoration-thickness:.14em; }
.footer-cup { width:1.05em; height:1.05em; color:#d9b963; flex:0 0 auto; stroke-width:1.9; }
@media (max-width:620px) {
  .site-footer { padding:8px 12px; border-radius:18px; font-size:.82rem; row-gap:5px; }
  .site-footer .footer-text { width:100%; text-align:center; }
}

/* Quieter tiles, charts that can be read without hovering */
.big { font-variant-numeric:tabular-nums; white-space:nowrap; }
.metric .tiny { font-size:.72rem; opacity:.85; }
.progress > i { background:var(--muted); }
.progress > i.warn { background:var(--warn); }
.progress > i.bad { background:var(--bad); }
.metric:hover { transform:none !important; }
.chart-box { position:relative; }
.chart-overlay { position:absolute; inset:0; pointer-events:none; font-size:.64rem; color:var(--muted); }
.chart-scale { position:absolute; top:3px; left:6px; opacity:.8; font-variant-numeric:tabular-nums; }
.chart-threshold { position:absolute; right:6px; transform:translateY(-118%); color:var(--warn); font-weight:650; white-space:nowrap; }
.chart-dot { position:absolute; width:8px; height:8px; margin:-4px 0 0 -4px; border-radius:50%; background:var(--accent); box-shadow:0 0 0 2px var(--surface); }
.chart-dot.second { background:var(--good); }
.chart-threshold-line { stroke:var(--warn); }
.chart-axis { display:flex; justify-content:space-between; margin:4px 1px 0; font-size:.63rem; color:var(--muted); font-variant-numeric:tabular-nums; }
.chart-card .chart-stats, .zoom-dialog .chart-stats { display:flex; flex-wrap:wrap; align-items:baseline; gap:2px 10px; margin:0 1px 6px; font-size:.7rem; color:var(--muted); }
.chart-stats strong { color:var(--text); font-size:1.02rem; font-weight:720; font-variant-numeric:tabular-nums; }
.chart-pair { display:inline-flex; align-items:baseline; gap:3px; }
.chart-pair i { display:inline-block; width:9px; height:3px; border-radius:3px; background:var(--accent); transform:translateY(-3px); }
.chart-pair.second i { background:var(--good); }
.chart-pair strong { font-size:.9rem; }
.zoom-dialog .chart-stats strong { font-size:1.3rem; }
[data-style="operations"], [data-style="zen"] { --shadow:none; }

/* 1.4.0 */
/* Alerts: most serious first, each with its own colour */
.health-reason { display:inline-flex; align-items:baseline; gap:6px; }
.health-reason > i { flex:0 0 auto; width:7px; height:7px; border-radius:50%; background:var(--warn); transform:translateY(-1px); }
.health-reason.level-2 > i { background:var(--bad); }
.health-reason.level-2, .health-reason.level-2 a { color:var(--text); }
.health-more { border:1px solid var(--border); border-radius:999px; background:var(--soft); padding:1px 9px; font-size:.74rem; font-weight:700; }
.health-more:hover, .health-more:focus-visible { border-color:var(--accent); color:var(--accent); }
/* Connection lost: what is on screen is no longer current */
.summary, .dashboard, .process-view, .health-banner { transition:opacity .3s; }
[data-stale] .summary, [data-stale] .dashboard, [data-stale] .process-view, [data-stale] .health-banner { opacity:.5; }
/* Small print stays readable */
.chart-axis, .chart-overlay { font-size:.7rem; }
.chart-card .chart-stats, .zoom-dialog .chart-stats { font-size:.74rem; }
.health-disclaimer { font-size:.72rem; }
.pressure-item small, .process-detail, .check-row .check-name small { font-size:.74rem; }
.value.warn-text { color:var(--warn); }
/* Network activity */
.list-title { margin:16px 0 8px; font-size:.78rem; font-weight:700; color:var(--muted); letter-spacing:.02em; }
.traffic-row { align-items:flex-start; }
.traffic-row .pill { flex:0 0 auto; white-space:nowrap; }
.traffic-row .check-name { font-variant-numeric:tabular-nums; }
.tag { display:inline-block; margin-left:6px; padding:0 6px; border:1px solid var(--border); border-radius:999px; color:var(--muted); font-size:.68rem; font-weight:650; vertical-align:1px; }
.status-line { display:flex; flex-wrap:wrap; gap:4px 12px; justify-content:flex-end; }
.status-line .s4 { color:var(--warn); } .status-line .s5 { color:var(--bad); }
.mini-bars { display:block; width:100%; height:44px; margin-top:12px; }
.mini-bars rect { fill:var(--accent); }
.mini-bars rect.zero { fill:var(--border); }
.mini-axis { display:flex; justify-content:space-between; color:var(--muted); font-size:.7rem; margin-top:3px; }
.acl-warning { margin:10px 0 0; padding:9px 11px; border:1px solid color-mix(in srgb,var(--warn) 45%,var(--border)); border-left-width:3px; border-radius:8px; background:color-mix(in srgb,var(--warn) 7%,var(--surface)); font-size:.8rem; line-height:1.5; }
.code-hint { display:block; margin-top:8px; padding:9px 11px; border:1px solid var(--border); border-radius:8px; background:var(--soft); font:.74rem/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; overflow-wrap:anywhere; user-select:all; }
.value.bad-text { color:var(--bad); }
</style>
</head>
<body>
  <div class="wrap">
    <header class="header">
      <div class="brand">
        <div class="logo" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#05070b"/><rect x="10" y="12" width="44" height="38" rx="7" fill="none" stroke="#f7fafc" stroke-width="3.5"/><path d="M14 33h9l6-13 8 25 6-12h7" fill="none" stroke="#56d7c7" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
        <div>
          <h1><?= $title ?></h1>
          <div class="subtitle" data-i18n="tagline">A lightweight Linux dashboard</div>
        </div>
      </div>
      <div class="toolbar">
        <span class="status" aria-live="polite">
          <span class="dot" id="connectionDot" aria-hidden="true"></span>
          <span id="connectionText" data-i18n="connecting">Connecting…</span>
        </span>
        <select class="control" id="language" aria-label="Language">
          <option value="en">English</option>
          <option value="fr">Français</option>
          <option value="es">Español</option>
          <option value="zh">中文</option>
          <option value="hi">हिन्दी</option>
          <option value="ja">日本語</option>
        </select>
        <label class="style-picker"><span data-i18n="interfaceStyle">Style</span><select class="control" id="styleChoice" aria-label="Interface style"><option value="auto" data-i18n="styleAuto">Auto</option><option value="operations" data-i18n="styleNight">Night</option><option value="zen" data-i18n="styleDim">Dusk</option><option value="pro" data-i18n="styleLight">Light</option></select></label>
        <button type="button" class="control" id="settings" aria-label="Settings" title="Settings">⚙</button>
        <button type="button" class="control" id="refresh" aria-label="Refresh" title="Refresh">↻</button>
      </div>
    </header>

    <nav class="view-tabs" id="viewTabs" aria-label="Views">
      <a href="?view=overview" data-view-link="overview" data-i18n="viewOverview">Overview</a>
      <a href="?view=system" data-view-link="system" data-i18n="viewSystem">System</a>
      <a href="?view=network" data-view-link="network" data-i18n="viewNetwork">Network</a>
      <a href="?view=hardware" data-view-link="hardware" data-i18n="viewHardware">Hardware</a>
      <a href="?view=processes" data-view-link="processes" data-i18n="viewProcesses">Processes</a>
    </nav>
    <div id="errorBanner" class="error-banner" role="alert"></div>
    <div class="system-head">
      <div><span data-i18n="host">Host</span>: <strong id="hostName">—</strong> · <span id="osSummary">—</span></div>
      <div><span data-i18n="updated">Updated</span>: <span id="updated">—</span></div>
    </div>

    <section id="healthBanner" class="health-banner" aria-label="Health summary">
      <div class="health-main"><span id="healthDot" class="health-dot"></span><strong id="healthTitle">—</strong><span id="healthDescription" class="tiny"></span></div>
      <div id="healthReasons" class="health-reasons"></div>
      <div class="help-cluster"><button type="button" class="help-button" data-help="healthDisclaimer" aria-label="Help">?</button></div>
    </section>

    <section class="summary" aria-label="At a glance">
      <div class="metric">
        <div class="eyebrow" data-i18n="cpu">CPU usage</div>
        <div class="metric-value-row"><div class="big" id="cpuValue">—</div></div>
        <div class="progress"><i id="cpuBar"></i></div>
        <div class="tiny" id="cpuExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="memory">Memory</div>
        <div class="metric-value-row"><div class="big" id="ramValue">—</div></div>
        <div class="progress"><i id="ramBar"></i></div>
        <div class="tiny" id="ramExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="swap">Swap</div>
        <div class="metric-value-row"><div class="big" id="swapValue">—</div></div>
        <div class="progress"><i id="swapBar"></i></div>
        <div class="tiny" id="swapExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="disk">Disk</div>
        <div class="metric-value-row"><div class="big" id="diskValue">—</div></div>
        <div class="progress"><i id="diskBar"></i></div>
        <div class="tiny" id="diskExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="uptime">Uptime</div>
        <div class="metric-value-row"><div class="big" id="uptimeValue">—</div></div>
        <div class="tiny" id="uptimeExtra">—</div>
      </div>
    </section>

    
    <main class="dashboard">
      <div class="column">
        <section class="panel" id="panel-activity" data-panel="activity">
          <h2><span class="icon" aria-hidden="true">▥</span><span data-i18n="activity">Live activity</span></h2>
          <div class="charts">
            <div class="chart-card" data-chart-card="cpu">
              <div class="chart-title"><span class="chart-label" data-i18n="cpuGraph">CPU · last 3 min</span><button type="button" class="chart-expand" data-chart="cpu" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <div class="chart-stats" id="cpuStats"></div><div class="chart-box"><svg id="cpuChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
            </div>
            <div class="chart-card" data-chart-card="ram">
              <div class="chart-title"><span class="chart-label" data-i18n="memoryGraph">RAM · last 3 min</span><button type="button" class="chart-expand" data-chart="ram" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <div class="chart-stats" id="ramStats"></div><div class="chart-box"><svg id="ramChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
            </div>
            <div class="chart-card" data-chart-card="swap">
              <div class="chart-title"><span class="chart-label" data-i18n="swapGraph">Swap · last 3 min</span><button type="button" class="chart-expand" data-chart="swap" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <div class="chart-stats" id="swapStats"></div><div class="chart-box"><svg id="swapChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
            </div>
            <div class="chart-card" data-chart-card="net">
              <div class="chart-title"><span data-i18n="networkGraph">Network traffic</span><span class="legend"><span><i></i><span data-i18n="rx">Rx</span></span><span><i class="second"></i><span data-i18n="tx">Tx</span></span></span><button type="button" class="chart-expand" data-chart="net" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <div class="chart-stats" id="netStats"></div><div class="chart-box"><svg id="netChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
            </div>
            <div class="chart-card" data-chart-card="io">
              <div class="chart-title"><span data-i18n="diskGraph">Disk I/O</span><span class="legend"><span><i></i><span data-i18n="read">Read</span></span><span><i class="second"></i><span data-i18n="write">Write</span></span></span><button type="button" class="chart-expand" data-chart="io" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <div class="chart-stats" id="ioStats"></div><div class="chart-box"><svg id="ioChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
            </div>
          </div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="historyNote" aria-label="Help">?</button></div>
          <details class="details" id="coresDetails">
            <summary><span data-i18n="perCore">CPU usage per core</span> <span id="coreCount"></span></summary>
            <div id="coreList" class="core-grid"></div>
          </details>
        </section>

        <section class="panel" id="panel-processes" data-panel="processes">
          <h2><span class="icon" aria-hidden="true">☷</span><span data-i18n="processes">Top processes</span><a class="panel-action" href="?view=processes" data-view-link="processes"><span data-i18n="showTop20">Show top 20</span><span aria-hidden="true">→</span></a></h2>
          <div class="process-columns">
            <div class="process-group">
              <h3 data-i18n="topCpu">Top 5 CPU</h3>
              <div id="processCpuList"></div>
            </div>
            <div class="process-group">
              <h3 data-i18n="topRam">Top 5 RAM</h3>
              <div id="processRamList"></div>
            </div>
            <div class="process-group process-swap-group">
              <h3 data-i18n="topSwap">Top 5 Swap</h3>
              <div id="processSwapList"></div>
            </div>
          </div>
          <div class="help-cluster" id="processHelpCluster">
            <button type="button" class="help-button" data-help="processNote,ramFormula,pssExplanation,swapProcessExplanation" aria-label="Help">?</button>
            <button type="button" class="help-button" id="collaboraNote" data-help="collaboraExplanation" aria-label="Help" hidden>?</button>
          </div>
        </section>

        <section class="panel" id="panel-storage" data-panel="storage">
          <h2><span class="icon" aria-hidden="true">▤</span><span data-i18n="storage">Storage</span></h2>
          <div id="disksList" class="meter-list"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="mergedMountNote" aria-label="Help">?</button></div>
          <div class="hr"></div>
          <h2><span class="icon" aria-hidden="true">⇣</span><span data-i18n="diskIo">Disk activity</span></h2>
          <div id="diskIoList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="diskIoNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-checks" data-panel="checks">
          <h2><span class="icon" aria-hidden="true">✓</span><span data-i18n="checksPanel">Services status</span><a class="panel-action" href="?view=network" data-view-link="network"><span data-i18n="details">Details</span><span aria-hidden="true">→</span></a></h2>
          <div id="checksList"></div>
        </section>

        <section class="panel" id="panel-failed" data-panel="failed">
          <h2><span class="icon" aria-hidden="true">⚠</span><span data-i18n="failedUnits">Failed services (systemd)</span></h2>
          <div id="failedList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="failedNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-connections" data-panel="connections">
          <h2><span class="icon" aria-hidden="true">⇄</span><span data-i18n="connectionsPanel">Current connections (TCP)</span></h2>
          <div id="connectionsList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="connNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-webtraffic" data-panel="webtraffic">
          <h2><span class="icon" aria-hidden="true">◔</span><span data-i18n="webPanel">Recent web traffic</span></h2>
          <div id="webTrafficList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="webNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-apache" data-panel="apache">
          <h2><span class="icon" aria-hidden="true">▶</span><span data-i18n="apachePanel">Apache, right now</span></h2>
          <div id="apacheList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="apacheNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-ports" data-panel="ports">
          <h2><span class="icon" aria-hidden="true">⇵</span><span data-i18n="listeningPorts">Listening ports (TCP)</span></h2>
          <div id="portsList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="portsNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-services" data-panel="services">
          <h2><span class="icon" aria-hidden="true">◉</span><span data-i18n="services">Services</span></h2>
          <div id="servicesList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="tcpNote" aria-label="Help">?</button></div>
        </section>
      </div>

      <div class="column">
        <section class="panel" id="panel-system" data-panel="system">
          <h2><span class="icon" aria-hidden="true">⌘</span><span data-i18n="system">System</span></h2>
          <div class="rows" id="systemRows"></div>
        </section>

        <section class="panel" id="panel-php" data-panel="php">
          <h2><span class="icon" aria-hidden="true">⚙</span><span data-i18n="phpPanel">PHP</span></h2>
          <div class="rows" id="phpRows"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="phpNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-network" data-panel="network">
          <h2><span class="icon" aria-hidden="true">⇄</span><span data-i18n="network">Network</span></h2>
          <div id="networkMain"></div>
          <details id="networkSecondary" class="details">
            <summary><span data-i18n="secondaryInterfaces">Virtual and secondary interfaces</span> <span id="secondaryCount"></span></summary>
            <div id="networkSecondaryList"></div>
          </details>
          <div class="help-cluster"><button type="button" class="help-button" data-help="networkNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-http" data-panel="http">
          <h2><span class="icon" aria-hidden="true">♧</span><span data-i18n="httpChecks">HTTP/HTTPS & certificates</span></h2>
          <div id="httpList"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="httpChecksNote" aria-label="Help">?</button></div>
        </section>

        <section class="panel" id="panel-hardware" data-panel="hardware">
          <h2><span class="icon" aria-hidden="true">◷</span><span data-i18n="hardware">Hardware & sensors</span></h2>
          <div class="rows" id="hardwareList"></div>
        </section>

        <section class="panel" id="panel-pressure" data-panel="pressure">
          <h2><span class="icon" aria-hidden="true">≋</span><span data-i18n="pressure">System pressure (PSI)</span></h2>
          <div id="pressureList" class="pressure-grid"></div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="pressureNote" aria-label="Help">?</button></div>
        </section>
      </div>
    </main>

    <div id="panelStore" hidden></div>
    <main class="process-view" id="processView" aria-labelledby="detailTitle">
      <div class="process-view-head"><h2 id="detailTitle" data-i18n="detailTitle">Top 20 processes</h2><span class="tiny" id="detailNote"></span></div>
      <div class="detail-columns">
        <section class="panel" id="detail-cpu">
          <h2><span class="icon" aria-hidden="true">◉</span><span data-i18n="top20Cpu">Top 20 · CPU</span></h2>
          <ol class="detail-list" id="detailCpuList"></ol>
        </section>
        <section class="panel" id="detail-ram">
          <h2><span class="icon" aria-hidden="true">▥</span><span data-i18n="top20Ram">Top 20 · RAM</span></h2>
          <ol class="detail-list" id="detailRamList"></ol>
        </section>
        <section class="panel" id="detail-swap">
          <h2><span class="icon" aria-hidden="true">⇄</span><span data-i18n="top20Swap">Top 20 · Swap</span></h2>
          <ol class="detail-list" id="detailSwapList"></ol>
        </section>
      </div>
      <div class="help-cluster" id="detailHelpCluster"><button type="button" class="help-button" data-help="processNote,ramFormula,pssExplanation,swapProcessExplanation" aria-label="Help">?</button></div>
    </main>
    <div id="helpPopover" class="help-popover" role="tooltip" hidden></div>
    <div id="chartTooltip" class="chart-tooltip" role="status" hidden></div>
    <dialog class="dialog" id="settingsDialog" aria-labelledby="settingsTitle">
      <div class="dialog-head"><h2 id="settingsTitle" data-i18n="settingsTitle">Customize dashboard</h2><button type="button" class="control" id="closeSettings" aria-label="Close">×</button></div>
      <div class="settings-grid">
        <label class="settings-field"><span data-i18n="refreshEvery">Refresh interval</span>
          <select id="refreshInterval" class="control"><option value="2">2 s</option><option value="3">3 s</option><option value="5">5 s</option><option value="10">10 s</option><option value="30">30 s</option><option value="60">60 s</option></select></label>
        <label class="settings-field"><span data-i18n="graphPeriod">Graph period</span>
          <select id="graphPeriod" class="control"><option value="1">1 min</option><option value="3">3 min</option><option value="10">10 min</option></select></label>
        <label class="settings-field"><span data-i18n="warnCpu">CPU warning threshold (%)</span><input class="control" type="number" id="warnCpu" min="50" max="95" step="1"></label>
        <label class="settings-field"><span data-i18n="warnRam">Memory warning threshold (%)</span><input class="control" type="number" id="warnRam" min="50" max="95" step="1"></label>
        <label class="settings-field"><span data-i18n="warnDisk">Disk warning threshold (%)</span><input class="control" type="number" id="warnDisk" min="50" max="95" step="1"></label>
      </div>
      <h3 data-i18n="visibleCharts">Visible charts</h3><div id="chartToggles" class="settings-checks"></div>
      <h3 data-i18n="visiblePanels">Panels: visibility and order</h3><div class="help-cluster"><button type="button" class="help-button" data-help="orderNote" aria-label="Help">?</button></div>
      <div id="panelToggles" class="settings-panels"></div>
      <h3 data-i18n="footerSetting">Footer</h3>
      <div class="settings-checks"><label><input type="checkbox" id="showFooter"><span data-i18n="showFooter">Show the source code and support links</span></label></div>
      <div class="dialog-actions"><button type="button" class="control" id="resetSettings" data-i18n="resetSettings">Reset preferences</button><button type="button" class="control primary" id="doneSettings" data-i18n="done">Done</button></div>
    </dialog>
    <dialog class="dialog zoom-dialog" id="chartDialog" aria-labelledby="zoomTitle">
      <div class="dialog-head"><h2 id="zoomTitle">—</h2><button type="button" class="control" id="closeChart" aria-label="Close">×</button></div>
      <div class="chart-stats" id="zoomStats"></div><div class="chart-box"><svg id="zoomChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg></div><div class="chart-axis" aria-hidden="true"></div>
      <div class="help-cluster"><button type="button" class="help-button" data-help="historyNote" aria-label="Help">?</button></div>
    </dialog>

    <footer class="foot">Monitor made Simple <?= ESM_VERSION ?> · PHP <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?> · <span data-i18n="footer">One file. No dependencies. Read-only monitoring.</span></footer>
    <footer class="site-footer" id="siteFooter" aria-label="Source code and support">
      <span class="footer-text" data-i18n="footerSource">Source code and support:</span>
      <a href="https://github.com/Fabrice-breizh" target="_blank" rel="noopener noreferrer">GitHub</a>
      <span class="footer-sep" aria-hidden="true">·</span>
      <a class="footer-support" href="https://www.buymeacoffee.com/fabricebreizh" target="_blank" rel="noopener noreferrer" aria-label="Buy me some tokens">
        <svg class="footer-cup" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 5h10v6a5 5 0 0 1-10 0V5Z"/><path d="M15 7h2a3 3 0 0 1 0 6h-2"/><path d="M4 19h13"/><path d="M7 22h7"/></svg><span data-i18n="footerBuyMe">Buy me</span> <span class="footer-strike" data-i18n="footerCoffee">a coffee</span> <strong data-i18n="footerTokens">some tokens</strong><svg class="footer-cup" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 5h10v6a5 5 0 0 1-10 0V5Z"/><path d="M15 7h2a3 3 0 0 1 0 6h-2"/><path d="M4 19h13"/><path d="M7 22h7"/></svg>
      </a>
    </footer>
  </div>
  <script nonce="<?= $nonce ?>">
'use strict';
// =============================================================
// 17. JAVASCRIPT AND I18N
// =============================================================
const words = {
  en: {
    "connectionsPanel": "Current connections (TCP)",
    "connIncoming": "Incoming",
    "connOutgoing": "Outgoing",
    "connLocal": "Internal (inside this server)",
    "addressCount": "{n} IP",
    "connByService": "Incoming, by service",
    "connNone": "No incoming connection right now.",
    "connOutgoingList": "Outgoing destinations",
    "sessionsTitle": "Logged-in users (SSH, console)",
    "sessionsNone": "Nobody is logged in.",
    "agoText": "{s} ago",
    "connNote": "Connections open at this instant, read from the kernel (nothing is scanned). An address is not a person: several people can share one, and many are robots. For outgoing connections, the program that opened them is not visible without root access. Traffic that goes straight to a container may not appear.",
    "webPanel": "Recent web traffic",
    "webRequests": "Requests ({m} min)",
    "webVisitors": "Browsers and apps (addresses)",
    "webBots": "Robots and scripts (addresses)",
    "webResponses": "Responses",
    "webSent": "Data sent",
    "webPerMinute": "Requests per minute",
    "nowWord": "now",
    "webTopClients": "Most active addresses",
    "webTopPages": "Most requested pages",
    "webTopErrors": "Requests in error",
    "errorCount": "errors: {n}",
    "botTag": "robot",
    "webNone": "No request in this period.",
    "webPartial": "Very busy server: only the last {s} could be read.",
    "webUnreadable": "The access log cannot be read by the web server's user ({user}). This panel stays empty until you allow it.", "webAclWarning": "Before you run this command: it lets {user} read the access logs, so every website and PHP application on this server could read them too (visitor addresses, pages requested). After the next log rotation, the new files of the folder, error log included, become readable as well. Needs the \"acl\" package. Your own access to the folder does not change.", "webAclUndo": "To undo it and return to the original permissions:",
    "webMissing": "No access log found. Set ESM_ACCESS_LOGS at the top of the file.",
    "webNote": "Read from the web server's access log; nothing is stored. Requests for this dashboard and requests coming from the server itself are left out. Robots are recognised by the name they announce, so some go unnoticed. The part of the address after \"?\" is hidden: it can contain secrets.",
    "apachePanel": "Apache, right now",
    "apacheRate": "Requests per second",
    "apacheWorkers": "Workers (busy / total)",
    "apacheKeepalive": "Idle connections kept open",
    "apacheUptime": "Running for",
    "apacheInFlight": "Requests being served",
    "apacheIdle": "No request is being served at this instant.",
    "apacheNotExtended": "Details per request need \"ExtendedStatus On\" in Apache's configuration.",
    "apacheOff": "Apache's status page is not reachable ({detail}). To enable it:",
    "apacheDisabled": "Disabled in the configuration.",
    "apacheNote": "From Apache's status page (mod_status), requested from this machine only. The duration is the time since the request started: a long one can be a download, a video stream, or a page that is stuck. Requests per second include those of this dashboard.",
    "alertInsecure": "No HTTPS: the password travels unencrypted",
    "alertNoCache": "Temporary folder not writable: caches and per-process CPU are disabled",
    "alertLoad": "High load: {load} for {cores} cores",
    "alertOom": "A process was killed for lack of memory in the last hour",
    "alertFiles": "Open files close to the system limit",
    "alertConntrack": "Connection tracking table almost full",
    "alertRaidDegraded": "RAID array degraded",
    "alertRaidSync": "RAID array rebuilding",
    "alertFpmQueue": "PHP-FPM: requests waiting for a free worker",
    "alertFpmMax": "PHP-FPM reached its process limit in the last hour",
    "alertOpcacheFull": "OPcache memory is full",
    "alertPortAll": "{service} (port {port}) is listening on all interfaces",
    "alertPortPublic": "{service} (port {port}) is listening on the public address {address}",
    "alertTls": "{name}: certificate expires in {days} d",
    "alertTlsExpired": "{name}: certificate has expired",
    "styleAuto": "Auto",
    "tlsExpired": "Certificate expired on",
    "lastDataAgo": "Last data received {s} ago.",
    "showAllAlerts": "Show all alerts",
    "phpPanel": "PHP",
    "phpSapi": "Server interface",
    "memoryLimit": "Memory limit per request",
    "fpmPool": "PHP-FPM pool",
    "fpmWorkers": "Workers (busy / total)",
    "fpmQueue": "Requests waiting",
    "fpmMaxReached": "Process limit reached",
    "fpmSlow": "Slow requests",
    "opcacheMemory": "OPcache memory",
    "opcacheHitRate": "OPcache hit rate",
    "opcacheScripts": "Cached scripts",
    "disabledState": "Disabled",
    "phpNote": "PHP-FPM figures are those of the pool that serves this page. \"Process limit reached\" counts how many times pm.max_children was hit since PHP-FPM started: if it keeps growing, requests are queuing.",
    "openFiles": "Open files",
    "conntrack": "Tracked connections",
    "oomKills": "Processes killed for lack of memory (since boot)",
    "raidHealthy": "healthy",
    "raidDegraded": "degraded",
    "raidRebuilding": "rebuilding",
    "raidChecking": "checking",
    "contextHelp": "Help",
    "maxValue": "Peak",
    "selfCheck": "This monitor (local probe)",
    "selfCheckExplanation": "Local probe with fixed IP. The TLS name is inferred from SERVER_NAME (or explicitly configured). Public TLS may require a separate HTTPS check.",
    "selfCheckNeedsConfig": "Local HTTP probe failed: check the local port and virtual host configuration.",
    "selfProbeMismatch": "The local endpoint did not return the expected monitor header.",
    "httpPending": "Pending",
    "lastCheck": "Last checked",
    "staleResult": "stale result",
    "processPss": "PSS",
    "processPartial": "Process list sampled (limit reached); CPU = 100% for one logical core.",
    "apiDuration": "API collection time",
    "processes": "Top processes",
    "topCpu": "Top 5 · CPU",
    "topRam": "Top 5 · RAM",
    "topSwap": "Top 5 · Swap",
    "swapProcessExplanation": "Swap by process is based on VmSwap in /proc/PID/status. Only processes readable by PHP are included; swap occupancy is not the same as swap I/O.",
    "interfaceStyle": "Interface style",
    "changeStyle": "Change interface style",
    "noSwapProcess": "No process with measurable Swap usage.",
    "processNote": "CPU is calculated between samples (100% = one logical core). Only processes visible to PHP are shown.",
    "ramFormula": "RAM used = MemTotal − MemAvailable. The Top 5 is not a breakdown of all RAM.",
    "pssExplanation": "Top RAM is ranked by RSS. Displayed PSS, when accessible, shares common memory proportionally between processes.",
    "collaboraExplanation": "forkit and kit_spare_* are usually Collabora Online / LibreOffice workers kept ready to open documents.",
    "noProcess": "No accessible processes.",
    "httpChecks": "HTTP/HTTPS & certificates",
    "httpChecksNote": "This dashboard is checked locally by default. Additional configured hosts are probed with TLS certificate validation.",
    "noHttpChecks": "No HTTP checks configured. Add targets in ESM_HTTP_CHECKS at the top of monitor.php.",
    "httpFailure": "HTTP error",
    "tlsExpires": "Certificate expires in",
    "tlsUnavailable": "TLS certificate: unavailable",
    "connectionFailed": "Connection or TLS handshake failed",
    "invalidResponse": "Invalid HTTP response",
    "settingsTitle": "Customize dashboard",
    "close": "Close",
    "expandChart": "Expand graph",
    "refreshEvery": "Refresh interval",
    "graphPeriod": "Graph period",
    "warnCpu": "CPU warning threshold (%)",
    "warnRam": "RAM warning threshold (%)",
    "warnDisk": "Disk warning threshold (%)",
    "visibleCharts": "Visible charts",
    "visiblePanels": "Panels: visibility and order",
    "orderNote": "Reorder the two groups below. On wide screens, panels automatically spread over 3 or 4 columns.",
    "leftColumn": "Group A",
    "rightColumn": "Group B",
    "moveUp": "Move up",
    "moveDown": "Move down",
    "resetSettings": "Reset preferences",
    "threshold": "Threshold",
    "axisNow": "now",
    "connectionRefused": "Connection refused (nothing is listening on this port)",
    "httpTimeout": "No answer in time (timeout)",
    "tlsCertificateError": "TLS certificate rejected (expired, self-signed or wrong name)",
    "viewOverview": "Overview",
    "viewSystem": "System",
    "viewNetwork": "Network",
    "viewHardware": "Hardware",
    "viewProcesses": "Processes",
    "showTop20": "Show top 20",
    "details": "Details",
    "checksPanel": "Services status",
    "noChecks": "No service check configured.",
    "failedUnits": "Failed services (systemd)",
    "noFailedUnits": "No failed service.",
    "systemdUnavailable": "Unavailable: systemctl is missing or not allowed for the web server user.",
    "failedNote": "Units that systemd reports as failed. Check them with: systemctl status <unit>. Refreshed every minute.",
    "listeningPorts": "Listening ports (TCP)",
    "noPorts": "No listening port found.",
    "portScopeAll": "All interfaces",
    "portScopeLocal": "Local only",
    "portSensitive": "database or API",
    "portsNote": "TCP ports open on this server. \"All interfaces\" means reachable from the network, unless a firewall blocks it. \"Local only\" means reachable from this machine only. Process names would require root access.",
    "rebootRequired": "Restart required",
    "rebootNo": "No",
    "rebootKernel": "kernel {k} installed, {r} running",
    "rebootPackages": "updated packages",
    "healthReboot": "Restart required",
    "healthFailedUnits": "Failed services",
    "yes": "Yes",
    "styleNight": "Night",
    "styleDim": "Dusk",
    "styleLight": "Light",
    "physicalCores": "Physical cores",
    "tempCpu": "CPU temperature",
    "tempDisk": "Disk temperature",
    "tempBoard": "Motherboard temperature",
    "tempChipset": "Chipset temperature",
    "tempWifi": "Wi-Fi temperature",
    "gpu": "Graphics card",
    "gpuUsage": "GPU usage",
    "gpuMemory": "Video memory",
    "gpuTemp": "GPU temperature",
    "gpuPower": "GPU power",
    "gpuClock": "GPU clock",
    "detailTitle": "Top 20 processes",
    "top20Cpu": "Top 20 · CPU",
    "top20Ram": "Top 20 · RAM",
    "top20Swap": "Top 20 · Swap",
    "detailNote": "Refreshed every {s} s, from the same sample as the dashboard.",
    "footerSetting": "Footer",
    "showFooter": "Show the source code and support links",
    "footerSource": "Source code and support:",
    "footerBuyMe": "Buy me",
    "footerCoffee": "a coffee",
    "footerTokens": "some tokens",
    "done": "Done",
    "healthDisclaimer": "Heuristic based on accessible metrics and configured checks; not a complete diagnosis.",
    "healthy": "Normal",
    "healthWarn": "Attention",
    "healthCritical": "Critical",
    "healthNeedsAttention": "At least one threshold or check requires attention.",
    "healthAllClear": "No active warnings among the monitored indicators.",
    "swapIdle": "Swap is occupied but no current swap I/O was detected.",
    "inodes": "Inodes",
    "diskBusy": "Disk busy",
    "linkSpeed": "Link",
    "networkErrorRate": "Errors/s",
    "networkErrors": "New network errors or drops",
    "fullStall": "Full stall",
    "tagline": "A lightweight Linux dashboard",
    "connecting": "Connecting…",
    "online": "Live",
    "offline": "Disconnected",
    "host": "Host",
    "updated": "Updated",
    "cpu": "CPU usage",
    "memory": "Memory",
    "disk": "Disk",
    "uptime": "Uptime",
    "activity": "Live activity",
    "cpuGraph": "CPU · last 3 min",
    "memoryGraph": "RAM · last 3 min",
    "historyNote": "Charts are stored in this tab only.",
    "system": "System",
    "storage": "Storage",
    "network": "Network",
    "services": "Services",
    "hardware": "Hardware & sensors",
    "footer": "One file. No dependencies. Read-only monitoring.",
    "os": "Operating system",
    "kernel": "Kernel",
    "architecture": "Architecture",
    "cpuModel": "Processor",
    "cores": "Logical cores",
    "load": "Load average",
    "php": "PHP",
    "swap": "Swap",
    "used": "used",
    "free": "free",
    "unknown": "Unavailable",
    "none": "No data",
    "onlineService": "Online",
    "offlineService": "Offline",
    "rx": "Receive",
    "tx": "Send",
    "refreshError": "Unable to fetch server metrics.",
    "seconds": "sec",
    "days": "d",
    "hours": "h",
    "minutes": "min",
    "temperature": "Temperature",
    "refresh": "Refresh",
    "language": "Language",
    "swapGraph": "Swap · last 3 min",
    "networkGraph": "Network traffic",
    "diskGraph": "Disk I/O",
    "perCore": "CPU usage per core",
    "read": "Read",
    "write": "Write",
    "diskIo": "Disk activity",
    "diskIoNote": "Throughput is based on successive samples. Layered devices are not counted twice.",
    "mergedMountNote": "Equivalent mount points are grouped together.",
    "extraMounts": "Other mount points",
    "swapActivity": "Swap activity",
    "swapIn": "Swap in",
    "swapOut": "Swap out",
    "pagesPerSecond": "pages/s",
    "swapDisabled": "Not configured",
    "cached": "Cached memory",
    "physical": "Physical",
    "vpn": "VPN",
    "virtual": "Virtual",
    "loopback": "Loopback",
    "secondaryInterfaces": "Virtual and secondary interfaces",
    "networkNote": "For VPNs, “Enabled” means the interface is switched on, not that a peer has completed a handshake.",
    "rxErrors": "Receive errors",
    "txErrors": "Transmit errors",
    "dropped": "Dropped",
    "pressure": "System pressure (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "Memory",
    "pressureIo": "I/O",
    "pressureNote": "Share of time tasks waited for resources, average over 10 seconds (PSI).",
    "tcpNote": "TCP connection checks, not HTTP content checks.",
    "estimating": "Calculating…",
    "enabledState": "Enabled",
    "upState": "Up",
    "downState": "Down",
    "unknownState": "Unknown",
    "dormantState": "Dormant",
    "lowerlayerdownState": "Lower layer down",
    "testingState": "Testing",
    "notpresentState": "Not present",
    "noDevices": "No compatible block devices detected.",
    "core": "Core",
    "available": "Available"
  },
  fr: {
    "connectionsPanel": "Connexions en cours (TCP)",
    "connIncoming": "Entrantes",
    "connOutgoing": "Sortantes",
    "connLocal": "Internes (dans ce serveur)",
    "addressCount": "{n} IP",
    "connByService": "Entrantes, par service",
    "connNone": "Aucune connexion entrante en ce moment.",
    "connOutgoingList": "Destinations sortantes",
    "sessionsTitle": "Utilisateurs connectés (SSH, console)",
    "sessionsNone": "Personne n'est connecté.",
    "agoText": "il y a {s}",
    "connNote": "Connexions ouvertes à cet instant, lues dans le noyau (rien n'est scanné). Une adresse n'est pas une personne : plusieurs personnes peuvent en partager une, et beaucoup sont des robots. Pour les connexions sortantes, le programme qui les a ouvertes n'est pas visible sans accès root. Le trafic qui va directement vers un conteneur peut ne pas apparaître.",
    "webPanel": "Trafic web récent",
    "webRequests": "Requêtes ({m} min)",
    "webVisitors": "Navigateurs et applications (adresses)",
    "webBots": "Robots et scripts (adresses)",
    "webResponses": "Réponses",
    "webSent": "Données envoyées",
    "webPerMinute": "Requêtes par minute",
    "nowWord": "maintenant",
    "webTopClients": "Adresses les plus actives",
    "webTopPages": "Pages les plus demandées",
    "webTopErrors": "Requêtes en erreur",
    "errorCount": "erreurs : {n}",
    "botTag": "robot",
    "webNone": "Aucune requête sur cette période.",
    "webPartial": "Serveur très sollicité : seules les {s} les plus récentes ont pu être lues.",
    "webUnreadable": "Le journal d'accès n'est pas lisible par l'utilisateur du serveur web ({user}). Ce panneau reste vide tant que vous ne l'autorisez pas.", "webAclWarning": "Avant de lancer cette commande : elle autorise {user} à lire les journaux d'accès, donc tous les sites et applications PHP de ce serveur pourront les lire aussi (adresses des visiteurs, pages demandées). Après la prochaine rotation des journaux, les nouveaux fichiers du dossier, journal d'erreurs compris, deviennent lisibles eux aussi. Nécessite le paquet « acl ». Votre propre accès au dossier ne change pas.", "webAclUndo": "Pour annuler et revenir aux droits d'origine :",
    "webMissing": "Aucun journal d'accès trouvé. Renseignez ESM_ACCESS_LOGS en haut du fichier.",
    "webNote": "Lu dans le journal d'accès du serveur web ; rien n'est conservé. Les requêtes vers ce tableau de bord et celles qui viennent du serveur lui-même sont exclues. Les robots sont reconnus au nom qu'ils annoncent : certains passent donc inaperçus. La partie de l'adresse après « ? » est masquée, car elle peut contenir des secrets.",
    "apachePanel": "Apache, en ce moment",
    "apacheRate": "Requêtes par seconde",
    "apacheWorkers": "Processus (occupés / total)",
    "apacheKeepalive": "Connexions inactives gardées ouvertes",
    "apacheUptime": "En service depuis",
    "apacheInFlight": "Requêtes en cours de traitement",
    "apacheIdle": "Aucune requête en cours à cet instant.",
    "apacheNotExtended": "Le détail par requête nécessite « ExtendedStatus On » dans la configuration d'Apache.",
    "apacheOff": "La page d'état d'Apache n'est pas joignable ({detail}). Pour l'activer :",
    "apacheDisabled": "Désactivé dans la configuration.",
    "apacheNote": "Issu de la page d'état d'Apache (mod_status), demandée depuis cette machine uniquement. La durée est le temps écoulé depuis le début de la requête : une longue durée peut être un téléchargement, un flux vidéo ou une page bloquée. Les requêtes par seconde comptent aussi celles de ce tableau de bord.",
    "alertInsecure": "Pas de HTTPS : le mot de passe circule en clair",
    "alertNoCache": "Dossier temporaire non accessible en écriture : caches et CPU par processus désactivés",
    "alertLoad": "Charge élevée : {load} pour {cores} cœurs",
    "alertOom": "Un processus a été arrêté par manque de mémoire depuis moins d'une heure",
    "alertFiles": "Fichiers ouverts proches de la limite du système",
    "alertConntrack": "Table de suivi des connexions presque pleine",
    "alertRaidDegraded": "Grappe RAID dégradée",
    "alertRaidSync": "Grappe RAID en reconstruction",
    "alertFpmQueue": "PHP-FPM : requêtes en attente d'un processus libre",
    "alertFpmMax": "PHP-FPM a atteint sa limite de processus depuis moins d'une heure",
    "alertOpcacheFull": "Mémoire OPcache pleine",
    "alertPortAll": "{service} (port {port}) en écoute sur toutes les interfaces",
    "alertPortPublic": "{service} (port {port}) en écoute sur l'adresse publique {address}",
    "alertTls": "{name} : le certificat expire dans {days} j",
    "alertTlsExpired": "{name} : certificat expiré",
    "styleAuto": "Auto",
    "tlsExpired": "Certificat expiré le",
    "lastDataAgo": "Dernières données reçues il y a {s}.",
    "showAllAlerts": "Afficher toutes les alertes",
    "phpSapi": "Interface serveur",
    "memoryLimit": "Limite mémoire par requête",
    "fpmPool": "Pool PHP-FPM",
    "fpmWorkers": "Processus (occupés / total)",
    "fpmQueue": "Requêtes en attente",
    "fpmMaxReached": "Limite de processus atteinte",
    "fpmSlow": "Requêtes lentes",
    "opcacheMemory": "Mémoire OPcache",
    "opcacheHitRate": "Taux de réussite OPcache",
    "opcacheScripts": "Scripts en cache",
    "disabledState": "Désactivé",
    "phpNote": "Les chiffres PHP-FPM sont ceux du pool qui sert cette page. « Limite de processus atteinte » compte le nombre de fois où pm.max_children a été atteint depuis le démarrage de PHP-FPM : s'il augmente, des requêtes font la queue.",
    "openFiles": "Fichiers ouverts",
    "conntrack": "Connexions suivies",
    "oomKills": "Processus arrêtés par manque de mémoire (depuis le démarrage)",
    "raidHealthy": "sain",
    "raidDegraded": "dégradé",
    "raidRebuilding": "reconstruction",
    "raidChecking": "vérification",
    "contextHelp": "Aide",
    "maxValue": "Maximum",
    "selfCheck": "Ce moniteur (sonde locale)",
    "selfCheckExplanation": "Sonde à IP locale fixe. Le nom TLS vient de SERVER_NAME (ou de la configuration). Vérifiez le TLS public avec une cible HTTPS dédiée.",
    "selfCheckNeedsConfig": "Sonde locale inaccessible : vérifier le port et le virtual host.",
    "selfProbeMismatch": "La réponse locale ne comporte pas la signature du moniteur attendue.",
    "httpPending": "En attente",
    "lastCheck": "Dernier contrôle",
    "staleResult": "résultat ancien",
    "processPss": "PSS",
    "processPartial": "Processus échantillonnés (limite atteinte) ; 100 % CPU = un cœur logique.",
    "apiDuration": "Temps de collecte API",
    "processes": "Principaux processus",
    "topCpu": "Top 5 · CPU",
    "topRam": "Top 5 · RAM",
    "topSwap": "Top 5 · Swap",
    "swapProcessExplanation": "Le Swap par processus provient de VmSwap dans /proc/PID/status. Seuls les processus lisibles par PHP sont comptés ; occupation du Swap et activité d’échange sont différentes.",
    "interfaceStyle": "Style d’interface",
    "changeStyle": "Changer de style",
    "noSwapProcess": "Aucun processus avec du Swap mesurable.",
    "processNote": "CPU calculé entre deux mesures (100 % = un cœur logique). Seuls les processus visibles par PHP sont affichés.",
    "ramFormula": "RAM utilisée = MemTotal − MemAvailable. Le Top 5 ne représente pas toute la consommation mémoire.",
    "pssExplanation": "Classement RAM par RSS. La valeur PSS, si accessible, répartit équitablement la mémoire partagée entre processus.",
    "collaboraExplanation": "forkit et kit_spare_* sont généralement des processus Collabora Online / LibreOffice préchargés pour ouvrir rapidement des documents.",
    "noProcess": "Aucun processus accessible.",
    "httpChecks": "HTTP/HTTPS et certificats",
    "httpChecksNote": "Le moniteur est vérifié localement par défaut. Les hôtes ajoutés sont contrôlés avec validation des certificats TLS.",
    "noHttpChecks": "Aucun contrôle HTTP configuré. Ajoutez vos cibles dans ESM_HTTP_CHECKS, au début de monitor.php.",
    "httpFailure": "Erreur HTTP",
    "tlsExpires": "Expiration du certificat dans",
    "tlsUnavailable": "Certificat TLS : indisponible",
    "connectionFailed": "Échec de connexion ou de négociation TLS",
    "invalidResponse": "Réponse HTTP invalide",
    "settingsTitle": "Personnaliser le tableau de bord",
    "close": "Fermer",
    "expandChart": "Agrandir le graphique",
    "refreshEvery": "Actualisation",
    "graphPeriod": "Période des graphiques",
    "warnCpu": "Seuil d’alerte CPU (%)",
    "warnRam": "Seuil d’alerte RAM (%)",
    "warnDisk": "Seuil d’alerte disque (%)",
    "visibleCharts": "Graphiques visibles",
    "visiblePanels": "Panneaux : affichage et ordre",
    "orderNote": "Réorganisez les deux groupes. Sur grand écran, les panneaux se répartissent automatiquement sur 3 ou 4 colonnes.",
    "leftColumn": "Groupe A",
    "rightColumn": "Groupe B",
    "moveUp": "Monter",
    "moveDown": "Descendre",
    "resetSettings": "Réinitialiser les préférences",
    "threshold": "Seuil",
    "axisNow": "maintenant",
    "connectionRefused": "Connexion refusée (aucun service n'écoute sur ce port)",
    "httpTimeout": "Pas de réponse à temps (délai dépassé)",
    "tlsCertificateError": "Certificat TLS refusé (expiré, auto-signé ou nom incorrect)",
    "viewOverview": "Vue d'ensemble",
    "viewSystem": "Système",
    "viewNetwork": "Réseau",
    "viewHardware": "Matériel",
    "viewProcesses": "Processus",
    "showTop20": "Afficher le top 20",
    "details": "Détails",
    "checksPanel": "État des services",
    "noChecks": "Aucun test de service configuré.",
    "failedUnits": "Services en échec (systemd)",
    "noFailedUnits": "Aucun service en échec.",
    "systemdUnavailable": "Indisponible : systemctl est absent ou non autorisé pour l'utilisateur du serveur web.",
    "failedNote": "Unités que systemd signale en échec. Pour les examiner : systemctl status <unité>. Actualisé chaque minute.",
    "listeningPorts": "Ports en écoute (TCP)",
    "noPorts": "Aucun port en écoute trouvé.",
    "portScopeAll": "Toutes les interfaces",
    "portScopeLocal": "Local uniquement",
    "portSensitive": "base de données ou API",
    "portsNote": "Ports TCP ouverts sur ce serveur. « Toutes les interfaces » : joignable depuis le réseau, sauf si un pare-feu le bloque. « Local uniquement » : joignable depuis cette machine seulement. Le nom des processus nécessiterait les droits root.",
    "rebootRequired": "Redémarrage nécessaire",
    "rebootNo": "Non",
    "rebootKernel": "noyau {k} installé, {r} en cours",
    "rebootPackages": "paquets mis à jour",
    "healthReboot": "Redémarrage nécessaire",
    "healthFailedUnits": "Services en échec",
    "yes": "Oui",
    "styleNight": "Nuit",
    "styleDim": "Crépuscule",
    "styleLight": "Clair",
    "physicalCores": "Cœurs physiques",
    "tempCpu": "Température CPU",
    "tempDisk": "Température disque",
    "tempBoard": "Température carte mère",
    "tempChipset": "Température chipset",
    "tempWifi": "Température Wi-Fi",
    "gpu": "Carte graphique",
    "gpuUsage": "Utilisation GPU",
    "gpuMemory": "Mémoire vidéo",
    "gpuTemp": "Température GPU",
    "gpuPower": "Consommation GPU",
    "gpuClock": "Fréquence GPU",
    "detailTitle": "Top 20 des processus",
    "top20Cpu": "Top 20 · CPU",
    "top20Ram": "Top 20 · RAM",
    "top20Swap": "Top 20 · Swap",
    "detailNote": "Actualisé toutes les {s} s, à partir du même relevé que le tableau de bord.",
    "footerSetting": "Pied de page",
    "showFooter": "Afficher les liens vers le code source et le soutien",
    "footerSource": "Code source et support :",
    "footerBuyMe": "Offrez-moi",
    "footerCoffee": "un café",
    "footerTokens": "des tokens",
    "done": "Terminé",
    "healthDisclaimer": "Indicateur fondé sur les métriques accessibles et les contrôles configurés, sans prétendre à un diagnostic complet.",
    "healthy": "Normal",
    "healthWarn": "Attention",
    "healthCritical": "Critique",
    "healthNeedsAttention": "Au moins un seuil ou un contrôle requiert une vérification.",
    "healthAllClear": "Aucune alerte active parmi les indicateurs surveillés.",
    "swapIdle": "Swap occupé, mais aucune entrée/sortie Swap détectée actuellement.",
    "inodes": "Inodes",
    "diskBusy": "Occupation disque",
    "linkSpeed": "Lien",
    "networkErrorRate": "Erreurs/s",
    "networkErrors": "Nouvelles erreurs ou pertes réseau",
    "fullStall": "Blocage complet",
    "tagline": "Supervision Linux légère",
    "connecting": "Connexion…",
    "online": "En direct",
    "offline": "Déconnecté",
    "host": "Serveur",
    "updated": "Actualisé",
    "cpu": "Utilisation CPU",
    "memory": "Mémoire",
    "disk": "Disque",
    "uptime": "Disponibilité",
    "activity": "Activité en direct",
    "cpuGraph": "CPU · 3 dernières min",
    "memoryGraph": "RAM · 3 dernières min",
    "historyNote": "Les graphiques sont conservés uniquement dans cet onglet.",
    "system": "Système",
    "storage": "Stockage",
    "network": "Réseau",
    "services": "Services",
    "hardware": "Matériel et capteurs",
    "footer": "Un seul fichier. Sans dépendances. Supervision en lecture seule.",
    "os": "Système d’exploitation",
    "kernel": "Noyau",
    "architecture": "Architecture",
    "cpuModel": "Processeur",
    "cores": "Cœurs logiques",
    "load": "Charge système",
    "php": "PHP",
    "swap": "Swap",
    "used": "utilisé",
    "free": "libre",
    "unknown": "Indisponible",
    "none": "Aucune donnée",
    "onlineService": "En ligne",
    "offlineService": "Hors ligne",
    "rx": "Réception",
    "tx": "Envoi",
    "refreshError": "Impossible de récupérer les mesures du serveur.",
    "seconds": "s",
    "days": "j",
    "hours": "h",
    "minutes": "min",
    "temperature": "Température",
    "refresh": "Actualiser",
    "language": "Langue",
    "swapGraph": "Swap · 3 dernières min",
    "networkGraph": "Trafic réseau",
    "diskGraph": "E/S disque",
    "perCore": "Utilisation par cœur CPU",
    "read": "Lecture",
    "write": "Écriture",
    "diskIo": "Activité disque",
    "diskIoNote": "Débits calculés entre deux mesures. Les périphériques empilés ne sont pas comptés deux fois.",
    "mergedMountNote": "Les points de montage équivalents sont regroupés.",
    "extraMounts": "Autres points de montage",
    "swapActivity": "Activité du Swap",
    "swapIn": "Entrées Swap",
    "swapOut": "Sorties Swap",
    "pagesPerSecond": "pages/s",
    "swapDisabled": "Non configuré",
    "cached": "Mémoire en cache",
    "physical": "Physique",
    "vpn": "VPN",
    "virtual": "Virtuelle",
    "loopback": "Boucle locale",
    "secondaryInterfaces": "Interfaces virtuelles et secondaires",
    "networkNote": "Pour un VPN, « Activée » signifie interface administrativement active, pas tunnel connecté ou handshake confirmé.",
    "rxErrors": "Erreurs en réception",
    "txErrors": "Erreurs en émission",
    "dropped": "Paquets perdus",
    "pressure": "Pression système (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "Mémoire",
    "pressureIo": "E/S",
    "pressureNote": "Part du temps où des tâches attendent des ressources, moyenne sur 10 secondes (PSI).",
    "tcpNote": "Tests de connexion TCP, sans vérification du contenu HTTP.",
    "estimating": "Calcul…",
    "enabledState": "Activée",
    "upState": "Actif",
    "downState": "Inactif",
    "unknownState": "Indéterminé",
    "dormantState": "En veille",
    "lowerlayerdownState": "Couche inférieure inactive",
    "testingState": "En test",
    "notpresentState": "Absent",
    "noDevices": "Aucun périphérique bloc compatible détecté.",
    "core": "Cœur",
    "available": "Disponible"
  },
  es: {
    "connectionsPanel": "Conexiones actuales (TCP)",
    "connIncoming": "Entrantes",
    "connOutgoing": "Salientes",
    "connLocal": "Internas (dentro de este servidor)",
    "addressCount": "{n} IP",
    "connByService": "Entrantes, por servicio",
    "connNone": "Ninguna conexión entrante en este momento.",
    "connOutgoingList": "Destinos salientes",
    "sessionsTitle": "Usuarios conectados (SSH, consola)",
    "sessionsNone": "No hay nadie conectado.",
    "agoText": "hace {s}",
    "connNote": "Conexiones abiertas en este instante, leídas del núcleo (no se escanea nada). Una dirección no es una persona: varias personas pueden compartir una, y muchas son robots. En las conexiones salientes, el programa que las abrió no es visible sin acceso root. El tráfico que va directamente a un contenedor puede no aparecer.",
    "webPanel": "Tráfico web reciente",
    "webRequests": "Peticiones ({m} min)",
    "webVisitors": "Navegadores y aplicaciones (direcciones)",
    "webBots": "Robots y scripts (direcciones)",
    "webResponses": "Respuestas",
    "webSent": "Datos enviados",
    "webPerMinute": "Peticiones por minuto",
    "nowWord": "ahora",
    "webTopClients": "Direcciones más activas",
    "webTopPages": "Páginas más solicitadas",
    "webTopErrors": "Peticiones con error",
    "errorCount": "errores: {n}",
    "botTag": "robot",
    "webNone": "Ninguna petición en este periodo.",
    "webPartial": "Servidor muy ocupado: solo se han podido leer los últimos {s}.",
    "webUnreadable": "El usuario del servidor web ({user}) no puede leer el registro de accesos. Este panel permanece vacío hasta que lo autorice.", "webAclWarning": "Antes de ejecutar este comando: permite que {user} lea los registros de accesos, por lo que todos los sitios y aplicaciones PHP de este servidor también podrán leerlos (direcciones de los visitantes, páginas solicitadas). Tras la próxima rotación de registros, los archivos nuevos de la carpeta, incluido el registro de errores, también serán legibles. Requiere el paquete «acl». Su propio acceso a la carpeta no cambia.", "webAclUndo": "Para deshacerlo y volver a los permisos originales:",
    "webMissing": "No se encontró ningún registro de accesos. Configure ESM_ACCESS_LOGS al principio del archivo.",
    "webNote": "Leído del registro de accesos del servidor web; no se guarda nada. Se excluyen las peticiones a este panel y las que proceden del propio servidor. Los robots se reconocen por el nombre que anuncian, así que algunos pasan desapercibidos. La parte de la dirección después de «?» se oculta, porque puede contener secretos.",
    "apachePanel": "Apache, ahora mismo",
    "apacheRate": "Peticiones por segundo",
    "apacheWorkers": "Procesos (ocupados / total)",
    "apacheKeepalive": "Conexiones inactivas mantenidas abiertas",
    "apacheUptime": "En servicio desde hace",
    "apacheInFlight": "Peticiones en curso",
    "apacheIdle": "Ninguna petición en curso en este instante.",
    "apacheNotExtended": "El detalle por petición requiere «ExtendedStatus On» en la configuración de Apache.",
    "apacheOff": "La página de estado de Apache no es accesible ({detail}). Para activarla:",
    "apacheDisabled": "Desactivado en la configuración.",
    "apacheNote": "Procede de la página de estado de Apache (mod_status), solicitada solo desde esta máquina. La duración es el tiempo transcurrido desde el inicio de la petición: una duración larga puede ser una descarga, un flujo de vídeo o una página bloqueada. Las peticiones por segundo incluyen las de este panel.",
    "alertInsecure": "Sin HTTPS: la contraseña viaja sin cifrar",
    "alertNoCache": "Carpeta temporal sin permiso de escritura: cachés y CPU por proceso desactivados",
    "alertLoad": "Carga alta: {load} para {cores} núcleos",
    "alertOom": "Un proceso fue detenido por falta de memoria en la última hora",
    "alertFiles": "Archivos abiertos cerca del límite del sistema",
    "alertConntrack": "Tabla de seguimiento de conexiones casi llena",
    "alertRaidDegraded": "Matriz RAID degradada",
    "alertRaidSync": "Matriz RAID en reconstrucción",
    "alertFpmQueue": "PHP-FPM: peticiones esperando un proceso libre",
    "alertFpmMax": "PHP-FPM alcanzó su límite de procesos en la última hora",
    "alertOpcacheFull": "Memoria de OPcache llena",
    "alertPortAll": "{service} (puerto {port}) en escucha en todas las interfaces",
    "alertPortPublic": "{service} (puerto {port}) en escucha en la dirección pública {address}",
    "alertTls": "{name}: el certificado caduca en {days} d",
    "alertTlsExpired": "{name}: certificado caducado",
    "styleAuto": "Automático",
    "tlsExpired": "Certificado caducado el",
    "lastDataAgo": "Últimos datos recibidos hace {s}.",
    "showAllAlerts": "Mostrar todas las alertas",
    "phpSapi": "Interfaz del servidor",
    "memoryLimit": "Límite de memoria por petición",
    "fpmPool": "Pool de PHP-FPM",
    "fpmWorkers": "Procesos (ocupados / total)",
    "fpmQueue": "Peticiones en espera",
    "fpmMaxReached": "Límite de procesos alcanzado",
    "fpmSlow": "Peticiones lentas",
    "opcacheMemory": "Memoria de OPcache",
    "opcacheHitRate": "Tasa de aciertos de OPcache",
    "opcacheScripts": "Scripts en caché",
    "disabledState": "Desactivado",
    "phpNote": "Las cifras de PHP-FPM son las del pool que sirve esta página. «Límite de procesos alcanzado» cuenta las veces que se llegó a pm.max_children desde que arrancó PHP-FPM: si aumenta, hay peticiones en cola.",
    "openFiles": "Archivos abiertos",
    "conntrack": "Conexiones rastreadas",
    "oomKills": "Procesos detenidos por falta de memoria (desde el arranque)",
    "raidHealthy": "correcto",
    "raidDegraded": "degradado",
    "raidRebuilding": "reconstruyendo",
    "raidChecking": "verificando",
    "contextHelp": "Ayuda",
    "maxValue": "Máximo",
    "selfCheck": "Este monitor (sonda local)",
    "selfCheckExplanation": "Sonda con IP local fija. El nombre TLS proviene de SERVER_NAME o la configuración. El TLS público puede necesitar otra comprobación HTTPS.",
    "selfCheckNeedsConfig": "Falla la sonda local: compruebe el puerto y el servidor virtual.",
    "selfProbeMismatch": "La respuesta local no contiene el encabezado del monitor esperado.",
    "httpPending": "Pendiente",
    "lastCheck": "Última comprobación",
    "staleResult": "resultado antiguo",
    "processPss": "PSS",
    "processPartial": "Lista de procesos muestreada (límite alcanzado); 100 % = un núcleo.",
    "apiDuration": "Tiempo de recopilación API",
    "processes": "Procesos principales",
    "topCpu": "Top 5 · CPU",
    "topRam": "Top 5 · RAM",
    "topSwap": "Top 5 · Swap",
    "swapProcessExplanation": "El Swap por proceso procede de VmSwap en /proc/PID/status. Solo se incluyen los procesos accesibles para PHP; ocupar Swap no implica actividad de intercambio.",
    "interfaceStyle": "Estilo de interfaz",
    "changeStyle": "Cambiar estilo",
    "noSwapProcess": "Ningún proceso con Swap medible.",
    "processNote": "CPU calculada entre muestras (100 % = un núcleo lógico). Solo se muestran procesos visibles para PHP.",
    "ramFormula": "RAM usada = MemTotal − MemAvailable. Los cinco procesos no explican todo el uso de memoria.",
    "pssExplanation": "La clasificación RAM usa RSS. El valor PSS, si está disponible, reparte la memoria compartida proporcionalmente.",
    "collaboraExplanation": "forkit y kit_spare_* suelen ser procesos precargados de Collabora Online / LibreOffice para abrir documentos rápidamente.",
    "noProcess": "No hay procesos accesibles.",
    "httpChecks": "HTTP/HTTPS y certificados",
    "httpChecksNote": "Este panel se comprueba localmente de forma automática. Los otros hosts se verifican con validación TLS.",
    "noHttpChecks": "No hay comprobaciones HTTP. Añade destinos a ESM_HTTP_CHECKS al principio de monitor.php.",
    "httpFailure": "Error HTTP",
    "tlsExpires": "El certificado caduca en",
    "tlsUnavailable": "Certificado TLS: no disponible",
    "connectionFailed": "Fallo de conexión o negociación TLS",
    "invalidResponse": "Respuesta HTTP no válida",
    "settingsTitle": "Personalizar el panel",
    "close": "Cerrar",
    "expandChart": "Ampliar gráfico",
    "refreshEvery": "Intervalo de actualización",
    "graphPeriod": "Período de gráficos",
    "warnCpu": "Umbral de alerta CPU (%)",
    "warnRam": "Umbral de alerta RAM (%)",
    "warnDisk": "Umbral de alerta disco (%)",
    "visibleCharts": "Gráficos visibles",
    "visiblePanels": "Paneles: visibilidad y orden",
    "orderNote": "Reordena ambos grupos. En pantallas amplias, los paneles se distribuyen en 3 o 4 columnas.",
    "leftColumn": "Grupo A",
    "rightColumn": "Grupo B",
    "moveUp": "Subir",
    "moveDown": "Bajar",
    "resetSettings": "Restablecer preferencias",
    "threshold": "Umbral",
    "axisNow": "ahora",
    "connectionRefused": "Conexión rechazada (ningún servicio escucha en este puerto)",
    "httpTimeout": "Sin respuesta a tiempo (tiempo de espera agotado)",
    "tlsCertificateError": "Certificado TLS rechazado (caducado, autofirmado o nombre incorrecto)",
    "viewOverview": "Resumen",
    "viewSystem": "Sistema",
    "viewNetwork": "Red",
    "viewHardware": "Hardware",
    "viewProcesses": "Procesos",
    "showTop20": "Ver el top 20",
    "details": "Detalles",
    "checksPanel": "Estado de los servicios",
    "noChecks": "No hay comprobaciones de servicio configuradas.",
    "failedUnits": "Servicios con error (systemd)",
    "noFailedUnits": "Ningún servicio con error.",
    "systemdUnavailable": "No disponible: systemctl no existe o no está permitido para el usuario del servidor web.",
    "failedNote": "Unidades que systemd marca como fallidas. Para revisarlas: systemctl status <unidad>. Se actualiza cada minuto.",
    "listeningPorts": "Puertos en escucha (TCP)",
    "noPorts": "No se encontró ningún puerto en escucha.",
    "portScopeAll": "Todas las interfaces",
    "portScopeLocal": "Solo local",
    "portSensitive": "base de datos o API",
    "portsNote": "Puertos TCP abiertos en este servidor. «Todas las interfaces»: accesible desde la red, salvo que un cortafuegos lo bloquee. «Solo local»: accesible solo desde esta máquina. Ver el nombre de los procesos requeriría acceso root.",
    "rebootRequired": "Reinicio necesario",
    "rebootNo": "No",
    "rebootKernel": "kernel {k} instalado, {r} en uso",
    "rebootPackages": "paquetes actualizados",
    "healthReboot": "Reinicio necesario",
    "healthFailedUnits": "Servicios con error",
    "yes": "Sí",
    "styleNight": "Noche",
    "styleDim": "Crepúsculo",
    "styleLight": "Claro",
    "physicalCores": "Núcleos físicos",
    "tempCpu": "Temperatura CPU",
    "tempDisk": "Temperatura del disco",
    "tempBoard": "Temperatura de la placa base",
    "tempChipset": "Temperatura del chipset",
    "tempWifi": "Temperatura Wi-Fi",
    "gpu": "Tarjeta gráfica",
    "gpuUsage": "Uso de GPU",
    "gpuMemory": "Memoria de vídeo",
    "gpuTemp": "Temperatura GPU",
    "gpuPower": "Consumo GPU",
    "gpuClock": "Frecuencia GPU",
    "detailTitle": "Top 20 de procesos",
    "top20Cpu": "Top 20 · CPU",
    "top20Ram": "Top 20 · RAM",
    "top20Swap": "Top 20 · Swap",
    "detailNote": "Actualizado cada {s} s, con la misma muestra que el panel.",
    "footerSetting": "Pie de página",
    "showFooter": "Mostrar los enlaces al código fuente y al apoyo",
    "footerSource": "Código fuente y soporte:",
    "footerBuyMe": "Invítame a",
    "footerCoffee": "un café",
    "footerTokens": "unos tokens",
    "done": "Listo",
    "healthDisclaimer": "Indicador aproximado basado en métricas accesibles y comprobaciones configuradas; no es un diagnóstico completo.",
    "healthy": "Normal",
    "healthWarn": "Atención",
    "healthCritical": "Crítico",
    "healthNeedsAttention": "Al menos un umbral o comprobación requiere atención.",
    "healthAllClear": "No hay alertas activas en los indicadores supervisados.",
    "swapIdle": "Swap ocupado, pero sin entradas o salidas de swap actualmente.",
    "inodes": "Inodos",
    "diskBusy": "Ocupación del disco",
    "linkSpeed": "Enlace",
    "networkErrorRate": "Errores/s",
    "networkErrors": "Nuevos errores o pérdidas de red",
    "fullStall": "Bloqueo completo",
    "tagline": "Monitor Linux ligero",
    "connecting": "Conectando…",
    "online": "En directo",
    "offline": "Desconectado",
    "host": "Servidor",
    "updated": "Actualizado",
    "cpu": "Uso de CPU",
    "memory": "Memoria",
    "disk": "Disco",
    "uptime": "Tiempo activo",
    "activity": "Actividad en directo",
    "cpuGraph": "CPU · últimos 3 min",
    "memoryGraph": "RAM · últimos 3 min",
    "historyNote": "Los gráficos se guardan solo en esta pestaña.",
    "system": "Sistema",
    "storage": "Almacenamiento",
    "network": "Red",
    "services": "Servicios",
    "hardware": "Hardware y sensores",
    "footer": "Un solo archivo. Sin dependencias. Supervisión de solo lectura.",
    "os": "Sistema operativo",
    "kernel": "Núcleo",
    "architecture": "Arquitectura",
    "cpuModel": "Procesador",
    "cores": "Núcleos lógicos",
    "load": "Carga media",
    "php": "PHP",
    "swap": "Swap",
    "used": "usado",
    "free": "libre",
    "unknown": "No disponible",
    "none": "Sin datos",
    "onlineService": "En línea",
    "offlineService": "Fuera de línea",
    "rx": "Recepción",
    "tx": "Envío",
    "refreshError": "No se pueden obtener métricas del servidor.",
    "seconds": "s",
    "days": "d",
    "hours": "h",
    "minutes": "min",
    "temperature": "Temperatura",
    "refresh": "Actualizar",
    "language": "Idioma",
    "swapGraph": "Swap · últimos 3 min",
    "networkGraph": "Tráfico de red",
    "diskGraph": "E/S de disco",
    "perCore": "Uso por núcleo CPU",
    "read": "Lectura",
    "write": "Escritura",
    "diskIo": "Actividad de disco",
    "diskIoNote": "Las tasas se calculan entre muestras. Los dispositivos superpuestos no se suman dos veces.",
    "mergedMountNote": "Se agrupan los puntos de montaje equivalentes.",
    "extraMounts": "Otros puntos de montaje",
    "swapActivity": "Actividad de swap",
    "swapIn": "Entradas swap",
    "swapOut": "Salidas swap",
    "pagesPerSecond": "páginas/s",
    "swapDisabled": "Sin configurar",
    "cached": "Memoria en caché",
    "physical": "Física",
    "vpn": "VPN",
    "virtual": "Virtual",
    "loopback": "Bucle local",
    "secondaryInterfaces": "Interfaces virtuales y secundarias",
    "networkNote": "Para VPN, « Activada » significa interfaz habilitada, no que el túnel haya establecido una conexión.",
    "rxErrors": "Errores de recepción",
    "txErrors": "Errores de envío",
    "dropped": "Paquetes descartados",
    "pressure": "Presión del sistema (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "Memoria",
    "pressureIo": "E/S",
    "pressureNote": "Porcentaje de tiempo que las tareas esperan recursos, media de 10 segundos (PSI).",
    "tcpNote": "Pruebas de conexión TCP, no de contenido HTTP.",
    "estimating": "Calculando…",
    "enabledState": "Activada",
    "upState": "Activo",
    "downState": "Inactivo",
    "unknownState": "Desconocido",
    "dormantState": "Inactivo temporalmente",
    "lowerlayerdownState": "Capa inferior inactiva",
    "testingState": "En prueba",
    "notpresentState": "Ausente",
    "noDevices": "No se detectaron dispositivos de bloque compatibles.",
    "core": "Núcleo",
    "available": "Disponible"
  },
  zh: {
    "connectionsPanel": "当前连接（TCP）",
    "connIncoming": "入站",
    "connOutgoing": "出站",
    "connLocal": "内部（本服务器内）",
    "addressCount": "{n} 个 IP",
    "connByService": "入站连接（按服务）",
    "connNone": "目前没有入站连接。",
    "connOutgoingList": "出站目标",
    "sessionsTitle": "已登录用户（SSH、控制台）",
    "sessionsNone": "没有用户登录。",
    "agoText": "{s} 前",
    "connNote": "此刻打开的连接，直接从内核读取（不进行任何扫描）。一个地址不等于一个人：多人可能共用一个地址，而且很多是机器人。对于出站连接，没有 root 权限就无法知道是哪个程序打开的。直接发往容器的流量可能不会显示。",
    "webPanel": "近期网站流量",
    "webRequests": "请求数（{m} 分钟）",
    "webVisitors": "浏览器和应用（地址）",
    "webBots": "机器人和脚本（地址）",
    "webResponses": "响应",
    "webSent": "已发送数据",
    "webPerMinute": "每分钟请求数",
    "nowWord": "现在",
    "webTopClients": "最活跃的地址",
    "webTopPages": "请求最多的页面",
    "webTopErrors": "出错的请求",
    "errorCount": "错误：{n}",
    "botTag": "机器人",
    "webNone": "这段时间内没有请求。",
    "webPartial": "服务器非常繁忙：只读取到最近 {s} 的记录。",
    "webUnreadable": "网页服务器的用户（{user}）无法读取访问日志。在您授权之前，此面板将保持为空。", "webAclWarning": "执行此命令之前请注意：它允许 {user} 读取访问日志，因此本服务器上的所有网站和 PHP 应用也都能读取（访客地址、请求的页面）。下一次日志轮转之后，该文件夹中的新文件（包括错误日志）也会变为可读。需要安装“acl”软件包。您自己对该文件夹的访问权限不会改变。", "webAclUndo": "如需撤销并恢复原来的权限：",
    "webMissing": "未找到访问日志。请在文件开头设置 ESM_ACCESS_LOGS。",
    "webNote": "数据来自网页服务器的访问日志，不会保存任何内容。对本监控面板的请求以及来自服务器自身的请求不计入。机器人是根据其自报的名称识别的，因此有些可能未被发现。地址中“?”之后的部分已隐藏，因为其中可能包含机密信息。",
    "apachePanel": "Apache 实时状态",
    "apacheRate": "每秒请求数",
    "apacheWorkers": "进程（忙碌 / 总数）",
    "apacheKeepalive": "保持打开的空闲连接",
    "apacheUptime": "已运行",
    "apacheInFlight": "正在处理的请求",
    "apacheIdle": "此刻没有正在处理的请求。",
    "apacheNotExtended": "要显示每个请求的详情，需要在 Apache 配置中设置“ExtendedStatus On”。",
    "apacheOff": "无法访问 Apache 状态页（{detail}）。启用方法：",
    "apacheDisabled": "已在配置中停用。",
    "apacheNote": "数据来自 Apache 状态页（mod_status），仅从本机请求。时长是请求开始以来经过的时间：时间很长可能是下载、视频流，或是卡住的页面。每秒请求数包含本监控面板自身的请求。",
    "alertInsecure": "未使用 HTTPS：密码以明文传输",
    "alertNoCache": "临时目录不可写：缓存和各进程 CPU 统计已停用",
    "alertLoad": "负载过高：{load}（{cores} 个核心）",
    "alertOom": "过去一小时内有进程因内存不足被终止",
    "alertFiles": "打开的文件数接近系统上限",
    "alertConntrack": "连接跟踪表即将占满",
    "alertRaidDegraded": "RAID 阵列已降级",
    "alertRaidSync": "RAID 阵列正在重建",
    "alertFpmQueue": "PHP-FPM：有请求在等待空闲进程",
    "alertFpmMax": "PHP-FPM 在过去一小时内达到进程数上限",
    "alertOpcacheFull": "OPcache 内存已满",
    "alertPortAll": "{service}（端口 {port}）正在所有网络接口上监听",
    "alertPortPublic": "{service}（端口 {port}）正在公网地址 {address} 上监听",
    "alertTls": "{name}：证书将在 {days} 天后过期",
    "alertTlsExpired": "{name}：证书已过期",
    "styleAuto": "自动",
    "tlsExpired": "证书已于以下日期过期",
    "lastDataAgo": "最后一次收到数据是在 {s} 前。",
    "showAllAlerts": "显示全部警报",
    "phpSapi": "服务器接口",
    "memoryLimit": "单次请求内存上限",
    "fpmPool": "PHP-FPM 进程池",
    "fpmWorkers": "进程（忙碌 / 总数）",
    "fpmQueue": "等待中的请求",
    "fpmMaxReached": "达到进程数上限的次数",
    "fpmSlow": "慢请求",
    "opcacheMemory": "OPcache 内存",
    "opcacheHitRate": "OPcache 命中率",
    "opcacheScripts": "已缓存的脚本",
    "disabledState": "已停用",
    "phpNote": "PHP-FPM 数据来自为本页面提供服务的进程池。“达到进程数上限的次数”是 PHP-FPM 启动以来触及 pm.max_children 的次数：如果持续增加，说明有请求在排队。",
    "openFiles": "打开的文件",
    "conntrack": "已跟踪的连接",
    "oomKills": "因内存不足被终止的进程（自开机以来）",
    "raidHealthy": "正常",
    "raidDegraded": "已降级",
    "raidRebuilding": "重建中",
    "raidChecking": "检查中",
    "contextHelp": "帮助",
    "maxValue": "峰值",
    "selfCheck": "此监控器（本地检测）",
    "selfCheckExplanation": "固定本地 IP 探测，TLS 名称来自 SERVER_NAME 或显式配置。公网 TLS 可单独添加 HTTPS 探测。",
    "selfCheckNeedsConfig": "本地检测失败：请检查端口和虚拟主机配置。",
    "selfProbeMismatch": "本地响应缺少预期的 monitor 标头。",
    "httpPending": "等待检测",
    "lastCheck": "上次检测",
    "staleResult": "过期结果",
    "processPss": "PSS",
    "processPartial": "进程超过上限，采用轮换抽样；100% CPU 表示一个逻辑核心。",
    "apiDuration": "API 采集耗时",
    "processes": "主要进程",
    "topCpu": "CPU 占用前五",
    "topRam": "内存占用前五",
    "topSwap": "Swap 占用前五",
    "swapProcessExplanation": "各进程的 Swap 使用量来自 /proc/PID/status 的 VmSwap。仅统计 PHP 可访问的进程；Swap 占用不等于当前交换活动。",
    "interfaceStyle": "界面风格",
    "changeStyle": "更换界面风格",
    "noSwapProcess": "未检测到使用 Swap 的进程。",
    "processNote": "CPU 使用率按两次采样计算（100% 等于一个逻辑核心）。仅显示 PHP 有权限读取的进程。",
    "ramFormula": "已用内存 = MemTotal − MemAvailable。前五名进程并不代表全部内存使用量。",
    "pssExplanation": "内存排名按 RSS 排序；可读取 PSS 时，显示按比例分摊共享内存后的值。",
    "collaboraExplanation": "forkit 和 kit_spare_* 通常是 Collabora Online / LibreOffice 预加载的文档处理进程。",
    "noProcess": "无法读取进程信息。",
    "httpChecks": "HTTP/HTTPS 与证书",
    "httpChecksNote": "默认自动检测本地监控页面；其他配置的主机也会验证 TLS 证书。",
    "noHttpChecks": "尚未配置 HTTP 检测。请在 monitor.php 开头的 ESM_HTTP_CHECKS 中添加目标。",
    "httpFailure": "HTTP 错误",
    "tlsExpires": "证书将在以下天数后过期",
    "tlsUnavailable": "无法获取 TLS 证书",
    "connectionFailed": "连接或 TLS 握手失败",
    "invalidResponse": "HTTP 响应无效",
    "settingsTitle": "自定义仪表盘",
    "close": "关闭",
    "expandChart": "放大图表",
    "refreshEvery": "刷新间隔",
    "graphPeriod": "图表时间范围",
    "warnCpu": "CPU 警告阈值 (%)",
    "warnRam": "内存警告阈值 (%)",
    "warnDisk": "磁盘警告阈值 (%)",
    "visibleCharts": "显示的图表",
    "visiblePanels": "面板显示与顺序",
    "orderNote": "调整以下两组面板的顺序。宽屏时会自动分布到 3 或 4 列。",
    "leftColumn": "分组 A",
    "rightColumn": "分组 B",
    "moveUp": "上移",
    "moveDown": "下移",
    "resetSettings": "恢复默认设置",
    "threshold": "阈值",
    "axisNow": "现在",
    "connectionRefused": "连接被拒绝（此端口没有服务在监听）",
    "httpTimeout": "未及时响应（超时）",
    "tlsCertificateError": "TLS 证书被拒绝（已过期、自签名或名称不符）",
    "viewOverview": "概览",
    "viewSystem": "系统",
    "viewNetwork": "网络",
    "viewHardware": "硬件",
    "viewProcesses": "进程",
    "showTop20": "查看前 20 名",
    "details": "详情",
    "checksPanel": "服务状态",
    "noChecks": "未配置服务检测。",
    "failedUnits": "失败的服务 (systemd)",
    "noFailedUnits": "没有失败的服务。",
    "systemdUnavailable": "不可用：systemctl 不存在或 Web 服务器用户无权使用。",
    "failedNote": "systemd 报告为失败的单元。可用 systemctl status <单元> 查看。每分钟刷新。",
    "listeningPorts": "监听端口 (TCP)",
    "noPorts": "未发现监听端口。",
    "portScopeAll": "所有网络接口",
    "portScopeLocal": "仅本机",
    "portSensitive": "数据库或 API",
    "portsNote": "本服务器上开放的 TCP 端口。“所有网络接口”表示可从网络访问（除非被防火墙阻止）。“仅本机”表示只能从本机访问。显示进程名称需要 root 权限。",
    "rebootRequired": "需要重启",
    "rebootNo": "否",
    "rebootKernel": "已安装内核 {k}，正在运行 {r}",
    "rebootPackages": "已更新的软件包",
    "healthReboot": "需要重启",
    "healthFailedUnits": "失败的服务",
    "yes": "是",
    "styleNight": "夜间",
    "styleDim": "黄昏",
    "styleLight": "浅色",
    "physicalCores": "物理核心",
    "tempCpu": "CPU 温度",
    "tempDisk": "磁盘温度",
    "tempBoard": "主板温度",
    "tempChipset": "芯片组温度",
    "tempWifi": "Wi-Fi 温度",
    "gpu": "显卡",
    "gpuUsage": "GPU 使用率",
    "gpuMemory": "显存",
    "gpuTemp": "GPU 温度",
    "gpuPower": "GPU 功耗",
    "gpuClock": "GPU 频率",
    "detailTitle": "进程前 20 名",
    "top20Cpu": "CPU 占用前 20",
    "top20Ram": "内存占用前 20",
    "top20Swap": "Swap 占用前 20",
    "detailNote": "每 {s} 秒刷新，与仪表板使用同一次采样。",
    "footerSetting": "页脚",
    "showFooter": "显示源代码与支持链接",
    "footerSource": "源码与支持：",
    "footerBuyMe": "请我喝",
    "footerCoffee": "咖啡",
    "footerTokens": "tokens",
    "done": "完成",
    "healthDisclaimer": "状态基于可用指标及已配置检测的估算，不代表完整诊断。",
    "healthy": "正常",
    "healthWarn": "注意",
    "healthCritical": "严重",
    "healthNeedsAttention": "至少有一项阈值或检测需要关注。",
    "healthAllClear": "监控指标中没有当前警报。",
    "swapIdle": "交换空间已使用，但当前未检测到交换读写。",
    "inodes": "索引节点",
    "diskBusy": "磁盘忙碌",
    "linkSpeed": "链路",
    "networkErrorRate": "错误/秒",
    "networkErrors": "新增网络错误或丢包",
    "fullStall": "完全阻塞",
    "tagline": "轻量级 Linux 监控面板",
    "connecting": "连接中…",
    "online": "实时",
    "offline": "已断开",
    "host": "主机",
    "updated": "更新时间",
    "cpu": "CPU 使用率",
    "memory": "内存",
    "disk": "磁盘",
    "uptime": "运行时间",
    "activity": "实时活动",
    "cpuGraph": "CPU · 最近3分钟",
    "memoryGraph": "内存 · 最近3分钟",
    "historyNote": "图表仅保存在当前标签页。",
    "system": "系统",
    "storage": "存储",
    "network": "网络",
    "services": "服务",
    "hardware": "硬件与传感器",
    "footer": "单文件。零依赖。只读监控。",
    "os": "操作系统",
    "kernel": "内核",
    "architecture": "架构",
    "cpuModel": "处理器",
    "cores": "逻辑核心",
    "load": "系统负载",
    "php": "PHP",
    "swap": "交换空间",
    "used": "已使用",
    "free": "可用",
    "unknown": "不可用",
    "none": "无数据",
    "onlineService": "在线",
    "offlineService": "离线",
    "rx": "接收",
    "tx": "发送",
    "refreshError": "无法获取服务器指标。",
    "seconds": "秒",
    "days": "天",
    "hours": "小时",
    "minutes": "分",
    "temperature": "温度",
    "refresh": "刷新",
    "language": "语言",
    "swapGraph": "交换空间 · 最近3分钟",
    "networkGraph": "网络流量",
    "diskGraph": "磁盘 I/O",
    "perCore": "各 CPU 核心使用率",
    "read": "读取",
    "write": "写入",
    "diskIo": "磁盘活动",
    "diskIoNote": "速率根据连续采样计算；不会重复累计叠加设备。",
    "mergedMountNote": "等效的挂载点已合并。",
    "extraMounts": "其他挂载点",
    "swapActivity": "交换空间活动",
    "swapIn": "换入",
    "swapOut": "换出",
    "pagesPerSecond": "页/秒",
    "swapDisabled": "未配置",
    "cached": "缓存内存",
    "physical": "物理接口",
    "vpn": "VPN",
    "virtual": "虚拟接口",
    "loopback": "回环接口",
    "secondaryInterfaces": "虚拟和次要网络接口",
    "networkNote": "对于 VPN，“已启用”仅表示接口已开启，不代表隧道已完成握手。",
    "rxErrors": "接收错误",
    "txErrors": "发送错误",
    "dropped": "丢弃的数据包",
    "pressure": "系统资源压力 (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "内存",
    "pressureIo": "I/O",
    "pressureNote": "任务等待资源的时间比例，10 秒平均值 (PSI)。",
    "tcpNote": "仅检查 TCP 连接，不检查 HTTP 内容。",
    "estimating": "计算中…",
    "enabledState": "已启用",
    "upState": "活动",
    "downState": "断开",
    "unknownState": "未知",
    "dormantState": "休眠",
    "lowerlayerdownState": "底层连接断开",
    "testingState": "测试中",
    "notpresentState": "不存在",
    "noDevices": "未检测到兼容的块设备。",
    "core": "核心",
    "available": "可用"
  },
  hi: {
    "connectionsPanel": "वर्तमान कनेक्शन (TCP)",
    "connIncoming": "आने वाले",
    "connOutgoing": "जाने वाले",
    "connLocal": "आंतरिक (इसी सर्वर के भीतर)",
    "addressCount": "{n} IP",
    "connByService": "आने वाले कनेक्शन, सेवा के अनुसार",
    "connNone": "इस समय कोई आने वाला कनेक्शन नहीं है।",
    "connOutgoingList": "जाने वाले कनेक्शन के गंतव्य",
    "sessionsTitle": "लॉग इन उपयोगकर्ता (SSH, कंसोल)",
    "sessionsNone": "कोई लॉग इन नहीं है।",
    "agoText": "{s} पहले",
    "connNote": "इस क्षण खुले कनेक्शन, सीधे कर्नेल से पढ़े गए (कुछ भी स्कैन नहीं किया जाता)। एक पता एक व्यक्ति नहीं होता: कई लोग एक ही पता साझा कर सकते हैं, और कई पते रोबोट के होते हैं। जाने वाले कनेक्शन किस प्रोग्राम ने खोले, यह root पहुँच के बिना नहीं दिखता। सीधे किसी कंटेनर तक जाने वाला ट्रैफ़िक शायद न दिखे।",
    "webPanel": "हाल का वेब ट्रैफ़िक",
    "webRequests": "अनुरोध ({m} मिनट)",
    "webVisitors": "ब्राउज़र और ऐप (पते)",
    "webBots": "रोबोट और स्क्रिप्ट (पते)",
    "webResponses": "उत्तर",
    "webSent": "भेजा गया डेटा",
    "webPerMinute": "प्रति मिनट अनुरोध",
    "nowWord": "अभी",
    "webTopClients": "सबसे सक्रिय पते",
    "webTopPages": "सबसे अधिक माँगे गए पृष्ठ",
    "webTopErrors": "त्रुटि वाले अनुरोध",
    "errorCount": "त्रुटियाँ: {n}",
    "botTag": "रोबोट",
    "webNone": "इस अवधि में कोई अनुरोध नहीं।",
    "webPartial": "सर्वर बहुत व्यस्त है: केवल पिछले {s} ही पढ़े जा सके।",
    "webUnreadable": "वेब सर्वर का उपयोगकर्ता ({user}) एक्सेस लॉग नहीं पढ़ सकता। जब तक आप अनुमति नहीं देते, यह पैनल खाली रहेगा।", "webAclWarning": "यह कमांड चलाने से पहले: यह {user} को एक्सेस लॉग पढ़ने देता है, इसलिए इस सर्वर की सभी वेबसाइटें और PHP एप्लिकेशन भी उन्हें पढ़ सकेंगे (आगंतुकों के पते, माँगे गए पृष्ठ)। अगले लॉग रोटेशन के बाद फ़ोल्डर की नई फ़ाइलें, त्रुटि लॉग सहित, भी पढ़ी जा सकेंगी। \"acl\" पैकेज आवश्यक है। फ़ोल्डर तक आपकी अपनी पहुँच नहीं बदलती।", "webAclUndo": "इसे रद्द करके मूल अनुमतियों पर लौटने के लिए:",
    "webMissing": "कोई एक्सेस लॉग नहीं मिला। फ़ाइल के शुरू में ESM_ACCESS_LOGS सेट करें।",
    "webNote": "वेब सर्वर के एक्सेस लॉग से पढ़ा गया; कुछ भी सहेजा नहीं जाता। इस डैशबोर्ड के अनुरोध और स्वयं सर्वर से आने वाले अनुरोध शामिल नहीं हैं। रोबोट उनके बताए नाम से पहचाने जाते हैं, इसलिए कुछ छूट सकते हैं। पते में \"?\" के बाद का भाग छिपाया जाता है, क्योंकि उसमें गोपनीय जानकारी हो सकती है।",
    "apachePanel": "Apache, इस समय",
    "apacheRate": "प्रति सेकंड अनुरोध",
    "apacheWorkers": "प्रक्रियाएँ (व्यस्त / कुल)",
    "apacheKeepalive": "खुले रखे गए निष्क्रिय कनेक्शन",
    "apacheUptime": "चालू हुए",
    "apacheInFlight": "इस समय संसाधित हो रहे अनुरोध",
    "apacheIdle": "इस क्षण कोई अनुरोध संसाधित नहीं हो रहा।",
    "apacheNotExtended": "प्रति अनुरोध विवरण के लिए Apache के कॉन्फ़िगरेशन में \"ExtendedStatus On\" चाहिए।",
    "apacheOff": "Apache का स्थिति पृष्ठ उपलब्ध नहीं है ({detail})। इसे चालू करने के लिए:",
    "apacheDisabled": "कॉन्फ़िगरेशन में बंद है।",
    "apacheNote": "Apache के स्थिति पृष्ठ (mod_status) से, जो केवल इसी मशीन से माँगा जाता है। अवधि अनुरोध शुरू होने के बाद का समय है: लंबी अवधि डाउनलोड, वीडियो स्ट्रीम या अटका हुआ पृष्ठ हो सकती है। प्रति सेकंड अनुरोधों में इस डैशबोर्ड के अनुरोध भी शामिल हैं।",
    "alertInsecure": "HTTPS नहीं है: पासवर्ड बिना एन्क्रिप्शन के भेजा जा रहा है",
    "alertNoCache": "अस्थायी फ़ोल्डर में लिखा नहीं जा सकता: कैश और प्रति-प्रक्रिया CPU बंद हैं",
    "alertLoad": "अधिक लोड: {cores} कोर के लिए {load}",
    "alertOom": "पिछले एक घंटे में मेमोरी की कमी से एक प्रक्रिया बंद की गई",
    "alertFiles": "खुली फ़ाइलें सिस्टम सीमा के करीब हैं",
    "alertConntrack": "कनेक्शन ट्रैकिंग तालिका लगभग भर गई है",
    "alertRaidDegraded": "RAID ऐरे डिग्रेडेड है",
    "alertRaidSync": "RAID ऐरे का पुनर्निर्माण चल रहा है",
    "alertFpmQueue": "PHP-FPM: अनुरोध खाली प्रक्रिया की प्रतीक्षा में हैं",
    "alertFpmMax": "PHP-FPM पिछले एक घंटे में अपनी प्रक्रिया सीमा तक पहुँचा",
    "alertOpcacheFull": "OPcache मेमोरी भर गई है",
    "alertPortAll": "{service} (पोर्ट {port}) सभी इंटरफ़ेस पर सुन रहा है",
    "alertPortPublic": "{service} (पोर्ट {port}) सार्वजनिक पते {address} पर सुन रहा है",
    "alertTls": "{name}: प्रमाणपत्र {days} दिन में समाप्त होगा",
    "alertTlsExpired": "{name}: प्रमाणपत्र समाप्त हो चुका है",
    "styleAuto": "स्वचालित",
    "tlsExpired": "प्रमाणपत्र इस तारीख को समाप्त हुआ",
    "lastDataAgo": "अंतिम डेटा {s} पहले मिला।",
    "showAllAlerts": "सभी चेतावनियाँ दिखाएँ",
    "phpSapi": "सर्वर इंटरफ़ेस",
    "memoryLimit": "प्रति अनुरोध मेमोरी सीमा",
    "fpmPool": "PHP-FPM पूल",
    "fpmWorkers": "प्रक्रियाएँ (व्यस्त / कुल)",
    "fpmQueue": "प्रतीक्षारत अनुरोध",
    "fpmMaxReached": "प्रक्रिया सीमा तक पहुँचने की संख्या",
    "fpmSlow": "धीमे अनुरोध",
    "opcacheMemory": "OPcache मेमोरी",
    "opcacheHitRate": "OPcache हिट दर",
    "opcacheScripts": "कैश की गई स्क्रिप्ट",
    "disabledState": "बंद",
    "phpNote": "PHP-FPM के आँकड़े उसी पूल के हैं जो यह पृष्ठ परोसता है। \"प्रक्रिया सीमा तक पहुँचने की संख्या\" बताती है कि PHP-FPM शुरू होने के बाद pm.max_children कितनी बार छुआ गया: यदि यह बढ़ रही है, तो अनुरोध कतार में हैं।",
    "openFiles": "खुली फ़ाइलें",
    "conntrack": "ट्रैक किए गए कनेक्शन",
    "oomKills": "मेमोरी की कमी से बंद की गई प्रक्रियाएँ (बूट के बाद से)",
    "raidHealthy": "ठीक",
    "raidDegraded": "डिग्रेडेड",
    "raidRebuilding": "पुनर्निर्माण",
    "raidChecking": "जाँच",
    "contextHelp": "सहायता",
    "maxValue": "अधिकतम",
    "selfCheck": "यह मॉनिटर (स्थानीय जाँच)",
    "selfCheckExplanation": "स्थिर स्थानीय IP से जाँच; TLS नाम SERVER_NAME या स्पष्ट कॉन्फ़िगरेशन से आता है। सार्वजनिक TLS के लिए अलग HTTPS जाँच जोड़ें।",
    "selfCheckNeedsConfig": "स्थानीय जाँच विफल: पोर्ट और वर्चुअल होस्ट जाँचें।",
    "selfProbeMismatch": "स्थानीय प्रतिक्रिया में अपेक्षित monitor हेडर नहीं है।",
    "httpPending": "प्रतीक्षारत",
    "lastCheck": "अंतिम जाँच",
    "staleResult": "पुराना परिणाम",
    "processPss": "PSS",
    "processPartial": "प्रक्रिया सीमा पार; नमूनाकरण चालू है। 100% CPU = एक लॉजिकल कोर।",
    "apiDuration": "API संग्रह समय",
    "processes": "प्रमुख प्रक्रियाएँ",
    "topCpu": "शीर्ष 5 · CPU",
    "topRam": "शीर्ष 5 · RAM",
    "topSwap": "शीर्ष 5 · स्वैप",
    "swapProcessExplanation": "प्रति-प्रक्रिया स्वैप /proc/PID/status के VmSwap से लिया जाता है। केवल PHP द्वारा पढ़ी जा सकने वाली प्रक्रियाएँ दिखाई देती हैं; स्वैप उपयोग और स्वैप I/O अलग हैं।",
    "interfaceStyle": "इंटरफ़ेस शैली",
    "changeStyle": "शैली बदलें",
    "noSwapProcess": "मापनीय स्वैप उपयोग वाली कोई प्रक्रिया नहीं।",
    "processNote": "CPU उपयोग दो नमूनों के बीच गणना होता है (100% = एक लॉजिकल कोर)। केवल PHP को दिखने वाली प्रक्रियाएँ सूचीबद्ध हैं।",
    "ramFormula": "उपयोग की गई RAM = MemTotal − MemAvailable। शीर्ष 5 प्रक्रियाएँ पूरी RAM का विवरण नहीं हैं।",
    "pssExplanation": "RAM क्रम RSS के आधार पर है। उपलब्ध होने पर PSS साझा मेमोरी को अनुपात में बाँटकर दिखाता है।",
    "collaboraExplanation": "forkit और kit_spare_* सामान्यतः Collabora Online / LibreOffice की पहले से तैयार प्रक्रियाएँ हैं।",
    "noProcess": "प्रक्रियाओं की जानकारी उपलब्ध नहीं है।",
    "httpChecks": "HTTP/HTTPS और प्रमाणपत्र",
    "httpChecksNote": "यह डैशबोर्ड डिफ़ॉल्ट रूप से स्थानीय रूप से जाँचा जाता है; अन्य होस्ट के TLS प्रमाणपत्र सत्यापित होते हैं।",
    "noHttpChecks": "HTTP जाँच कॉन्फ़िगर नहीं है। monitor.php की शुरुआत में ESM_HTTP_CHECKS भरें।",
    "httpFailure": "HTTP त्रुटि",
    "tlsExpires": "प्रमाणपत्र समाप्त होने में",
    "tlsUnavailable": "TLS प्रमाणपत्र उपलब्ध नहीं",
    "connectionFailed": "कनेक्शन या TLS हैंडशेक विफल",
    "invalidResponse": "अमान्य HTTP प्रतिक्रिया",
    "settingsTitle": "डैशबोर्ड अनुकूलित करें",
    "close": "बंद करें",
    "expandChart": "ग्राफ़ बड़ा करें",
    "refreshEvery": "रीफ़्रेश अंतराल",
    "graphPeriod": "ग्राफ़ अवधि",
    "warnCpu": "CPU चेतावनी सीमा (%)",
    "warnRam": "RAM चेतावनी सीमा (%)",
    "warnDisk": "डिस्क चेतावनी सीमा (%)",
    "visibleCharts": "दिखने वाले ग्राफ़",
    "visiblePanels": "पैनल: दृश्यता और क्रम",
    "orderNote": "दोनों समूहों का क्रम बदलें। चौड़ी स्क्रीन पर पैनल अपने आप 3 या 4 कॉलम में बँटते हैं।",
    "leftColumn": "समूह A",
    "rightColumn": "समूह B",
    "moveUp": "ऊपर ले जाएँ",
    "moveDown": "नीचे ले जाएँ",
    "resetSettings": "सेटिंग्स रीसेट करें",
    "threshold": "सीमा",
    "axisNow": "अभी",
    "connectionRefused": "कनेक्शन अस्वीकृत (इस पोर्ट पर कोई सेवा नहीं सुन रही)",
    "httpTimeout": "समय पर उत्तर नहीं (टाइमआउट)",
    "tlsCertificateError": "TLS प्रमाणपत्र अस्वीकृत (समाप्त, स्व-हस्ताक्षरित या गलत नाम)",
    "viewOverview": "सारांश",
    "viewSystem": "सिस्टम",
    "viewNetwork": "नेटवर्क",
    "viewHardware": "हार्डवेयर",
    "viewProcesses": "प्रक्रियाएँ",
    "showTop20": "शीर्ष 20 देखें",
    "details": "विवरण",
    "checksPanel": "सेवाओं की स्थिति",
    "noChecks": "कोई सेवा जाँच कॉन्फ़िगर नहीं है।",
    "failedUnits": "विफल सेवाएँ (systemd)",
    "noFailedUnits": "कोई विफल सेवा नहीं।",
    "systemdUnavailable": "उपलब्ध नहीं: systemctl मौजूद नहीं है या वेब सर्वर उपयोगकर्ता के लिए अनुमति नहीं है।",
    "failedNote": "वे यूनिट जिन्हें systemd विफल बताता है। जाँचने के लिए: systemctl status <यूनिट>। हर मिनट अपडेट।",
    "listeningPorts": "सुनने वाले पोर्ट (TCP)",
    "noPorts": "कोई सुनने वाला पोर्ट नहीं मिला।",
    "portScopeAll": "सभी इंटरफ़ेस",
    "portScopeLocal": "केवल स्थानीय",
    "portSensitive": "डेटाबेस या API",
    "portsNote": "इस सर्वर पर खुले TCP पोर्ट। \"सभी इंटरफ़ेस\" का अर्थ है नेटवर्क से पहुँच योग्य, जब तक फ़ायरवॉल न रोके। \"केवल स्थानीय\" का अर्थ है केवल इसी मशीन से। प्रक्रिया के नाम के लिए root अधिकार चाहिए।",
    "rebootRequired": "रीस्टार्ट आवश्यक",
    "rebootNo": "नहीं",
    "rebootKernel": "कर्नेल {k} इंस्टॉल, {r} चल रहा है",
    "rebootPackages": "अपडेट किए गए पैकेज",
    "healthReboot": "रीस्टार्ट आवश्यक",
    "healthFailedUnits": "विफल सेवाएँ",
    "yes": "हाँ",
    "styleNight": "रात",
    "styleDim": "संध्या",
    "styleLight": "हल्का",
    "physicalCores": "भौतिक कोर",
    "tempCpu": "CPU तापमान",
    "tempDisk": "डिस्क तापमान",
    "tempBoard": "मदरबोर्ड तापमान",
    "tempChipset": "चिपसेट तापमान",
    "tempWifi": "Wi-Fi तापमान",
    "gpu": "ग्राफ़िक्स कार्ड",
    "gpuUsage": "GPU उपयोग",
    "gpuMemory": "वीडियो मेमोरी",
    "gpuTemp": "GPU तापमान",
    "gpuPower": "GPU बिजली खपत",
    "gpuClock": "GPU आवृत्ति",
    "detailTitle": "शीर्ष 20 प्रक्रियाएँ",
    "top20Cpu": "शीर्ष 20 · CPU",
    "top20Ram": "शीर्ष 20 · RAM",
    "top20Swap": "शीर्ष 20 · स्वैप",
    "detailNote": "हर {s} सेकंड में अपडेट, डैशबोर्ड वाले ही नमूने से।",
    "footerSetting": "फ़ुटर",
    "showFooter": "सोर्स कोड और सहायता लिंक दिखाएँ",
    "footerSource": "सोर्स कोड और सहायता:",
    "footerBuyMe": "मुझे",
    "footerCoffee": "कॉफी",
    "footerTokens": "tokens दिलाएं",
    "done": "पूर्ण",
    "healthDisclaimer": "उपलब्ध आँकड़ों और कॉन्फ़िगर की गई जाँचों पर आधारित अनुमान; संपूर्ण निदान नहीं।",
    "healthy": "सामान्य",
    "healthWarn": "चेतावनी",
    "healthCritical": "गंभीर",
    "healthNeedsAttention": "कम से कम एक सीमा या जाँच पर ध्यान देना आवश्यक है।",
    "healthAllClear": "निगरानी के अंतर्गत कोई सक्रिय चेतावनी नहीं।",
    "swapIdle": "स्वैप उपयोग में है, पर अभी स्वैप I/O नहीं मिला।",
    "inodes": "इनोड",
    "diskBusy": "डिस्क व्यस्त",
    "linkSpeed": "लिंक",
    "networkErrorRate": "त्रुटियाँ/सेकंड",
    "networkErrors": "नई नेटवर्क त्रुटियाँ या पैकेट हानि",
    "fullStall": "पूर्ण अवरोध",
    "tagline": "हल्का Linux निगरानी डैशबोर्ड",
    "connecting": "कनेक्ट हो रहा है…",
    "online": "लाइव",
    "offline": "डिस्कनेक्ट",
    "host": "सर्वर",
    "updated": "अपडेट",
    "cpu": "CPU उपयोग",
    "memory": "मेमोरी",
    "disk": "डिस्क",
    "uptime": "चालू समय",
    "activity": "लाइव गतिविधि",
    "cpuGraph": "CPU · पिछले 3 मिनट",
    "memoryGraph": "RAM · पिछले 3 मिनट",
    "historyNote": "ग्राफ़ केवल इस टैब में रहते हैं।",
    "system": "सिस्टम",
    "storage": "स्टोरेज",
    "network": "नेटवर्क",
    "services": "सेवाएँ",
    "hardware": "हार्डवेयर और सेंसर",
    "footer": "एक फ़ाइल। बिना निर्भरता। केवल पढ़ने की निगरानी।",
    "os": "ऑपरेटिंग सिस्टम",
    "kernel": "कर्नेल",
    "architecture": "आर्किटेक्चर",
    "cpuModel": "प्रोसेसर",
    "cores": "लॉजिकल कोर",
    "load": "औसत लोड",
    "php": "PHP",
    "swap": "स्वैप",
    "used": "उपयोग",
    "free": "खाली",
    "unknown": "उपलब्ध नहीं",
    "none": "डेटा नहीं",
    "onlineService": "चालू",
    "offlineService": "बंद",
    "rx": "प्राप्त",
    "tx": "भेजा",
    "refreshError": "सर्वर डेटा उपलब्ध नहीं।",
    "seconds": "से",
    "days": "दिन",
    "hours": "घं",
    "minutes": "मि",
    "temperature": "तापमान",
    "refresh": "रीफ्रेश",
    "language": "भाषा",
    "swapGraph": "Swap · पिछले 3 मिनट",
    "networkGraph": "नेटवर्क ट्रैफ़िक",
    "diskGraph": "डिस्क I/O",
    "perCore": "प्रति CPU कोर उपयोग",
    "read": "पढ़ना",
    "write": "लिखना",
    "diskIo": "डिस्क गतिविधि",
    "diskIoNote": "गति लगातार नमूनों से गणना होती है। लेयर्ड डिवाइस दो बार नहीं गिने जाते।",
    "mergedMountNote": "समान माउंट पॉइंट एक साथ दिखाए जाते हैं।",
    "extraMounts": "अन्य माउंट पॉइंट",
    "swapActivity": "Swap गतिविधि",
    "swapIn": "Swap इन",
    "swapOut": "Swap आउट",
    "pagesPerSecond": "पेज/सेकंड",
    "swapDisabled": "कॉन्फ़िगर नहीं",
    "cached": "कैश मेमोरी",
    "physical": "भौतिक",
    "vpn": "VPN",
    "virtual": "वर्चुअल",
    "loopback": "लूपबैक",
    "secondaryInterfaces": "वर्चुअल और द्वितीयक इंटरफ़ेस",
    "networkNote": "VPN के लिए “सक्रिय किया गया” का अर्थ इंटरफ़ेस चालू है, न कि टनल का हैंडशेक सफल हुआ है।",
    "rxErrors": "प्राप्ति त्रुटियाँ",
    "txErrors": "भेजने की त्रुटियाँ",
    "dropped": "छोड़े गए पैकेट",
    "pressure": "सिस्टम दबाव (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "मेमोरी",
    "pressureIo": "I/O",
    "pressureNote": "संसाधनों की प्रतीक्षा में बीता समय, 10 सेकंड का औसत (PSI)।",
    "tcpNote": "केवल TCP कनेक्शन जाँच, HTTP सामग्री जाँच नहीं।",
    "estimating": "गणना हो रही है…",
    "enabledState": "सक्रिय किया गया",
    "upState": "सक्रिय",
    "downState": "बंद",
    "unknownState": "अज्ञात",
    "dormantState": "निष्क्रिय",
    "lowerlayerdownState": "निचली परत बंद",
    "testingState": "परीक्षण",
    "notpresentState": "अनुपस्थित",
    "noDevices": "कोई संगत ब्लॉक डिवाइस नहीं मिला।",
    "core": "कोर",
    "available": "उपलब्ध"
  },
  ja: {
    "connectionsPanel": "現在の接続（TCP）",
    "connIncoming": "受信",
    "connOutgoing": "送信",
    "connLocal": "内部（このサーバー内）",
    "addressCount": "{n} IP",
    "connByService": "受信接続（サービス別）",
    "connNone": "現在、受信接続はありません。",
    "connOutgoingList": "送信先",
    "sessionsTitle": "ログイン中のユーザー（SSH、コンソール）",
    "sessionsNone": "ログイン中のユーザーはいません。",
    "agoText": "{s} 前",
    "connNote": "この瞬間に開いている接続を、カーネルから直接読み取っています（スキャンは行いません）。アドレスは人ではありません。複数の人が同じアドレスを共有することがあり、多くはロボットです。送信接続を開いたプログラムは、root 権限がないと分かりません。コンテナーに直接届く通信は表示されない場合があります。",
    "webPanel": "最近のウェブトラフィック",
    "webRequests": "リクエスト数（{m} 分）",
    "webVisitors": "ブラウザー・アプリ（アドレス）",
    "webBots": "ロボット・スクリプト（アドレス）",
    "webResponses": "レスポンス",
    "webSent": "送信データ量",
    "webPerMinute": "1分あたりのリクエスト数",
    "nowWord": "現在",
    "webTopClients": "最もアクティブなアドレス",
    "webTopPages": "最も多くリクエストされたページ",
    "webTopErrors": "エラーになったリクエスト",
    "errorCount": "エラー：{n}",
    "botTag": "ロボット",
    "webNone": "この期間のリクエストはありません。",
    "webPartial": "サーバーが非常に混雑しています：直近 {s} のみ読み取れました。",
    "webUnreadable": "ウェブサーバーのユーザー（{user}）がアクセスログを読み取れません。許可するまで、このパネルは空のままです。", "webAclWarning": "このコマンドを実行する前に：{user} がアクセスログを読めるようになるため、このサーバー上のすべてのウェブサイトと PHP アプリケーションも読めるようになります（訪問者のアドレス、リクエストされたページ）。次回のログローテーション後は、フォルダー内の新しいファイル（エラーログを含む）も読み取り可能になります。「acl」パッケージが必要です。フォルダーに対するご自身のアクセス権は変わりません。", "webAclUndo": "元の権限に戻すには：",
    "webMissing": "アクセスログが見つかりません。ファイル冒頭の ESM_ACCESS_LOGS を設定してください。",
    "webNote": "ウェブサーバーのアクセスログから読み取っており、何も保存しません。このダッシュボードへのリクエストと、サーバー自身からのリクエストは除外されます。ロボットは名乗っている名前で判別するため、見逃されるものもあります。アドレスの「?」以降は、秘密情報を含む可能性があるため表示しません。",
    "apachePanel": "Apache の現在の状況",
    "apacheRate": "1秒あたりのリクエスト数",
    "apacheWorkers": "プロセス（処理中 / 合計）",
    "apacheKeepalive": "開いたままの待機中接続",
    "apacheUptime": "稼働時間",
    "apacheInFlight": "処理中のリクエスト",
    "apacheIdle": "現在、処理中のリクエストはありません。",
    "apacheNotExtended": "リクエストごとの詳細には、Apache の設定で「ExtendedStatus On」が必要です。",
    "apacheOff": "Apache のステータスページに接続できません（{detail}）。有効にするには：",
    "apacheDisabled": "設定で無効になっています。",
    "apacheNote": "Apache のステータスページ（mod_status）から取得しており、このマシンからのみ要求します。時間はリクエスト開始からの経過時間で、長い場合はダウンロード、動画ストリーム、または止まっているページの可能性があります。1秒あたりのリクエスト数には、このダッシュボード自身のリクエストも含まれます。",
    "alertInsecure": "HTTPS ではありません：パスワードが暗号化されずに送信されます",
    "alertNoCache": "一時フォルダーに書き込めません：キャッシュとプロセス別 CPU は無効です",
    "alertLoad": "高負荷：{load}（{cores} コア）",
    "alertOom": "過去1時間以内にメモリ不足でプロセスが強制終了されました",
    "alertFiles": "開いているファイル数がシステム上限に近づいています",
    "alertConntrack": "接続追跡テーブルがほぼ満杯です",
    "alertRaidDegraded": "RAID アレイが縮退しています",
    "alertRaidSync": "RAID アレイを再構築中",
    "alertFpmQueue": "PHP-FPM：空きプロセス待ちのリクエストがあります",
    "alertFpmMax": "PHP-FPM が過去1時間以内にプロセス数の上限に達しました",
    "alertOpcacheFull": "OPcache のメモリが満杯です",
    "alertPortAll": "{service}（ポート {port}）がすべてのインターフェースで待ち受け中",
    "alertPortPublic": "{service}（ポート {port}）がパブリックアドレス {address} で待ち受け中",
    "alertTls": "{name}：証明書の有効期限まであと {days} 日",
    "alertTlsExpired": "{name}：証明書の有効期限が切れています",
    "styleAuto": "自動",
    "tlsExpired": "証明書の有効期限切れ",
    "lastDataAgo": "最後のデータ受信は {s} 前です。",
    "showAllAlerts": "すべての警告を表示",
    "phpSapi": "サーバーインターフェース",
    "memoryLimit": "リクエストごとのメモリ上限",
    "fpmPool": "PHP-FPM プール",
    "fpmWorkers": "プロセス（処理中 / 合計）",
    "fpmQueue": "待機中のリクエスト",
    "fpmMaxReached": "プロセス数上限への到達回数",
    "fpmSlow": "遅いリクエスト",
    "opcacheMemory": "OPcache メモリ",
    "opcacheHitRate": "OPcache ヒット率",
    "opcacheScripts": "キャッシュ済みスクリプト",
    "disabledState": "無効",
    "phpNote": "PHP-FPM の数値は、このページを処理しているプールのものです。「プロセス数上限への到達回数」は PHP-FPM の起動以降に pm.max_children に達した回数で、増え続ける場合はリクエストが待たされています。",
    "openFiles": "開いているファイル",
    "conntrack": "追跡中の接続",
    "oomKills": "メモリ不足で強制終了されたプロセス（起動以降）",
    "raidHealthy": "正常",
    "raidDegraded": "縮退",
    "raidRebuilding": "再構築中",
    "raidChecking": "チェック中",
    "contextHelp": "ヘルプ",
    "maxValue": "最大",
    "selfCheck": "このモニター（ローカル検査）",
    "selfCheckExplanation": "固定ローカルIPを検査し、TLS名にはSERVER_NAMEまたは明示設定を使用します。公開TLSには別のHTTPS検査が必要な場合があります。",
    "selfCheckNeedsConfig": "ローカル検査に失敗しました。ポートと仮想ホストを確認してください。",
    "selfProbeMismatch": "ローカル応答に予期した monitor ヘッダーがありません。",
    "httpPending": "待機中",
    "lastCheck": "最終チェック",
    "staleResult": "古い結果",
    "processPss": "PSS",
    "processPartial": "プロセス数の上限により一部を抽出。CPU 100% は論理コア1個分です。",
    "apiDuration": "API 収集時間",
    "processes": "主なプロセス",
    "topCpu": "CPU 上位5件",
    "topRam": "RAM 上位5件",
    "topSwap": "Swap 使用量 上位5件",
    "swapProcessExplanation": "プロセス別の Swap は /proc/PID/status の VmSwap を使用します。PHP が読み取れるプロセスのみ対象です。Swap 使用量と入出力頻度は異なります。",
    "interfaceStyle": "画面スタイル",
    "changeStyle": "スタイルを切り替える",
    "noSwapProcess": "Swap 使用量を測定できるプロセスはありません。",
    "processNote": "CPU 使用率は連続した測定から計算します（100% = 論理コア1個）。PHPから参照できるプロセスのみ表示します。",
    "ramFormula": "使用RAM = MemTotal − MemAvailable。上位5プロセスはRAM全体の内訳ではありません。",
    "pssExplanation": "RAM順位はRSS基準です。PSSが取得できる場合、共有メモリをプロセス間で比例配分した値を表示します。",
    "collaboraExplanation": "forkitとkit_spare_*は通常、文書を素早く開くためのCollabora Online / LibreOfficeの待機プロセスです。",
    "noProcess": "参照可能なプロセスがありません。",
    "httpChecks": "HTTP/HTTPS と証明書",
    "httpChecksNote": "このダッシュボードをローカルで自動検査します。追加ホストはTLS証明書も検証します。",
    "noHttpChecks": "HTTP チェックが未設定です。monitor.php 冒頭の ESM_HTTP_CHECKS に追加してください。",
    "httpFailure": "HTTP エラー",
    "tlsExpires": "証明書の有効期限まで",
    "tlsUnavailable": "TLS 証明書を取得できません",
    "connectionFailed": "接続または TLS ハンドシェイクに失敗",
    "invalidResponse": "無効な HTTP 応答",
    "settingsTitle": "ダッシュボードのカスタマイズ",
    "close": "閉じる",
    "expandChart": "グラフを拡大",
    "refreshEvery": "更新間隔",
    "graphPeriod": "グラフ表示期間",
    "warnCpu": "CPU 警告しきい値 (%)",
    "warnRam": "RAM 警告しきい値 (%)",
    "warnDisk": "ディスク警告しきい値 (%)",
    "visibleCharts": "表示するグラフ",
    "visiblePanels": "パネルの表示と順番",
    "orderNote": "2つのグループの並び順を変更できます。広い画面ではパネルを3～4列に自動配置します。",
    "leftColumn": "グループA",
    "rightColumn": "グループB",
    "moveUp": "上へ",
    "moveDown": "下へ",
    "resetSettings": "設定を初期化",
    "threshold": "しきい値",
    "axisNow": "現在",
    "connectionRefused": "接続が拒否されました（このポートで待ち受けているサービスがありません）",
    "httpTimeout": "時間内に応答がありません（タイムアウト）",
    "tlsCertificateError": "TLS 証明書が拒否されました（期限切れ、自己署名、または名前の不一致）",
    "viewOverview": "概要",
    "viewSystem": "システム",
    "viewNetwork": "ネットワーク",
    "viewHardware": "ハードウェア",
    "viewProcesses": "プロセス",
    "showTop20": "上位20件を表示",
    "details": "詳細",
    "checksPanel": "サービスの状態",
    "noChecks": "サービスチェックが設定されていません。",
    "failedUnits": "失敗したサービス (systemd)",
    "noFailedUnits": "失敗したサービスはありません。",
    "systemdUnavailable": "利用不可：systemctl が存在しないか、Web サーバーのユーザーに許可されていません。",
    "failedNote": "systemd が失敗と報告しているユニットです。確認するには：systemctl status <ユニット>。1分ごとに更新。",
    "listeningPorts": "待ち受けポート (TCP)",
    "noPorts": "待ち受けポートはありません。",
    "portScopeAll": "すべてのインターフェース",
    "portScopeLocal": "ローカルのみ",
    "portSensitive": "データベースまたは API",
    "portsNote": "このサーバーで開いている TCP ポートです。「すべてのインターフェース」はファイアウォールで遮断されていない限りネットワークから接続可能、「ローカルのみ」はこのマシンからのみ接続可能です。プロセス名の表示には root 権限が必要です。",
    "rebootRequired": "再起動が必要",
    "rebootNo": "いいえ",
    "rebootKernel": "カーネル {k} がインストール済み、{r} が稼働中",
    "rebootPackages": "更新されたパッケージ",
    "healthReboot": "再起動が必要",
    "healthFailedUnits": "失敗したサービス",
    "yes": "はい",
    "styleNight": "ナイト",
    "styleDim": "トワイライト",
    "styleLight": "ライト",
    "physicalCores": "物理コア",
    "tempCpu": "CPU 温度",
    "tempDisk": "ディスク温度",
    "tempBoard": "マザーボード温度",
    "tempChipset": "チップセット温度",
    "tempWifi": "Wi-Fi 温度",
    "gpu": "グラフィックカード",
    "gpuUsage": "GPU 使用率",
    "gpuMemory": "ビデオメモリ",
    "gpuTemp": "GPU 温度",
    "gpuPower": "GPU 消費電力",
    "gpuClock": "GPU クロック",
    "detailTitle": "プロセス上位20件",
    "top20Cpu": "CPU 上位20件",
    "top20Ram": "RAM 上位20件",
    "top20Swap": "Swap 使用量 上位20件",
    "detailNote": "{s} 秒ごとに更新（ダッシュボードと同じサンプル）。",
    "footerSetting": "フッター",
    "showFooter": "ソースコードとサポートのリンクを表示",
    "footerSource": "ソースコードとサポート：",
    "footerBuyMe": "奢ってください",
    "footerCoffee": "コーヒー",
    "footerTokens": "tokens",
    "done": "完了",
    "healthDisclaimer": "取得可能な指標と設定済みチェックに基づく目安であり、完全な診断ではありません。",
    "healthy": "正常",
    "healthWarn": "注意",
    "healthCritical": "重大",
    "healthNeedsAttention": "しきい値またはチェック項目の確認が必要です。",
    "healthAllClear": "監視中の項目に現在の警告はありません。",
    "swapIdle": "スワップは使用されていますが、現在の入出力は検出されません。",
    "inodes": "inode",
    "diskBusy": "ディスク稼働率",
    "linkSpeed": "リンク",
    "networkErrorRate": "エラー/秒",
    "networkErrors": "新しいネットワークエラーまたはパケット損失",
    "fullStall": "完全停止",
    "tagline": "軽量Linux監視ダッシュボード",
    "connecting": "接続中…",
    "online": "ライブ",
    "offline": "切断",
    "host": "ホスト",
    "updated": "更新",
    "cpu": "CPU使用率",
    "memory": "メモリ",
    "disk": "ディスク",
    "uptime": "稼働時間",
    "activity": "リアルタイム",
    "cpuGraph": "CPU · 過去3分",
    "memoryGraph": "RAM · 過去3分",
    "historyNote": "グラフはこのタブ内でのみ保存されます。",
    "system": "システム",
    "storage": "ストレージ",
    "network": "ネットワーク",
    "services": "サービス",
    "hardware": "ハードウェアとセンサー",
    "footer": "単一ファイル。依存関係なし。読み取り専用監視。",
    "os": "OS",
    "kernel": "カーネル",
    "architecture": "アーキテクチャ",
    "cpuModel": "プロセッサ",
    "cores": "論理コア",
    "load": "ロードアベレージ",
    "php": "PHP",
    "swap": "スワップ",
    "used": "使用",
    "free": "空き",
    "unknown": "利用不可",
    "none": "データなし",
    "onlineService": "稼働",
    "offlineService": "停止",
    "rx": "受信",
    "tx": "送信",
    "refreshError": "サーバーの情報を取得できません。",
    "seconds": "秒",
    "days": "日",
    "hours": "時間",
    "minutes": "分",
    "temperature": "温度",
    "refresh": "更新",
    "language": "言語",
    "swapGraph": "スワップ · 過去3分",
    "networkGraph": "ネットワーク通信量",
    "diskGraph": "ディスク I/O",
    "perCore": "CPUコア別使用率",
    "read": "読み取り",
    "write": "書き込み",
    "diskIo": "ディスクの動作",
    "diskIoNote": "速度は連続する計測値から算出します。階層化デバイスの重複加算は避けています。",
    "mergedMountNote": "同じファイルシステムのマウントはまとめて表示します。",
    "extraMounts": "その他のマウントポイント",
    "swapActivity": "スワップ動作",
    "swapIn": "スワップイン",
    "swapOut": "スワップアウト",
    "pagesPerSecond": "ページ/秒",
    "swapDisabled": "未設定",
    "cached": "キャッシュメモリ",
    "physical": "物理",
    "vpn": "VPN",
    "virtual": "仮想",
    "loopback": "ループバック",
    "secondaryInterfaces": "仮想・補助インターフェース",
    "networkNote": "VPN の「有効」はインターフェースが有効という意味で、接続やハンドシェイクの成功は保証しません。",
    "rxErrors": "受信エラー",
    "txErrors": "送信エラー",
    "dropped": "破棄パケット",
    "pressure": "システム負荷 (PSI)",
    "pressureCpu": "CPU",
    "pressureMemory": "メモリ",
    "pressureIo": "I/O",
    "pressureNote": "リソース待ち時間の割合（10秒平均、PSI）。",
    "tcpNote": "TCP接続確認のみ。HTTPの内容は確認しません。",
    "estimating": "計算中…",
    "enabledState": "有効",
    "upState": "稼働",
    "downState": "停止",
    "unknownState": "不明",
    "dormantState": "休止",
    "lowerlayerdownState": "下位リンク停止",
    "testingState": "テスト中",
    "notpresentState": "存在しない",
    "noDevices": "対応するブロックデバイスを検出できません。",
    "core": "コア",
    "available": "利用可能"
  }
};

// =============================================================
// 20. CLIENT STATE AND PREFERENCES
// =============================================================
const $ = (id) => document.getElementById(id);
const VIEWS = ['overview', 'system', 'network', 'hardware', 'processes'];
const VIEW_LABELS = {overview:'viewOverview', system:'viewSystem', network:'viewNetwork', hardware:'viewHardware', processes:'viewProcesses'};
let currentView = VIEWS.includes(document.documentElement.dataset.view) ? document.documentElement.dataset.view : 'overview';
// Panels of each page; on the overview, the order and visibility can be customized.
const pageGroups = {
  system: {left:['system', 'failed'], right:['php', 'pressure']},
  network: {left:['network', 'connections', 'ports'], right:['webtraffic', 'apache', 'services', 'http']},
  hardware: {left:['hardware'], right:['storage']},
  processes: {left:[], right:[]},
};
const PROCESS_REFRESH_SECONDS = <?= (int) ESM_PROCESS_CACHE_SECONDS ?>;
const BACKGROUND_REFRESH_SECONDS = <?= max(0, (int) ESM_BACKGROUND_REFRESH_SECONDS) ?>;
const PAGE_TITLE = document.title;
const APP_TITLE = <?= json_encode(ESM_TITLE, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
const styles = ['auto', 'operations', 'pro', 'zen'];
const HISTORY_LIMIT = 600;

function setting(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function saveSetting(key, value) {
  try { localStorage.setItem(key, value); } catch {  }
}

const savedLanguage = setting('esmLang');
const browserLanguage = (navigator.language || 'en').slice(0, 2).toLowerCase();
let lang = words[savedLanguage] ? savedLanguage : (words[browserLanguage] ? browserLanguage : 'en');
let visualStyle = styles.includes(setting('mmsStyle')) ? setting('mmsStyle') : 'operations';
let showFooter = setting('mmsShowFooter') !== '0';

const chartKeys = {cpu:'cpuGraph',ram:'memoryGraph',swap:'swapGraph',net:'networkGraph',io:'diskGraph'};
const panelGroups = {
  left:['activity'],
  right:['checks','processes'],
};
const panelLabels = {activity:'activity', processes:'processes', checks:'checksPanel'};
const allPanels = ['activity','processes','checks','storage','services','system','php','failed','ports','network','http','hardware','pressure','connections','webtraffic','apache'];
function jsonSetting(key, fallback) {
  try { const value = JSON.parse(setting(key)); return value ?? fallback; }
  catch { return fallback; }
}
function validChoice(value, values, fallback) {
  const numeric = Number(value);
  return values.includes(numeric) ? numeric : fallback;
}
let refreshSeconds = validChoice(setting('esm32Refresh'), [2,3,5,10,30,60], <?= (int) $refresh ?>);
let graphMinutes = validChoice(setting('esm32Period'), [1,3,10], 3);
const thresholds = {
  cpu:validChoice(setting('esm32WarnCpu'), Array.from({length:46},(_,i)=>i+50), 85),
  ram:validChoice(setting('esm32WarnRam'), Array.from({length:46},(_,i)=>i+50), 85),
  disk:validChoice(setting('esm32WarnDisk'), Array.from({length:46},(_,i)=>i+50), 85),
};
let hiddenPanels = new Set((Array.isArray(jsonSetting('esm32HiddenPanels', []))
  ? jsonSetting('esm32HiddenPanels', []) : []).filter(id => panelLabels[id]));
let hiddenCharts = new Set((Array.isArray(jsonSetting('esm32HiddenCharts', []))
  ? jsonSetting('esm32HiddenCharts', []) : []).filter(id => chartKeys[id]));
const storedOrder = jsonSetting('esm32Order', {});
let panelOrder = {};
for (const side of Object.keys(panelGroups)) {
  const desired = Array.isArray(storedOrder?.[side]) ? storedOrder[side] : [];
  panelOrder[side] = [...new Set([...desired.filter(id => panelGroups[side].includes(id)), ...panelGroups[side]])];
}


const state = {
  latest: null,
  previous: null,
  busy: false,
  connected: false,
  errorDetail: '',
  failures: 0,
  retryAt: 0,
  lastSuccess: 0,
  health: {severity: 0, count: 0},
  active: !document.hidden,
  rates: {
    cpu: null, cores: [], network: {}, disk: {},
    swapIn: null, swapOut: null, processCpu:{},
    netRx: null, netTx: null, diskRead: null, diskWrite: null,
  },
  history: {
    cpu: [], ram: [], swap: [], netRx: [], netTx: [], diskRead: [], diskWrite: [],
  },
  historyTimes:[],
};

function t(key) {
  return words[lang]?.[key] ?? words.en[key] ?? key;
}
function localeColon() {
  return lang === 'fr' ? '\u202f: ' : (['ja','zh'].includes(lang) ? '：' : ': ');
}
function setText(id, value) {
  $(id).textContent = value == null ? '—' : String(value);
}
function number(value, digits = 1) {
  if (value == null || !Number.isFinite(Number(value))) return t('unknown');
  return new Intl.NumberFormat(lang, { maximumFractionDigits: digits }).format(value);
}
function percentage(used, total) {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return null;
  return Math.max(0, Math.min(100, 100 * used / total));
}
function pct(value) {
  return value == null || !Number.isFinite(value) ? '—' : number(value) + '%';
}
function bytes(value) {
  if (value == null || !Number.isFinite(value)) return t('unknown');
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let current = value;
  let i = 0;
  while (Math.abs(current) >= 1024 && i < units.length - 1) {
    current /= 1024;
    i++;
  }
  return number(current) + ' ' + units[i];
}
function speed(value) {
  return value == null || !Number.isFinite(value) ? '—' : bytes(value) + '/s';
}
function duration(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return '—';
  const n = Math.max(0, Math.floor(seconds));
  const d = Math.floor(n / 86400);
  const h = Math.floor((n % 86400) / 3600);
  const m = Math.floor((n % 3600) / 60);
  return [
    d ? d + t('days') : '',
    h ? h + t('hours') : '',
    m ? m + t('minutes') : '',
    d === 0 && h === 0 && m === 0 ? n + t('seconds') : '',
  ].filter(Boolean).join(' ');
}
function node(tag, className = '', value = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value != null) element.textContent = String(value);
  return element;
}
function row(label, value) {
  const element = node('div', 'r');
  element.append(
    node('span', 'label', label),
    node('span', 'value', value ?? t('unknown')),
  );
  return element;
}
function empty(element, message = t('none')) {
  element.replaceChildren(node('p', 'empty', message));
}
function makeBar(value) {
  const track = node('div', 'progress');
  const fill = node('i');
  fill.style.width = (value ?? 0) + '%';
  if (value >= 90) fill.className = 'bad';
  else if (value >= 75) fill.className = 'warn';
  track.append(fill);
  return track;
}
function updateBar(id, value, threshold = 85) {
  const fill = $(id);
  fill.style.width = (value ?? 0) + '%';
  fill.className = value >= Math.min(99, threshold + 10) ? 'bad' : value >= threshold ? 'warn' : '';
}
function appendHistory(key, value) {
  state.history[key].push(Number.isFinite(value) ? value : null);
  if (state.history[key].length > HISTORY_LIMIT) state.history[key].shift();
}
// The charts survive a reload of the page (same tab, less than 15 minutes later).
const HISTORY_KEY = 'mmsHistory:' + location.pathname;
function saveHistory() {
  try {
    const round = value => Number.isFinite(value) ? Math.round(value * 100) / 100 : null;
    const history = {};
    for (const [key, values] of Object.entries(state.history)) history[key] = values.map(round);
    sessionStorage.setItem(HISTORY_KEY, JSON.stringify({savedAt: Date.now(), times: state.historyTimes, history}));
  } catch {  }
}
function restoreHistory() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(HISTORY_KEY));
    const times = saved?.times;
    if (!Array.isArray(times) || !times.length || !(Date.now() - saved.savedAt < 15 * 60000)) return;
    const keys = Object.keys(state.history);
    if (!keys.every(key => Array.isArray(saved.history?.[key]) && saved.history[key].length === times.length)) return;
    state.historyTimes = times.map(Number).slice(-HISTORY_LIMIT);
    for (const key of keys) state.history[key] = saved.history[key].map(value => Number.isFinite(value) ? value : null).slice(-HISTORY_LIMIT);
  } catch {  }
}
window.addEventListener('pagehide', saveHistory);
// True while the user is selecting text in a panel: redrawing it would drop the selection.
function userIsSelecting() {
  const selection = window.getSelection?.();
  if (!selection || selection.isCollapsed || !selection.rangeCount) return false;
  const anchor = selection.anchorNode;
  const element = anchor?.nodeType === 1 ? anchor : anchor?.parentElement;
  return Boolean(element?.closest?.('.dashboard, .process-view'));
}

// =============================================================
// 21. LIVE METRIC CALCULATIONS
// =============================================================
function cpuUsage(current, previous) {
  if (!current || !previous || current.total == null || previous.total == null) return null;
  const deltaTotal = current.total - previous.total;
  const deltaIdle = current.idle - previous.idle;
  if (deltaTotal <= 0 || deltaIdle < 0) return null;
  return Math.max(0, Math.min(100, 100 * (deltaTotal - deltaIdle) / deltaTotal));
}
function counterRate(current, previous, seconds) {
  if (!Number.isFinite(current) || !Number.isFinite(previous) || seconds <= 0 || current < previous) return null;
  return (current - previous) / seconds;
}
function selectChartDevices(items) {
  const physical = items.filter(item => !item.virtual);
  return physical.length ? physical : items;
}
function aggregateRates(items, map, rxKey, txKey) {
  let rx = 0;
  let tx = 0;
  let count = 0;
  for (const item of items) {
    const rate = map[item.name];
    if (rate && Number.isFinite(rate[rxKey]) && Number.isFinite(rate[txKey])) {
      rx += rate[rxKey];
      tx += rate[txKey];
      count++;
    }
  }
  return count ? [rx, tx] : [null, null];
}

function calculateRates(data) {
  const previous = state.previous;
  const currentMs = Number(data.sampleTimeMs);
  const elapsed = previous ? (currentMs - Number(previous.sampleTimeMs)) / 1000 : 0;
  const validDelta = elapsed >= 0.8 && elapsed <= Math.max(90, refreshSeconds * 5);
  const rates = {
    cpu: validDelta ? cpuUsage(data.cpu, previous?.cpu) : null,
    cores: [], network: {}, disk: {},
    swapIn: null, swapOut: null, processCpu:{},
    netRx: null, netTx: null, diskRead: null, diskWrite: null,
  };
  const oldCores = new Map((previous?.cpu?.cores || []).map(item => [item.id, item]));
  rates.cores = (data.cpu?.cores || []).map(item => ({
    id: item.id,
    usage: validDelta ? cpuUsage(item, oldCores.get(item.id)) : null,
  }));
  const oldNet = new Map((previous?.network || []).map(item => [item.name, item]));
  for (const item of data.network || []) {
    const old = oldNet.get(item.name);
    rates.network[item.name] = {
      rx: validDelta ? counterRate(item.rx, old?.rx, elapsed) : null,
      tx: validDelta ? counterRate(item.tx, old?.tx, elapsed) : null,
      rxErrors: validDelta ? counterRate(item.rxErrors, old?.rxErrors, elapsed) : null,
      txErrors: validDelta ? counterRate(item.txErrors, old?.txErrors, elapsed) : null,
      dropped: validDelta ? counterRate(item.rxDropped + item.txDropped,
        old ? old.rxDropped + old.txDropped : null, elapsed) : null,
    };
  }
  const oldDisk = new Map((previous?.diskIo || []).map(item => [item.name, item]));
  for (const item of data.diskIo || []) {
    const old = oldDisk.get(item.name);
    rates.disk[item.name] = {
      read: validDelta ? counterRate(item.readBytes, old?.readBytes, elapsed) : null,
      write: validDelta ? counterRate(item.writeBytes, old?.writeBytes, elapsed) : null,
      busy: validDelta ? Math.min(100, Math.max(0, counterRate(item.busyMs, old?.busyMs, elapsed) / 10)) : null,
      readOps: validDelta ? counterRate(item.readOps, old?.readOps, elapsed) : null,
      writeOps: validDelta ? counterRate(item.writeOps, old?.writeOps, elapsed) : null,
    };
  }
  const newSwap = data.memory?.swapActivity;
  const oldSwap = previous?.memory?.swapActivity;
  if (validDelta && newSwap && oldSwap) {
    rates.swapIn = counterRate(newSwap.pageIn, oldSwap.pageIn, elapsed);
    rates.swapOut = counterRate(newSwap.pageOut, oldSwap.pageOut, elapsed);
  }

  for (const proc of data.processes?.items || []) {
    if (Number.isFinite(proc.cpuPercent)) rates.processCpu[proc.pid] = proc.cpuPercent;
  }

  const interfaces = data.network || [];
  const physical = interfaces.filter(item => item.category === 'physical');
  const vpn = interfaces.filter(item => item.category === 'vpn');
  const fallback = interfaces.filter(item => item.category !== 'loopback');
  [rates.netRx, rates.netTx] = aggregateRates(
    physical.length ? physical : (vpn.length ? vpn : fallback),
    rates.network, 'rx', 'tx'
  );
  [rates.diskRead, rates.diskWrite] = aggregateRates(
    selectChartDevices(data.diskIo || []), rates.disk, 'read', 'write'
  );
  return rates;
}

// =============================================================
// 22. NATIVE SVG CHARTS
// =============================================================
const chartData = Object.create(null);
const svgNS = 'http://www.w3.org/2000/svg';
const chartTip = $('chartTooltip');
let activeChart = null;
function svgEl(tag, attrs = {}) {
  const element = document.createElementNS(svgNS, tag);
  for (const [key,value] of Object.entries(attrs)) element.setAttribute(key,String(value));
  return element;
}
function chartSampleText(data, index) {
  const count = Math.max(0,...data.series.map(values => values.length));
  if (!count) return '';
  const sample = Math.max(0,Math.min(count-1,index));
  const sampleTime = data.times[sample];
  const time = sampleTime ? new Date(sampleTime).toLocaleTimeString(lang) : '';
  const names = data.key === 'io' ? ['read','write'] : ['rx','tx'];
  const values = data.series.map((samples, i) => {
    const value = samples[sample];
    if (!Number.isFinite(value)) return null;
    const prefix = data.series.length > 1 ? t(names[i] || names[0]) + localeColon() : '';
    return prefix + (data.scale === 'auto' ? speed(value) : pct(value));
  }).filter(Boolean);
  return [time,...values].filter(Boolean).join(' · ');
}
function showChartSample(id, index, pointer = null) {
  const data = chartData[id];
  if (!data) return;
  const count = Math.max(0,...data.series.map(values => values.length));
  if (!count) { hideChartTip(); return; }
  const sample = Math.max(0,Math.min(count-1,index));
  data.hit.dataset.point = String(sample);
  data.hit.setAttribute('aria-valuenow',String(sample));
  data.hit.setAttribute('aria-valuetext',chartSampleText(data,sample));
  data.hit.setAttribute('aria-label',(data.label || id) + ' · ' + chartSampleText(data,sample));
  const x = data.xs?.[sample] ?? (count === 1 ? 200 : sample * 400 / (count-1));
  data.guide.setAttribute('x1',String(x));
  data.guide.setAttribute('x2',String(x));
  data.guide.style.display = '';
  chartTip.textContent = chartSampleText(data,sample);
  if (!chartTip.textContent) return;
  if (chartTip.parentElement !== (data.svg.closest('dialog[open]') || document.body)) {
    (data.svg.closest('dialog[open]') || document.body).append(chartTip);
  }
  chartTip.hidden = false;
  activeChart = id;
  const rect = data.svg.getBoundingClientRect();
  const anchoredPointer = pointer || data.lastPointer;
  const px = anchoredPointer ? anchoredPointer.clientX : rect.left + x/400*rect.width;
  const py = anchoredPointer ? anchoredPointer.clientY : rect.top + rect.height*0.5;
  const w = chartTip.offsetWidth || 180;
  const h = chartTip.offsetHeight || 35;
  chartTip.style.left = Math.max(8,Math.min(window.innerWidth-w-8,px+12))+'px';
  chartTip.style.top = Math.max(8,Math.min(window.innerHeight-h-8,py-h-14))+'px';
}
function hideChartTip(id = null) {
  if (id && activeChart !== id) return;
  chartTip.hidden = true;
  if (activeChart && chartData[activeChart]) chartData[activeChart].guide.style.display = 'none';
  activeChart = null;
}
const CHART_TOP = 8, CHART_BOTTOM = 96;
function chartY(value, max) {
  return CHART_BOTTOM - Math.max(0, Math.min(1, value / max)) * (CHART_BOTTOM - CHART_TOP);
}
function chartWindow(times) {
  const end = times.length ? times[times.length - 1] : Date.now();
  const span = graphMinutes * 60000;
  return {start: end - span, span};
}
function chartX(time, win) {
  return Math.max(0, Math.min(400, (time - win.start) / win.span * 400));
}
function agoLabel(seconds) {
  const minutes = Math.floor(seconds / 60), rest = Math.round(seconds % 60);
  if (!minutes) return `-${rest} s`;
  return rest ? `-${minutes} min ${rest} s` : `-${minutes} min`;
}
function chartThreshold(key) {
  return key === 'cpu' ? thresholds.cpu : key === 'ram' ? thresholds.ram : null;
}
function chartHeadline(target, series, key) {
  if (!target) return;
  const formatter = ['net','io'].includes(key) ? speed : pct;
  const last = values => { const finite = values.filter(Number.isFinite); return finite.length ? finite[finite.length-1] : null; };
  const peak = values => { const finite = values.filter(Number.isFinite); return finite.length ? Math.max(...finite) : null; };
  const show = value => value == null ? '—' : formatter(value);
  target.replaceChildren();
  if (series.length === 1) {
    target.append(node('strong','',show(last(series[0]))), node('span','chart-peak',`${t('maxValue')} ${show(peak(series[0]))}`));
    return;
  }
  series.forEach((values, index) => {
    const pair = node('span','chart-pair' + (index ? ' second' : ''));
    pair.append(node('i'), document.createTextNode(index ? '↑ ' : '↓ '), node('strong','',show(last(values))));
    target.append(pair);
  });
  target.append(node('span','chart-peak',`${t('maxValue')} ↓ ${show(peak(series[0]))} · ↑ ${show(peak(series[1]))}`));
}
function plot(id, series, scale = 100, key = 'cpu', threshold = null) {
  const svg = $(id);
  let data = chartData[id];
  if (!data) {
    const drawing = svgEl('g');
    const guide = svgEl('line',{x1:0,x2:0,y1:0,y2:100,stroke:'var(--accent)','stroke-width':1.5,'stroke-dasharray':'3 3','vector-effect':'non-scaling-stroke'});
    guide.style.display = 'none';
    const hit = svgEl('rect',{x:0,y:0,width:400,height:100,fill:'transparent',tabindex:0,role:'slider','aria-valuemin':0,'aria-valuemax':100});
    hit.addEventListener('pointermove',event => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width) return;
      const n = Math.max(0,...(chartData[id]?.series || []).map(v=>v.length));
      if (!n) return;
      chartData[id].lastPointer = {clientX:event.clientX,clientY:event.clientY};
      const target = Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width)) * 400;
      const xs = chartData[id].xs || [];
      let nearest = n - 1, distance = Infinity;
      xs.forEach((x, i) => { const d = Math.abs(x - target); if (d < distance) { distance = d; nearest = i; } });
      showChartSample(id,nearest,event);
    });
    hit.addEventListener('pointerleave',()=>{chartData[id].lastPointer=null;hideChartTip(id);});
    hit.addEventListener('focus',()=> {
      chartData[id].lastPointer=null;
      const n = Math.max(0,...(chartData[id]?.series || []).map(v=>v.length));
      showChartSample(id,Number(hit.dataset.point ?? n-1));
    });
    hit.addEventListener('blur',()=>{chartData[id].lastPointer=null;hideChartTip(id);});
    hit.addEventListener('keydown',event=> {
      if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
      event.preventDefault();
      const n = Math.max(0,...(chartData[id]?.series || []).map(v=>v.length));
      let index = Number(hit.dataset.point ?? n-1);
      if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = n-1;
      else index += event.key === 'ArrowRight' ? 1 : -1;
      showChartSample(id,index);
    });
    svg.append(drawing,guide,hit);
    const overlay = node('div','chart-overlay');
    svg.parentElement.append(overlay);
    data = chartData[id] = {svg,drawing,guide,hit,overlay,lastPointer:null};
  }
  const count = Math.max(0,...series.map(values=>values.length));
  data.series = series;
  data.scale = scale;
  data.key = key;
  data.label = svg.getAttribute('aria-label') || key;
  data.times = state.historyTimes.slice(-count);
  data.hit.setAttribute('aria-valuemax',String(Math.max(0,count-1)));
  if (Number(data.hit.dataset.point) >= count) data.hit.dataset.point = String(Math.max(0,count-1));
  data.drawing.replaceChildren();
  data.overlay.replaceChildren();
  const valid = series.flat().filter(v=>Number.isFinite(v));
  const max = scale === 'auto' ? Math.max(1,...valid)*1.12 : scale;
  // Horizontal position = real sample time inside the selected period, so the time axis is exact
  // (a young history only fills the right side; a pause, e.g. a hidden tab, leaves a gap).
  const win = chartWindow(data.times);
  const xs = data.times.map(time => chartX(time, win));
  data.xs = xs;
  const expected = refreshSeconds * 1000;
  // Background tabs are refreshed slowly (and browsers may slow them down to once a minute).
  const allowed = Math.max(3 * expected, expected + 4000, BACKGROUND_REFRESH_SECONDS > 0 ? Math.max(BACKGROUND_REFRESH_SECONDS * 2000, 65000) : 0);
  const gap = i => i > 0 && data.times[i] - data.times[i-1] > allowed;
  for (const fraction of [.25,.5,.75]) {
    const y = chartY(fraction * max, max);
    data.drawing.append(svgEl('line',{x1:0,x2:400,y1:y,y2:y,stroke:'currentColor',opacity:'.1','vector-effect':'non-scaling-stroke'}));
  }
  data.overlay.append(node('span','chart-scale',valid.length ? (scale === 'auto' ? speed(max) : '100 %') : ''));
  if (Number.isFinite(threshold) && scale !== 'auto') {
    // Same projection as the curve: the line stays right whatever the vertical scale.
    const y = chartY(threshold, max);
    data.drawing.append(svgEl('line',{x1:0,x2:400,y1:y,y2:y,class:'chart-threshold-line','stroke-width':1.3,'stroke-dasharray':'5 4','vector-effect':'non-scaling-stroke'}));
    const label = node('span','chart-threshold',`${t('threshold')} ${number(threshold,0)} %`);
    label.style.top = y + '%';
    data.overlay.append(label);
  }
  series.forEach((values,index)=> {
    const color = index === 0 ? 'var(--accent)' : 'var(--good)';
    const segments = [];
    let current = [];
    values.forEach((value,i)=> {
      if (!Number.isFinite(value) || gap(i)) { if (current.length) segments.push(current); current = []; }
      if (Number.isFinite(value)) current.push([xs[i] ?? 400, chartY(value, max)]);
    });
    if (current.length) segments.push(current);
    for (const points of segments) {
      if (points.length === 1) continue;
      const line = points.map(([x,y],k) => (k ? 'L ' : 'M ') + x.toFixed(1) + ' ' + y.toFixed(1)).join(' ');
      const area = line + ` L ${points.at(-1)[0].toFixed(1)} ${CHART_BOTTOM} L ${points[0][0].toFixed(1)} ${CHART_BOTTOM} Z`;
      data.drawing.append(svgEl('path',{d:area,fill:color,opacity:index === 0 ? '.13' : '.09',stroke:'none'}));
      data.drawing.append(svgEl('path',{d:line,fill:'none',stroke:color,'stroke-width':2.2,'stroke-linejoin':'round','vector-effect':'non-scaling-stroke'}));
    }
    // Latest measurement: an HTML dot, so it stays round although the SVG is stretched.
    const lastIndex = values.findLastIndex(value => Number.isFinite(value));
    if (lastIndex >= 0) {
      const dot = node('span', 'chart-dot' + (index ? ' second' : ''));
      dot.style.left = ((xs[lastIndex] ?? 400) / 4) + '%';
      dot.style.top = chartY(values[lastIndex], max) + '%';
      data.overlay.append(dot);
    }
  });
  const axis = data.svg.parentElement.nextElementSibling;
  if (axis?.classList.contains('chart-axis')) {
    const span = graphMinutes * 60;
    axis.replaceChildren(node('span','',agoLabel(span)), node('span','',agoLabel(span / 2)), node('span','',t('axisNow')));
  }
  if (activeChart===id && !chartTip.hidden) showChartSample(id,Number(data.hit.dataset.point ?? count-1),data.lastPointer);
}
function visibleSeries(key) {
  const times = state.historyTimes;
  const cutoff = (times[times.length-1] || Date.now()) - graphMinutes * 60000;
  const start = Math.max(0, times.findIndex(value => value >= cutoff));
  return state.history[key].slice(start);
}
function seriesForChart(key) {
  if (key === 'net') return [visibleSeries('netRx'), visibleSeries('netTx')];
  if (key === 'io') return [visibleSeries('diskRead'), visibleSeries('diskWrite')];
  return [visibleSeries(key)];
}
function renderZoom() {
  if (!$('chartDialog').open) return;
  const key = $('chartDialog').dataset.chart;
  if (!chartKeys[key]) return;
  const label = ['cpu','ram','swap'].includes(key) ? t(chartKeys[key]).replace('3', graphMinutes) : t(chartKeys[key]);
  setText('zoomTitle', label);
  $('zoomChart').setAttribute('aria-label', label);
  const series = seriesForChart(key);
  plot('zoomChart', series, ['net','io'].includes(key) ? 'auto' : 100, key, chartThreshold(key));
  chartHeadline($('zoomStats'), series, key);
}
function renderCharts() {
  for (const [key,id] of Object.entries({cpu:'cpuChart',ram:'ramChart',swap:'swapChart',net:'netChart',io:'ioChart'})) {
    const series = seriesForChart(key);
    plot(id, series, ['net','io'].includes(key) ? 'auto' : 100, key, chartThreshold(key));
    chartHeadline($(key + 'Stats'), series, key);
  }
  renderZoom();
}
function updateChartTitles() {
  for (const key of ['cpu','ram','swap']) {
    const label = document.querySelector(`[data-chart-card="${key}"] .chart-label`);
    if (label) label.textContent = t(chartKeys[key]).replace('3', graphMinutes);
  }
}


// =============================================================
// 23. DIAGNOSTICS AND HEALTH
// =============================================================
function processLists(data, limit) {
  const processes = data.processes?.items || [];
  return {
    all: processes,
    cpu: processes.filter(proc => Number.isFinite(proc.cpuPercent))
      .sort((a,b) => b.cpuPercent - a.cpuPercent).slice(0,limit),
    ram: processes.filter(proc => Number.isFinite(proc.rssBytes))
      .sort((a,b) => b.rssBytes - a.rssBytes).slice(0,limit),
    swap: processes.filter(proc => Number.isFinite(proc.swapBytes) && proc.swapBytes > 0)
      .sort((a,b) => b.swapBytes - a.swapBytes).slice(0,limit),
  };
}
function fillProcessList(id, list, kind, processes, ranked = false) {
    const target = $(id);
    target.replaceChildren();
    if (!list.length) {
      empty(target, !processes.length ? t('noProcess') : kind === 'swap' ? t('noSwapProcess') : t('estimating'));
      return;
    }
    list.forEach((proc, index) => {
      const item = node(ranked ? 'li' : 'div','process-item');
      if (ranked) item.append(node('span','process-rank',String(index + 1)));
      const left = node('div');
      const name = node('div','process-name',proc.name || '—');
      name.title = proc.name || '';
      const memoryDetail = kind === 'ram' && Number.isFinite(proc.pssBytes)
        ? ' · ' + t('processPss') + ' ' + bytes(proc.pssBytes) : '';
      const poolDetail = proc.detail ? ' · ' + proc.detail : '';
      left.append(name, node('div','process-detail',`PID ${proc.pid}${poolDetail}${memoryDetail}`));
      const value = kind === 'cpu' ? pct(proc.cpuPercent) : bytes(kind === 'swap' ? proc.swapBytes : proc.rssBytes);
      item.append(left,node('strong','process-value',value));
      target.append(item);
    });
}
function renderProcesses(data) {
  const {all: processes, cpu, ram, swap} = processLists(data, 5);
  fillProcessList('processCpuList',cpu,'cpu',processes);
  fillProcessList('processRamList',ram,'ram',processes);
  fillProcessList('processSwapList',swap,'swap',processes);
  $('collaboraNote').hidden = !processes.some(proc => /^(?:forkit|kit_spare(?:_.*)?)$/i.test(proc.name || ''));
  $('processHelpCluster').querySelector('[data-help]').dataset.help = (data.processes?.partial ? 'processPartial' : 'processNote') + ',ramFormula,pssExplanation,swapProcessExplanation';
}
function renderProcessDetail(data) {
  const {all: processes, cpu, ram, swap} = processLists(data, Number(data.limit) || 20);
  fillProcessList('detailCpuList',cpu,'cpu',processes,true);
  fillProcessList('detailRamList',ram,'ram',processes,true);
  fillProcessList('detailSwapList',swap,'swap',processes,true);
  setText('detailNote', t('detailNote').replace('{s}', String(PROCESS_REFRESH_SECONDS)));
  $('detailHelpCluster').querySelector('[data-help]').dataset.help = (data.processes?.partial ? 'processPartial' : 'processNote') + ',ramFormula,pssExplanation,swapProcessExplanation';
}
function renderHttp(data) {
  const target = $('httpList');
  target.replaceChildren();
  const checks = data.httpChecks || [];
  if (!checks.length) { empty(target, t('noHttpChecks')); return; }
  for (const check of checks) {
    const item = node('div','item');
    const status = check.online === null ? '' : (check.online ? 'up' : 'down');
    const head = node('div','meter-row');
    const label = check.online === null ? t('httpPending') : check.online ? t('onlineService')
      : (check.reachable ? t('httpFailure') : t('offlineService'));
    head.append(node('strong','',check.self ? t('selfCheck') : check.name),node('span','pill '+status,label));
    const statusCode = check.httpStatus ? ' · HTTP ' + check.httpStatus : '';
    const latency = check.latencyMs != null ? ' · ' + number(check.latencyMs) + ' ms' : '';
    const publicUrl = check.self ? location.origin + location.pathname : check.endpoint;
    item.append(head,node('div','smalltext', publicUrl + statusCode + latency));
    if (check.self && !check.online) item.append(node('div','smalltext',t('selfCheckExplanation')));
    if (Number.isFinite(check.checkedAt)) {
      const time = new Date(check.checkedAt * 1000).toLocaleTimeString(lang);
      item.append(node('div','smalltext',t('lastCheck') + localeColon() + time
        + (check.stale ? ' · ' + t('staleResult') : '')));
    }
    if (check.tls) {
      const message = check.tlsDays === null ? t('tlsUnavailable')
        : check.tlsDays < 0 ? `${t('tlsExpired')}${localeColon()}${check.tlsExpiry}`
        : `${t('tlsExpires')}${localeColon()}${number(check.tlsDays,0)} ${t('days')} (${check.tlsExpiry})`;
      const div = node('div','smalltext',message);
      if (check.tlsDays !== null && check.tlsDays < 14) div.style.color = check.tlsDays < 0 ? 'var(--bad)' : 'var(--warn)';
      item.append(div);
    }
    if (check.error) item.append(node('div','smalltext',t(check.error)));
    target.append(item);
  }
}
// Text of an alert computed by the server: a text key, {placeholders} and an optional detail.
function alertText(alert) {
  const args = alert.args && !Array.isArray(alert.args) ? alert.args : {};
  let text = t(alert.key);
  for (const [name, value] of Object.entries(args)) {
    if (name !== 'detail') text = text.replaceAll('{' + name + '}', String(value));
  }
  return args.detail ? text + localeColon() + args.detail : text;
}
const HEALTH_VISIBLE = 6;
let healthExpanded = false;
function renderHealth(data) {
  const warnings = [];
  const add = (level, reason, view = null) => warnings.push({level, reason, view});
  // Thresholds chosen in the settings of this page.
  function usage(value, threshold, label, view) {
    if (value === null || !Number.isFinite(value) || value < threshold) return;
    add(value >= Math.min(99, threshold + 10) ? 2 : 1, `${label}${localeColon()}${pct(value)}`, view);
  }
  usage(state.rates.cpu, thresholds.cpu, t('cpu'), 'processes');
  const ram = data.memory?.ram;
  usage(ram ? percentage(ram.used, ram.total) : null, thresholds.ram, t('memory'), 'processes');
  for (const disk of data.disks || []) {
    usage(percentage(disk.used, disk.total), thresholds.disk, disk.mount, 'hardware');
    if (disk.inodes) usage(percentage(disk.inodes.used, disk.inodes.total), 90, `${disk.mount} · ${t('inodes')}`, 'hardware');
  }
  // Rates measured between two refreshes of this page.
  const swapping = Math.max(0, state.rates.swapIn || 0) + Math.max(0, state.rates.swapOut || 0);
  if (swapping >= 10) add(swapping >= 100 ? 2 : 1, `${t('swapActivity')}${localeColon()}${number(swapping)} ${t('pagesPerSecond')}`, 'processes');
  for (const link of data.network || []) {
    if (link.category !== 'physical') continue;
    const rate = state.rates.network[link.name];
    if (rate && ((rate.rxErrors || 0)+(rate.txErrors || 0) >= 1 || (rate.dropped || 0) >= 10)) {
      add(1,`${link.name}${localeColon()}${t('networkErrors')}`, 'network');
    }
  }
  // Everything else is evaluated by the server (the same list feeds ?api=health and --check).
  for (const alert of data.alerts || []) {
    add(alert.level === 2 ? 2 : 1, alertText(alert), VIEWS.includes(alert.view) ? alert.view : null);
  }
  warnings.sort((a, b) => b.level - a.level); // critical first; the order is otherwise kept
  const severity = warnings.length ? warnings[0].level : 0;
  state.health = {severity, count: warnings.length};
  const panel = $('healthBanner');
  panel.className = 'health-banner ' + ['ok','warn','bad'][severity];
  setText('healthTitle',t(['healthy','healthWarn','healthCritical'][severity]));
  setText('healthDescription',severity ? t('healthNeedsAttention') : t('healthAllClear'));
  const list = $('healthReasons');
  list.replaceChildren();
  if (warnings.length <= HEALTH_VISIBLE) healthExpanded = false;
  const shown = healthExpanded ? warnings : warnings.slice(0, HEALTH_VISIBLE);
  for (const {level, reason, view} of shown) {
    const item = node('span','health-reason level-' + level);
    item.append(node('i'));
    if (view) {
      const link = node('a','',reason);
      link.href = '?view=' + view;
      link.dataset.viewLink = view;
      item.append(link);
    } else item.append(node('span','',reason));
    list.append(item);
  }
  if (warnings.length > shown.length) {
    const more = node('button','health-more',`+${warnings.length - shown.length}`);
    more.type = 'button';
    more.setAttribute('aria-label', t('showAllAlerts'));
    more.title = t('showAllAlerts');
    more.addEventListener('click', () => { healthExpanded = true; if (state.latest) renderHealth(state.latest); });
    list.append(more);
  }
  const swap = data.memory?.swap;
  if (!warnings.length && swap?.total > 0 && percentage(swap.used,swap.total) >= 50 && swapping < 1) {
    list.append(node('span','',t('swapIdle')));
  }
  updateTitle();
}

// =============================================================
// 24. PANEL RENDERING
// =============================================================
function renderSummary(data) {
  const system = data.system || {};
  const memory = data.memory || {};
  const disks = data.disks || [];
  const root = disks.find(item => item.mount === '/') || disks[0];
  const ram = memory.ram;
  const swap = memory.swap;
  const ramPct = ram ? percentage(ram.used, ram.total) : null;
  const swapPct = swap && swap.total > 0 ? percentage(swap.used, swap.total) : null;
  const diskPct = root ? percentage(root.used, root.total) : null;

  setText('hostName', system.hostname);
  setText('osSummary', system.os);
  setText('updated', system.time ? new Date(system.time).toLocaleTimeString(lang) : '—');

  setText('cpuValue', state.rates.cpu == null ? t('estimating') : pct(state.rates.cpu));
  updateBar('cpuBar', state.rates.cpu, thresholds.cpu);
  setText('cpuExtra', system.load?.length ? `${t('load')}${localeColon()}${system.load.map(v => number(v)).join(' / ')}` : '—');

  setText('ramValue', pct(ramPct));
  updateBar('ramBar', ramPct, thresholds.ram);
  setText('ramExtra', ram ? `${bytes(ram.used)} / ${bytes(ram.total)}` : '—');

  setText('swapValue', swap && swap.total === 0 ? '0 %' : pct(swapPct));
  updateBar('swapBar', swapPct);
  const swapRate = Math.max(0, state.rates.swapIn || 0) + Math.max(0, state.rates.swapOut || 0);
  $('swapBar').className = swapRate >= 100 ? 'bad' : swapRate >= 10 ? 'warn' : '';
  setText('swapExtra', swap && swap.total === 0
    ? t('swapDisabled')
    : swap ? `${bytes(swap.used)} / ${bytes(swap.total)}` : t('unknown'));

  setText('diskValue', pct(diskPct));
  updateBar('diskBar', diskPct, thresholds.disk);
  setText('diskExtra', root ? `${root.mount} · ${bytes(root.used)} / ${bytes(root.total)}` : '—');

  setText('uptimeValue', duration(system.uptimeSeconds));
  setText('uptimeExtra', system.kernel ? 'Linux ' + system.kernel : '—');
}

function renderSystem(data) {
  const s = data.system || {};
  const m = data.memory || {};
  const rows = $('systemRows');
  const swap = m.swap;
  const swapLabel = swap && swap.total === 0
    ? t('swapDisabled')
    : swap ? `${bytes(swap.used)} / ${bytes(swap.total)}` : null;
  rows.replaceChildren(
    row(t('os'), s.os),
    row(t('kernel'), s.kernel),
    row(t('architecture'), s.architecture),
    row(t('php'), s.php),
    row(t('cores'), s.logicalCores),
    row(t('load'), s.load?.length ? s.load.map(v => number(v)).join(' / ') : null),
    row(t('swap'), swapLabel),
    row(t('cached'), m.ram?.cached == null ? null : bytes(m.ram.cached)),
    row(t('swapIn'), speedPages(state.rates.swapIn)),
    row(t('swapOut'), speedPages(state.rates.swapOut)),
    row(t('apiDuration'), data.collectionMs == null ? null : number(data.collectionMs) + ' ms'),
  );
  const kernel = data.kernel || {};
  for (const [key, pair] of [['openFiles', kernel.openFiles], ['conntrack', kernel.conntrack]]) {
    if (!pair) continue;
    // The limit on open files is practically unlimited on many systems: a percentage would mean nothing.
    const share = pair.max < 1e12 ? ` / ${number(pair.max, 0)} (${pct(percentage(pair.used, pair.max))})` : '';
    rows.append(row(t(key), number(pair.used, 0) + share));
  }
  if (Number.isFinite(kernel.oomKills)) {
    const oomRow = row(t('oomKills'), number(kernel.oomKills, 0));
    if (kernel.oomKills > 0) oomRow.querySelector('.value').classList.add('warn-text');
    rows.append(oomRow);
  }
  const reboot = data.reboot || {};
  const reasons = [];
  if ((reboot.reasons || []).includes('kernel')) {
    reasons.push(t('rebootKernel').replace('{k}', reboot.latestKernel || '?').replace('{r}', reboot.runningKernel || '?'));
  }
  if (reboot.packages?.length) reasons.push(t('rebootPackages') + localeColon() + reboot.packages.slice(0, 5).join(', ') + (reboot.packages.length > 5 ? '…' : ''));
  const rebootRow = row(t('rebootRequired'), reboot.required ? t('yes') + (reasons.length ? ' · ' + reasons.join(' · ') : '') : t('rebootNo'));
  if (reboot.required) rebootRow.querySelector('.value').style.color = 'var(--warn)';
  rows.prepend(rebootRow);
}

function renderPhp(data) {
  const php = data.php || {};
  const list = [
    row('PHP', php.version),
    row(t('phpSapi'), php.sapi),
    row(t('memoryLimit'), php.memoryLimit === '-1' ? '∞' : php.memoryLimit),
  ];
  const fpm = php.fpm;
  if (fpm) {
    list.push(row(t('fpmPool'), (fpm.pool || '—') + (fpm.manager ? ` (${fpm.manager})` : '')));
    if (Number.isFinite(fpm.total)) list.push(row(t('fpmWorkers'), `${number(fpm.active, 0)} / ${number(fpm.total, 0)}`));
    if (Number.isFinite(fpm.listenQueue)) {
      const queue = row(t('fpmQueue'), number(fpm.listenQueue, 0));
      if (fpm.listenQueue > 0) queue.querySelector('.value').classList.add('warn-text');
      list.push(queue);
    }
    if (Number.isFinite(fpm.maxChildrenReached)) {
      const reached = row(t('fpmMaxReached'), number(fpm.maxChildrenReached, 0) + ' ×');
      if (fpm.maxChildrenReached > 0) reached.querySelector('.value').classList.add('warn-text');
      list.push(reached);
    }
    if (Number.isFinite(fpm.slowRequests)) list.push(row(t('fpmSlow'), number(fpm.slowRequests, 0)));
  }
  const cache = php.opcache;
  if (cache) {
    const size = (cache.used || 0) + (cache.free || 0) + (cache.wasted || 0);
    const memory = row(t('opcacheMemory'), `${bytes(cache.used)} / ${bytes(size)} (${pct(percentage(cache.used + (cache.wasted || 0), size))})`);
    if (cache.full) memory.querySelector('.value').classList.add('warn-text');
    list.push(memory);
    if (Number.isFinite(cache.hitRate)) list.push(row(t('opcacheHitRate'), pct(cache.hitRate)));
    if (Number.isFinite(cache.scripts)) list.push(row(t('opcacheScripts'), number(cache.scripts, 0)));
  } else list.push(row('OPcache', t('disabledState')));
  $('phpRows').replaceChildren(...list);
}

function renderChecks(data) {
  const target = $('checksList');
  target.replaceChildren();
  const services = data.services || [];
  const checks = data.httpChecks || [];
  if (!services.length && !checks.length) { empty(target, t('noChecks')); return; }
  const add = (name, status, label, detail = '') => {
    const item = node('div', 'check-row');
    const left = node('span', 'check-name', name);
    if (detail) left.append(node('small', '', detail));
    item.append(left, node('span', 'pill ' + status, label));
    target.append(item);
  };
  for (const service of services) add(service.name, service.online ? 'up' : 'down', t(service.online ? 'onlineService' : 'offlineService'));
  for (const check of checks) {
    const status = check.online === null ? '' : (check.online ? 'up' : 'down');
    const label = check.online === null ? t('httpPending') : t(check.online ? 'onlineService' : 'offlineService');
    const tls = !check.tls || !Number.isFinite(check.tlsDays) ? ''
      : check.tlsDays < 0 ? `${t('tlsExpired')}${localeColon()}${check.tlsExpiry}`
      : `${t('tlsExpires')}${localeColon()}${number(check.tlsDays, 0)} ${t('days')}`;
    add(check.self ? t('selfCheck') : check.name, status, label, tls);
  }
}
function renderFailedUnits(data) {
  const target = $('failedList');
  target.replaceChildren();
  const failed = data.failedUnits || {};
  if (!failed.available) { empty(target, t('systemdUnavailable')); return; }
  if (!failed.units?.length) { target.append(node('p', 'ok-message', '✓ ' + t('noFailedUnits'))); return; }
  for (const unit of failed.units) {
    const item = node('div', 'check-row');
    const left = node('span', 'check-name', unit.unit);
    if (unit.description) left.append(node('small', '', unit.description));
    item.append(left, node('span', 'pill down', unit.sub || 'failed'));
    target.append(item);
  }
}
function renderPorts(data) {
  const target = $('portsList');
  target.replaceChildren();
  const ports = data.ports || [];
  if (!ports.length) { empty(target, t('noPorts')); return; }
  for (const entry of ports) {
    const item = node('div', 'check-row');
    const left = node('span', 'check-name');
    left.append(node('strong', '', String(entry.port)), document.createTextNode(entry.service ? ' · ' + entry.service : ''));
    if (entry.sensitive) left.append(node('small', '', t('portSensitive')));
    const scope = entry.scope === 'all' ? t('portScopeAll') : entry.scope === 'local' ? t('portScopeLocal') : entry.address;
    item.append(left, node('span', 'pill ' + (entry.scope === 'local' ? 'up' : entry.sensitive ? 'warn' : ''), scope));
    target.append(item);
  }
}

// ---- Network activity: connections, sessions, web traffic, Apache ----
const expandedTraffic = new Set();
function keptDetails(id, title) {
  const details = node('details', 'details');
  details.open = expandedTraffic.has(id); // redrawn at every refresh: remember what was opened
  details.addEventListener('toggle', () => {
    if (details.open) expandedTraffic.add(id);
    else expandedTraffic.delete(id);
  });
  details.append(node('summary', '', title));
  return details;
}
function trafficRow(title, detail, pillText, pillClass = '', tag = '') {
  const item = node('div', 'check-row traffic-row');
  const left = node('span', 'check-name');
  left.append(node('strong', '', title));
  if (tag) left.append(node('span', 'tag', tag));
  if (detail) left.append(node('small', '', detail));
  item.append(left);
  if (pillText !== null) item.append(node('span', 'pill ' + pillClass, pillText));
  return item;
}
function ago(epochSeconds) {
  return t('agoText').replace('{s}', duration(Math.max(0, Date.now() / 1000 - epochSeconds)));
}
function renderConnections(traffic) {
  const target = $('connectionsList');
  const c = traffic.connections;
  if (!c || !Array.isArray(c.services)) { empty(target); return; }
  const rows = node('div', 'rows');
  rows.append(
    row(t('connIncoming'), `${number(c.incoming, 0)} · ${t('addressCount').replace('{n}', number(c.incomingAddresses, 0))}`),
    row(t('connOutgoing'), number(c.outgoing, 0)),
    row(t('connLocal'), number(c.local, 0)),
  );
  target.replaceChildren(rows, node('h3', 'list-title', t('connByService')));
  if (!c.services.length) target.append(node('p', 'empty', t('connNone')));
  for (const service of c.services) {
    const clients = service.clients.map(client => client.ip + (client.count > 1 ? ' ×' + client.count : '')).join(', ')
      + (service.addresses > service.clients.length ? ', …' : '');
    target.append(trafficRow(service.port + (service.service ? ' · ' + service.service : ''), clients,
      `${number(service.connections, 0)} · ${t('addressCount').replace('{n}', number(service.addresses, 0))}`));
  }
  if (c.destinations.length) {
    const details = keptDetails('outgoing', `${t('connOutgoingList')} (${number(c.outgoingDestinations, 0)})`);
    for (const destination of c.destinations) {
      details.append(trafficRow(destination.ip, destination.port + (destination.service ? ' · ' + destination.service : ''),
        destination.count > 1 ? '×' + destination.count : null));
    }
    target.append(details);
  }
  const sessions = traffic.sessions;
  if (sessions?.available) {
    target.append(node('h3', 'list-title', t('sessionsTitle')));
    if (!sessions.sessions.length) target.append(node('p', 'empty', t('sessionsNone')));
    for (const session of sessions.sessions) {
      target.append(trafficRow(session.user, [session.line, session.from].filter(Boolean).join(' · '),
        session.since ? ago(session.since) : null));
    }
  }
}
function minuteBars(series) {
  const peak = Math.max(1, ...series);
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('class', 'mini-bars');
  svg.setAttribute('viewBox', `0 0 ${series.length * 10} 40`);
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `${t('webPerMinute')}${localeColon()}${series.join(', ')}`);
  series.forEach((count, index) => {
    const height = count ? Math.max(2, 38 * count / peak) : 1;
    const bar = document.createElementNS(svgNS, 'rect');
    bar.setAttribute('x', String(index * 10 + 1));
    bar.setAttribute('y', String(40 - height));
    bar.setAttribute('width', '8');
    bar.setAttribute('height', String(height));
    if (!count) bar.setAttribute('class', 'zero');
    const title = document.createElementNS(svgNS, 'title');
    title.textContent = `−${series.length - index} min${localeColon()}${count}`;
    bar.append(title);
    svg.append(bar);
  });
  return svg;
}
function renderWebTraffic(traffic) {
  const target = $('webTrafficList');
  const web = traffic.web;
  if (!web || !web.state) { empty(target); return; }
  if (web.state !== 'ok') {
    const message = node('p', 'empty', web.state === 'unreadable' ? t('webUnreadable').replace('{user}', web.user) : t('webMissing'));
    target.replaceChildren(message);
    if (web.state === 'unreadable' && web.command) {
      // What the command implies comes first: it must be read before the command is copied.
      const warning = node('p', 'acl-warning', t('webAclWarning').replaceAll('{user}', web.user));
      warning.setAttribute('role', 'note');
      target.append(warning, node('code', 'code-hint', web.command));
      if (web.undo) target.append(node('p', 'smalltext', t('webAclUndo')), node('code', 'code-hint', web.undo));
    }
    return;
  }
  const people = web.visitors - web.bots;
  const rows = node('div', 'rows');
  const responses = row(t('webResponses'), '');
  const line = node('span', 'status-line');
  for (const family of ['2', '3', '4', '5']) {
    if (web.status[family] > 0 || family === '2') line.append(node('span', 's' + family, `${family}xx${localeColon()}${number(web.status[family], 0)}`));
  }
  responses.querySelector('.value').replaceChildren(line);
  rows.append(
    row(t('webRequests').replace('{m}', web.minutes), `${number(web.requests, 0)} · ${number(web.requests / web.minutes)} /min`),
    row(t('webVisitors'), number(people, 0)),
    row(t('webBots'), number(web.bots, 0)),
    responses,
    row(t('webSent'), bytes(web.bytes)),
  );
  const axis = node('div', 'mini-axis');
  axis.append(node('span', '', `−${web.minutes} min`), node('span', '', t('webPerMinute')), node('span', '', t('nowWord')));
  target.replaceChildren(rows, minuteBars(web.series), axis);
  if (web.coveredSeconds < web.minutes * 60 - 30) target.append(node('p', 'smalltext', t('webPartial').replace('{s}', duration(web.coveredSeconds))));
  if (!web.requests) { target.append(node('p', 'empty', t('webNone'))); return; }
  target.append(node('h3', 'list-title', t('webTopClients')));
  for (const client of web.clients) {
    target.append(trafficRow(client.ip, `${client.page} · ${ago(client.last)}`,
      number(client.requests, 0) + (client.errors ? ` · ${t('errorCount').replace('{n}', number(client.errors, 0))}` : ''),
      client.errors && client.errors >= client.requests / 2 ? 'warn' : '', client.bot ? t('botTag') : ''));
  }
  target.append(node('h3', 'list-title', t('webTopPages')));
  for (const page of web.pages) target.append(trafficRow(page.page, '', number(page.count, 0)));
  if (web.errors.length) {
    const details = keptDetails('errors', `${t('webTopErrors')} (${number(web.status['4'] + web.status['5'], 0)})`);
    for (const error of web.errors) details.append(trafficRow(error.page, '', `${error.status} · ×${number(error.count, 0)}`, error.status >= 500 ? 'down' : 'warn'));
    target.append(details);
  }
}
let apachePrevious = null;
function renderApache(traffic) {
  const target = $('apacheList');
  const apache = traffic.apache;
  if (!apache || !apache.state || apache.state === 'disabled') { empty(target, t('apacheDisabled')); return; }
  if (apache.state !== 'ok') {
    target.replaceChildren(node('p', 'empty', t('apacheOff').replace('{detail}', apache.httpStatus ? 'HTTP ' + apache.httpStatus : t('unknown'))),
      node('code', 'code-hint', 'sudo a2enmod status && sudo systemctl reload apache2'));
    apachePrevious = null;
    return;
  }
  const rows = node('div', 'rows');
  let rate = null;
  if (apachePrevious && apache.atMs > apachePrevious.atMs && apache.totalAccesses >= apachePrevious.totalAccesses) {
    rate = (apache.totalAccesses - apachePrevious.totalAccesses) / ((apache.atMs - apachePrevious.atMs) / 1000);
  }
  if (!apachePrevious || apache.atMs !== apachePrevious.atMs) {
    if (rate !== null) apache.rate = rate;
    else if (apachePrevious?.rate != null && apache.totalAccesses >= apachePrevious.totalAccesses) apache.rate = apachePrevious.rate;
    apachePrevious = apache;
  }
  if (Number.isFinite(apache.totalAccesses)) rows.append(row(t('apacheRate'), apachePrevious.rate == null ? t('estimating') : number(apachePrevious.rate) + ' /s'));
  if (Number.isFinite(apache.busy)) rows.append(row(t('apacheWorkers'), `${number(apache.busy, 0)} / ${number(apache.busy + (apache.idle || 0), 0)}`));
  if (Number.isFinite(apache.keepalive)) rows.append(row(t('apacheKeepalive'), number(apache.keepalive, 0)));
  if (Number.isFinite(apache.uptimeSeconds)) rows.append(row(t('apacheUptime'), duration(apache.uptimeSeconds)));
  target.replaceChildren(rows, node('h3', 'list-title', t('apacheInFlight')));
  if (!apache.extended) { target.append(node('p', 'empty', t('apacheNotExtended'))); return; }
  if (!apache.requests.length) target.append(node('p', 'empty', t('apacheIdle')));
  for (const request of apache.requests) {
    target.append(trafficRow([request.method, request.vhost + request.path].filter(Boolean).join(' ') || '—', request.client,
      request.seconds == null ? null : duration(request.seconds), request.seconds >= 30 ? 'warn' : ''));
  }
}
function renderTraffic(data) {
  renderConnections(data.traffic);
  renderWebTraffic(data.traffic);
  renderApache(data.traffic);
}

function speedPages(value) {
  return value == null ? '—' : number(value) + ' ' + t('pagesPerSecond');
}
function renderCores() {
  const cores = state.rates.cores;
  $('coreCount').textContent = cores.length ? '(' + cores.length + ')' : '';
  const target = $('coreList');
  target.replaceChildren();
  if (!cores.length) { empty(target); return; }
  for (const core of cores) {
    const tile = node('div', 'core');
    const head = node('div', 'meter-row');
    head.append(node('span', '', core.id), node('strong', '', core.usage == null ? '—' : pct(core.usage)));
    tile.append(head, makeBar(core.usage));
    target.append(tile);
  }
}

const expandedDisks = new Set();
function renderDisks(data) {
  const target = $('disksList');
  target.replaceChildren();
  const disks = data.disks || [];
  if (!disks.length) { empty(target); return; }

  for (const disk of disks) {
    const value = percentage(disk.used, disk.total);
    const item = node('div', 'item');
    const header = node('div', 'meter-row');
    header.append(node('strong', '', disk.mount), node('span', 'pill', pct(value)));
    item.append(header, makeBar(value), node('div', 'smalltext',
      `${bytes(disk.used)} / ${bytes(disk.total)} · ${t('free')}: ${bytes(disk.free)} · ${disk.type}`));
    if (disk.inodes && disk.inodes.total > 0) {
      const ipct = percentage(disk.inodes.used,disk.inodes.total);
      item.append(node('div','inode-line', `${t('inodes')}: ${pct(ipct)} · ${number(disk.inodes.free,0)} ${t('free')}`));
    } else if (!disk.inodes && !/^(?:fuse(?:\.|$)|nfs|cifs|smb|sshfs|davfs)/i.test(disk.type || '')) {
      item.append(node('div','inode-line', `${t('inodes')}: ${t('unknown')}`));
    }

    const aliases = (disk.mounts || []).filter(name => name !== disk.mount);
    if (aliases.length) {
      const details = node('details', 'details');
      // The panel is redrawn at every refresh: remember what the user opened.
      details.open = expandedDisks.has(disk.mount);
      details.addEventListener('toggle', () => {
        if (details.open) expandedDisks.add(disk.mount);
        else expandedDisks.delete(disk.mount);
      });
      const summary = node('summary', '', `${t('extraMounts')} (${aliases.length})`);
      const content = node('div', 'smalltext', aliases.join(' · '));
      details.append(summary, content);
      item.append(details);
    }
    target.append(item);
  }
}

function renderDiskIo(data) {
  const target = $('diskIoList');
  target.replaceChildren();
  const devices = data.diskIo || [];
  if (!devices.length) { empty(target, t('noDevices')); return; }
  for (const device of devices) {
    const item = node('div', 'item');
    const rate = state.rates.disk[device.name] || {};
    const header = node('div', 'meter-row');
    header.append(node('strong', '', device.name), node('span', 'pill', device.virtual ? t('virtual') : t('physical')));
    item.append(header, node('div', 'smalltext',
      `${t('read')}: ${speed(rate.read)} · ${t('write')}: ${speed(rate.write)}`));
    item.append(node('div','smalltext',`${t('diskBusy')}: ${pct(rate.busy)} · ${t('read')}: ${rate.readOps == null ? '—' : number(rate.readOps) } IOPS · ${t('write')}: ${rate.writeOps == null ? '—' : number(rate.writeOps)} IOPS`));
    target.append(item);
  }
}

function networkStatus(value) {
  const key = String(value || 'unknown').replace(/[^a-z]/g, '') + 'State';
  return t(key) === key ? t('unknownState') : t(key);
}
const expandedNetwork = new Set();
function networkItem(info) {
  const wrapper = node('details','item network-item');
  wrapper.open = expandedNetwork.has(info.name);
  wrapper.addEventListener('toggle', () => {
    if (wrapper.open) expandedNetwork.add(info.name);
    else expandedNetwork.delete(info.name);
  });
  const summary = node('summary','meter-row');
  const status = info.state === 'up' ? 'up' : info.state === 'down' ? 'down' : info.state === 'enabled' ? 'enabled' : '';
  const name = node('strong','',info.name);
  const pill = node('span','pill '+status,networkStatus(info.state));
  summary.append(name,pill);
  const rate = state.rates.network[info.name] || {};
  const quick = node('div','smalltext network-quick',
    `${t('rx')}: ${speed(rate.rx)} · ${t('tx')}: ${speed(rate.tx)}`);
  const details = node('div','network-detail');
  details.append(node('div','smalltext', `${t('rx')}: ${bytes(info.rx)} · ${t('tx')}: ${bytes(info.tx)}`),
    node('div','smalltext',t(info.category || 'virtual')));
  if (info.ipv4?.length) details.append(node('div','smalltext','IPv4 : ' + info.ipv4.join(' · ')));
  if (info.ipv6?.length) details.append(node('div','smalltext','IPv6 : ' + info.ipv6.join(' · ')));
  const metadata = [];
  if (info.mtu) metadata.push(`MTU ${info.mtu}`);
  if (info.linkMbps) metadata.push(`${t('linkSpeed')} ${number(info.linkMbps,0)} Mb/s`);
  if (metadata.length) details.append(node('div','smalltext', metadata.join(' · ')));
  if (info.rxErrors || info.txErrors || info.rxDropped || info.txDropped) {
    details.append(node('div','smalltext',`${t('rxErrors')}: ${number(info.rxErrors,0)} · ${t('txErrors')}: ${number(info.txErrors,0)} · ${t('dropped')}: ${number((info.rxDropped||0)+(info.txDropped||0),0)}`));
    const relevant = state.rates.network[info.name];
    if (relevant) details.append(node('div','smalltext',`${t('networkErrorRate')}: ${relevant.rxErrors == null ? '—' : number((relevant.rxErrors||0) + (relevant.txErrors||0))} /s · ${t('dropped')}: ${relevant.dropped == null ? '—' : number(relevant.dropped)} /s`));
  }
  wrapper.append(summary,quick,details);
  return wrapper;
}
function renderNetwork(data) {
  const list = data.network || [];
  const primary = list.filter(item => item.category === 'physical' || item.category === 'vpn');
  const other = list.filter(item => item.category !== 'physical' && item.category !== 'vpn');
  if (!primary.length) {
    const main = other.find(item => item.category !== 'loopback');
    if (main) {
      primary.push(main);
      other.splice(other.indexOf(main), 1);
    }
  }
  const target = $('networkMain');
  target.replaceChildren();
  if (!primary.length) empty(target);
  else for (const item of primary) target.append(networkItem(item));

  const secondary = $('networkSecondary');
  secondary.hidden = other.length === 0;
  setText('secondaryCount', `(${other.length})`);
  const extras = $('networkSecondaryList');
  extras.replaceChildren();
  for (const item of other) extras.append(networkItem(item));
}

function renderServices(data) {
  const target = $('servicesList');
  target.replaceChildren();
  const services = data.services || [];
  if (!services.length) { empty(target); return; }
  for (const service of services) {
    const item = node('div', 'item');
    const head = node('div', 'meter-row');
    head.append(
      node('strong', '', service.name),
      node('span', 'pill ' + (service.online ? 'up' : 'down'),
        service.online ? t('onlineService') : t('offlineService'))
    );
    const ms = service.latencyMs == null ? '' : ` · ${number(service.latencyMs)} ms`;
    item.append(head, node('div', 'smalltext', String(service.endpoint) + ms));
    target.append(item);
  }
}

function renderHardware(data) {
  const target = $('hardwareList');
  const s = data.system || {};
  const sockets = Number(s.cpuSockets) || 1;
  target.replaceChildren(
    row(t('cpuModel'), s.cpuModel ? (sockets > 1 ? `${sockets} × ${s.cpuModel}` : s.cpuModel) : null),
    row(t('cores'), s.logicalCores),
  );
  if (Number.isFinite(s.physicalCores) && s.physicalCores !== s.logicalCores) target.append(row(t('physicalCores'), s.physicalCores));
  const temps = data.temperatures || [];
  const cpuCount = temps.filter(sensor => sensor.kind === 'cpu').length;
  const labels = {cpu:'tempCpu', disk:'tempDisk', board:'tempBoard', chipset:'tempChipset', wifi:'tempWifi'};
  if (!temps.length) target.append(row(t('temperature'), t('unknown')));
  for (const sensor of temps) {
    let label = labels[sensor.kind] ? t(labels[sensor.kind]) : (sensor.name || t('temperature'));
    if (sensor.kind === 'cpu' && cpuCount > 1) label += ' ' + (Number(sensor.index) + 1);
    if (sensor.kind === 'disk' && sensor.name) label += ' · ' + sensor.name;
    target.append(row(label, number(sensor.celsius) + ' °C'));
  }
  for (const array of data.raid || []) {
    const status = array.degraded ? t('raidDegraded')
      : array.sync ? `${t(array.sync.action === 'check' ? 'raidChecking' : 'raidRebuilding')} ${pct(array.sync.percent)}`
      : t('raidHealthy');
    const disks = Number.isFinite(array.devices) ? ` · ${array.working}/${array.devices}` : '';
    const raidRow = row(`RAID · ${array.name}`, `${array.level ? array.level + ' · ' : ''}${status}${disks}`);
    if (array.degraded) raidRow.querySelector('.value').classList.add('bad-text');
    target.append(raidRow);
  }
  const gpus = data.gpus || [];
  gpus.forEach((gpu, index) => {
    const suffix = gpus.length > 1 ? ' ' + (index + 1) : '';
    target.append(row(t('gpu') + suffix, gpu.name || t('unknown')));
    if (Number.isFinite(gpu.busyPercent)) target.append(row(t('gpuUsage') + suffix, pct(gpu.busyPercent)));
    if (Number.isFinite(gpu.vramTotal) && gpu.vramTotal > 0) {
      target.append(row(t('gpuMemory') + suffix, (Number.isFinite(gpu.vramUsed) ? bytes(gpu.vramUsed) + ' / ' : '') + bytes(gpu.vramTotal)));
    }
    if (Number.isFinite(gpu.celsius)) target.append(row(t('gpuTemp') + suffix, number(gpu.celsius) + ' °C'));
    if (Number.isFinite(gpu.watts)) target.append(row(t('gpuPower') + suffix, number(gpu.watts) + ' W'));
    if (Number.isFinite(gpu.mhz)) {
      target.append(row(t('gpuClock') + suffix, number(gpu.mhz, 0) + (Number.isFinite(gpu.maxMhz) ? ' / ' + number(gpu.maxMhz, 0) : '') + ' MHz'));
    }
  });
}

function renderPressure(data) {
  const target = $('pressureList');
  target.replaceChildren();
  const psi = data.pressure || {};
  for (const [field, label] of [['cpu','pressureCpu'], ['memory','pressureMemory'], ['io','pressureIo']]) {
    const p = psi[field];
    const tile = node('div', 'pressure-item');
    tile.append(
      node('small', '', t(label)),
      node('strong', '', p ? pct(p.avg10) : '—'),
      node('small', '', p ? `60s: ${pct(p.avg60)} · 300s: ${pct(p.avg300)}` : t('unknown')),
      node('small', '', p?.full ? `${t('fullStall')}: ${pct(p.full.avg10)}` : ''),
    );
    target.append(tile);
  }
}

// =============================================================
// 25. LANGUAGE AND STYLE
// =============================================================
function applyLanguage() {
  document.documentElement.lang = lang;
  $('language').value = lang;
  document.querySelectorAll('[data-i18n]').forEach(element => {
    element.textContent = t(element.dataset.i18n);
  });
  for (const [id, key] of [['styleChoice','changeStyle'], ['refresh','refresh'], ['language','language'],
    ['settings','settingsTitle'], ['closeSettings','close'], ['closeChart','close']]) {
    $(id).setAttribute('aria-label', t(key));
    if (id !== 'language') $(id).title = t(key);
  }
  for (const [id, key] of [
    ['cpuChart','cpuGraph'], ['ramChart','memoryGraph'], ['swapChart','swapGraph'],
    ['netChart','networkGraph'], ['ioChart','diskGraph']
  ]) {
    $(id).setAttribute('aria-label', t(key));
  }
  for (const btn of document.querySelectorAll('.chart-expand')) {
    const title = t('expandChart') + ' · ' + t(chartKeys[btn.dataset.chart]);
    btn.setAttribute('aria-label', title);
    btn.title = title;
  }
  for (const button of document.querySelectorAll('.help-button')) {
    button.setAttribute('aria-label', t('contextHelp'));
    button.setAttribute('aria-expanded', activeHelp === button && !helpPopover.hidden ? 'true' : 'false');
  }
  if (activeHelp && !helpPopover.hidden) showHelp(activeHelp,helpPinned);
  updateChartTitles();
  if ($('settingsDialog').open) renderPreferenceControls();
  document.querySelectorAll('[data-i18n-title]').forEach(element => { element.title = t(element.dataset.i18nTitle); });
  if (state.latest) render(state.latest);
  updateViewChrome();
  setText('connectionText', state.connected ? t('online') : (state.latest ? t('offline') : t('connecting')));
  if ($('errorBanner').classList.contains('show')) $('errorBanner').textContent = errorBannerText();
}
// "Auto" follows the light or dark setting of the device.
const darkScheme = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
function resolvedStyle() {
  if (visualStyle !== 'auto') return visualStyle;
  return darkScheme && !darkScheme.matches ? 'pro' : 'operations';
}
function applyStyle() {
  const style = resolvedStyle();
  document.documentElement.dataset.style = style;
  $('styleChoice').value = visualStyle;
  document.querySelector('meta[name="color-scheme"]').content = style === 'pro' ? 'light dark' : 'dark light';
}
darkScheme?.addEventListener?.('change', () => {
  if (visualStyle !== 'auto') return;
  applyStyle();
  renderCharts();
});
$('language').addEventListener('change', event => {
  if (!words[event.target.value]) return;
  lang = event.target.value;
  saveSetting('esmLang', lang);
  dashboardMeasured = false;
  applyLanguage();
  requestAnimationFrame(() => { layoutDashboard(true); rebalanceDashboardOnce(); });
});
$('styleChoice').addEventListener('change', event => {
  if (!styles.includes(event.target.value)) return;
  visualStyle = event.target.value;
  saveSetting('mmsStyle', visualStyle);
  applyStyle();
  requestAnimationFrame(() => { layoutDashboard(true); rebalanceDashboardOnce(); });
});
$('refresh').addEventListener('click', () => poll(true));

// =============================================================
// 26. LAYOUT, PREFERENCES AND DIALOGS
// =============================================================
let currentDashboardColumns = 0;
let dashboardMeasured = false;
const panelHeights = {};
const panelWeights = {
  activity:2.8, system:1.3, processes:1.8, network:2.0, storage:1.9,
  http:1.0, services:1.0, hardware:1.2, pressure:.8, checks:1.0, failed:.6, ports:1.6, php:1.3, connections:1.6, webtraffic:2.6, apache:1.2,
};
function layoutDashboard(force = false) {
  const dashboard = document.querySelector('.dashboard');
  const width = dashboard.clientWidth || document.querySelector('.wrap').clientWidth;
  const groups = currentView === 'overview' ? panelOrder : pageGroups[currentView];
  const panelCount = groups.left.length + groups.right.length;
  const count = Math.max(1, Math.min(panelCount, width >= 1940 ? 4 : width >= 1340 ? 3 : width >= 790 ? 2 : 1));
  if (!force && count === currentDashboardColumns) return;
  currentDashboardColumns = count;
  dashboard.style.setProperty('--dashboard-cols', String(count));
  const columns = Array.from({length:count}, () => node('div','column'));
  const targetLists = Array.from({length:count}, () => []);
  if (count === 1) targetLists[0].push(...groups.left, ...groups.right);
  else if (count === 2) {
    targetLists[0].push(...groups.left);
    targetLists[1].push(...groups.right);
  } else {
    const totalHeight = Array(count).fill(0);
    const ordered = [];
    const longest = Math.max(groups.left.length, groups.right.length);
    for (let i = 0; i < longest; i++) {
      if (groups.left[i]) ordered.push(groups.left[i]);
      if (groups.right[i]) ordered.push(groups.right[i]);
    }
    for (const id of ordered) {
      const minHeight = Math.min(...totalHeight);
      const index = totalHeight.indexOf(minHeight);
      targetLists[index].push(id);
      totalHeight[index] += (currentView === 'overview' && hiddenPanels.has(id)) ? 0.01 : (panelHeights[id] ?? panelWeights[id] ?? 1);
    }
  }
  const panels = new Map(allPanels.map(id => [id, $('panel-' + id)]));
  const store = $('panelStore');
  for (const panel of panels.values()) store.append(panel); // panels of other pages wait here, hidden
  for (let i = 0; i < count; i++) {
    for (const id of targetLists[i]) columns[i].append(panels.get(id));
  }
  dashboard.replaceChildren(...columns);
}
function rebalanceDashboardOnce() {
  if (dashboardMeasured || currentDashboardColumns < 3) return;
  dashboardMeasured = true;
  const panels = Array.from(document.querySelectorAll('.dashboard .panel'));
  if (!panels.length) return;
  for (const panel of panels) {
    if (!panel.hidden) panelHeights[panel.dataset.panel] = Math.max(.6,panel.offsetHeight / 200);
  }
  layoutDashboard(true);
}
let resizeQueued = false;
window.addEventListener('resize', () => {
  if (resizeQueued) return;
  resizeQueued = true;
  requestAnimationFrame(() => { resizeQueued = false; layoutDashboard(); });
});

function applyPreferences() {
  $('refreshInterval').value = String(refreshSeconds);
  $('graphPeriod').value = String(graphMinutes);
  for (const [name, value] of Object.entries(thresholds)) $('warn' + name[0].toUpperCase() + name.slice(1)).value = String(value);
  for (const name of allPanels) $('panel-' + name).hidden = currentView === 'overview' && hiddenPanels.has(name);
  for (const name of Object.keys(chartKeys)) {
    const card = document.querySelector(`[data-chart-card="${name}"]`);
    if (card) card.hidden = hiddenCharts.has(name);
  }
  $('siteFooter').hidden = !showFooter;
  $('showFooter').checked = showFooter;
  dashboardMeasured = false;
  layoutDashboard(true);
  updateChartTitles();
  renderCharts();
}
function renderPreferenceControls() {
  const chartTarget = $('chartToggles');
  chartTarget.replaceChildren();
  for (const [id, key] of Object.entries(chartKeys)) {
    const label = node('label');
    const input = node('input'); input.type = 'checkbox'; input.checked = !hiddenCharts.has(id);
    input.addEventListener('change', () => {
      if (input.checked) hiddenCharts.delete(id); else hiddenCharts.add(id);
      saveSetting('esm32HiddenCharts',JSON.stringify([...hiddenCharts]));
      applyPreferences();
    });
    label.append(input,node('span','',t(key).replace('3',graphMinutes)));
    chartTarget.append(label);
  }
  const panelTarget = $('panelToggles');
  panelTarget.replaceChildren();
  for (const side of ['left','right']) {
    const group = node('div');
    group.append(node('h4','',t(side === 'left' ? 'leftColumn' : 'rightColumn')));
    panelOrder[side].forEach((id,index) => {
      const item = node('div','panel-option');
      const label = node('label');
      const box = node('input'); box.type='checkbox'; box.checked=!hiddenPanels.has(id);
      box.addEventListener('change', () => {
        if (box.checked) hiddenPanels.delete(id); else hiddenPanels.add(id);
        saveSetting('esm32HiddenPanels', JSON.stringify([...hiddenPanels]));
        applyPreferences();
      });
      label.append(box,node('span','',t(panelLabels[id])));
      const buttons = node('div','order-buttons');
      for (const direction of [-1,1]) {
        const button = node('button','',direction === -1 ? '↑':'↓');
        button.type='button'; button.disabled=direction === -1 ? index===0 : index === panelOrder[side].length-1;
        button.setAttribute('aria-label',t(direction === -1 ? 'moveUp':'moveDown')+' : '+t(panelLabels[id]));
        button.addEventListener('click', () => {
          const next = index + direction;
          [panelOrder[side][index],panelOrder[side][next]]=[panelOrder[side][next],panelOrder[side][index]];
          saveSetting('esm32Order',JSON.stringify(panelOrder));
          applyPreferences(); renderPreferenceControls();
        });
        buttons.append(button);
      }
      item.append(label,buttons);
      group.append(item);
    });
    panelTarget.append(group);
  }
}
function setRefresh() {
  if (pollIntervalId !== null) clearInterval(pollIntervalId);
  pollIntervalId = setInterval(poll, refreshSeconds * 1000);
}
let pollIntervalId = null;
$('settings').addEventListener('click', () => {
  renderPreferenceControls();
  $('settingsDialog').showModal();
});
$('closeSettings').addEventListener('click', () => { hideHelp(true); $('settingsDialog').close(); });
$('doneSettings').addEventListener('click', () => { hideHelp(true); $('settingsDialog').close(); });
$('refreshInterval').addEventListener('change', event => {
  refreshSeconds=validChoice(event.target.value,[2,3,5,10,30,60],5);
  saveSetting('esm32Refresh',String(refreshSeconds));
  setRefresh();
});
$('graphPeriod').addEventListener('change', event => {
  graphMinutes=validChoice(event.target.value,[1,3,10],3);
  saveSetting('esm32Period',String(graphMinutes));
  applyPreferences(); renderPreferenceControls();
});
for (const name of ['cpu','ram','disk']) {
  const input = $('warn'+name[0].toUpperCase()+name.slice(1));
  input.addEventListener('change', () => {
    // Out-of-range values are brought back to the nearest limit instead of being discarded.
    const typed = Math.round(Number(input.value));
    thresholds[name]=Number.isFinite(typed) && input.value !== '' ? Math.max(50,Math.min(95,typed)) : 85;
    input.value=String(thresholds[name]);
    saveSetting('esm32Warn'+name[0].toUpperCase()+name.slice(1),String(thresholds[name]));
    if (state.latest) renderHealth(state.latest);
    renderCharts();
  });
}
$('showFooter').addEventListener('change', event => {
  showFooter = event.target.checked;
  saveSetting('mmsShowFooter', showFooter ? '1' : '0');
  applyPreferences();
});
$('resetSettings').addEventListener('click', () => {
  refreshSeconds = <?= (int) $refresh ?>; graphMinutes = 3; showFooter = true;
  Object.assign(thresholds,{cpu:85,ram:85,disk:85});
  hiddenPanels.clear(); hiddenCharts.clear();
  panelOrder={left:[...panelGroups.left],right:[...panelGroups.right]};
  for (const key of ['esm32Refresh','esm32Period','esm32WarnCpu','esm32WarnRam','esm32WarnDisk',
    'esm32HiddenPanels','esm32HiddenCharts','esm32Order','mmsShowFooter']) {
    try { localStorage.removeItem(key); } catch {  }
  }
  applyPreferences(); renderPreferenceControls(); setRefresh();
  if (state.latest) renderHealth(state.latest);
});
for (const button of document.querySelectorAll('.chart-expand')) {
  button.addEventListener('click', () => {
    $('chartDialog').dataset.chart = button.dataset.chart;
    $('chartDialog').showModal(); renderZoom();
  });
}
$('closeChart').addEventListener('click',()=>{ hideHelp(true); $('chartDialog').close(); });
for (const modal of [$('chartDialog'), $('settingsDialog')]) modal.addEventListener('close', () => hideHelp(true));

// =============================================================
// 27. POLLING AND ERROR HANDLING
// =============================================================
function render(data) {
  state.latest = data;
  renderSummary(data);
  renderHealth(data);
  renderCharts();
  // Panels are rebuilt at every refresh, which would drop a text selection: while the user is
  // selecting (to copy an address, a unit name...), they keep their content until the next refresh.
  if (!userIsSelecting()) {
    renderSystem(data);
    renderPhp(data);
    renderHttp(data);
    renderCores();
    renderDisks(data);
    renderDiskIo(data);
    renderNetwork(data);
    renderServices(data);
    renderPressure(data);
    renderChecks(data);
    renderFailedUnits(data);
    renderPorts(data);
    if (data.view === currentView && data.traffic) renderTraffic(data);
    // Modules collected only for one page: render them only when they belong to the page shown.
    if (data.view === currentView && data.processes) {
      if (currentView === 'processes') renderProcessDetail(data); else renderProcesses(data);
    }
    if (data.view === currentView && Array.isArray(data.temperatures)) renderHardware(data);
  }
  if (!dashboardMeasured && currentDashboardColumns >= 3) requestAnimationFrame(rebalanceDashboardOnce);
}

function showOnline() {
  $('connectionDot').className = 'dot ok';
  state.connected = true;
  state.errorDetail = '';
  state.failures = 0;
  state.lastSuccess = Date.now();
  setText('connectionText', t('online'));
  $('errorBanner').classList.remove('show');
  delete document.documentElement.dataset.stale;
  updateTitle();
}
function errorBannerText() {
  const age = state.lastSuccess ? duration((Date.now() - state.lastSuccess) / 1000) : '';
  return t('refreshError') + ' (' + state.errorDetail + ')' + (age ? ' ' + t('lastDataAgo').replace('{s}', age) : '');
}
function showOffline(error) {
  $('connectionDot').className = 'dot error';
  state.connected = false;
  setText('connectionText', t('offline'));
  state.errorDetail = String(error?.message || 'error');
  // Retry less and less often (up to once a minute) instead of hammering a server in trouble.
  state.failures = Math.min(8, state.failures + 1);
  state.retryAt = Date.now() + Math.min(60000, refreshSeconds * 1000 * 2 ** (state.failures - 1)) - 500;
  $('errorBanner').textContent = errorBannerText();
  $('errorBanner').classList.add('show');
  document.documentElement.dataset.stale = '1'; // dims the figures: they are no longer current
  updateTitle();
}
let pollCount = 0;
async function poll(force = false) {
  force = force === true; // setInterval and event listeners pass other arguments
  if (!force && !state.active && (BACKGROUND_REFRESH_SECONDS <= 0 || Date.now() - (state.lastPoll || 0) < BACKGROUND_REFRESH_SECONDS * 1000 - 500)) return;
  if (!force && state.failures > 0 && Date.now() < state.retryAt) return;
  if (state.busy) { state.repoll = true; return; }
  state.busy = true;
  state.lastPoll = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(8000, refreshSeconds * 2000));
    let response;
    try {
      response = await fetch(location.pathname + '?api=stats&view=' + encodeURIComponent(currentView), {
        cache: 'no-store', credentials: 'same-origin', signal: controller.signal,
      });
    } catch (error) {
      throw error?.name === 'AbortError' ? new Error('timeout') : error;
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const data = await response.json();
    if (!data.ok) throw new Error('API error');
    state.rates = calculateRates(data);
    state.previous = data;
    appendHistory('cpu', state.rates.cpu);
    appendHistory('ram', data.memory?.ram ? percentage(data.memory.ram.used, data.memory.ram.total) : null);
    appendHistory('swap', data.memory?.swap?.total > 0
      ? percentage(data.memory.swap.used, data.memory.swap.total) : null);
    appendHistory('netRx', state.rates.netRx);
    appendHistory('netTx', state.rates.netTx);
    appendHistory('diskRead', state.rates.diskRead);
    appendHistory('diskWrite', state.rates.diskWrite);
    state.historyTimes.push(Number(data.sampleTimeMs) || Date.now());
    if (state.historyTimes.length > HISTORY_LIMIT) state.historyTimes.shift();
    render(data);
    showOnline();
    if (++pollCount % 3 === 0) saveHistory();
  } catch (error) {
    showOffline(error);
    state.previous = null;
  } finally {
    state.busy = false;
    if (state.repoll) { state.repoll = false; poll(); }
  }
}

// =============================================================
// 28. INTERNATIONALIZED HELP
// =============================================================
const helpPopover = $('helpPopover');
let activeHelp = null;
let helpPinned = false;
function showHelp(button, pinned = false) {
  if (!button || !button.dataset.help) return;
  activeHelp = button;
  helpPinned = pinned;
  const host = button.closest('dialog[open]') || document.body;
  if (helpPopover.parentElement !== host) host.append(helpPopover);
  helpPopover.textContent = button.dataset.help.split(',').map(key => t(key)).filter(Boolean).join('\n\n');
  helpPopover.hidden = false;
  const rect = button.getBoundingClientRect();
  const popupWidth = Math.min(345,window.innerWidth - 24);
  const left = Math.min(Math.max(12,rect.left - popupWidth + rect.width),window.innerWidth - popupWidth - 12);
  helpPopover.style.left = left + 'px';
  const below = rect.bottom + 8;
  const maxHeight = Math.min(window.innerHeight * .6,380);
  helpPopover.style.top = (below + maxHeight < window.innerHeight ? below : Math.max(12, rect.top - Math.min(helpPopover.scrollHeight,maxHeight) - 8)) + 'px';
  button.setAttribute('aria-expanded','true');
}
function hideHelp(force = false) {
  if (helpPinned && !force) return;
  if (activeHelp) activeHelp.setAttribute('aria-expanded','false');
  activeHelp = null; helpPinned = false; helpPopover.hidden = true;
}
document.addEventListener('pointerover', event => {
  const button = event.target.closest?.('.help-button');
  if (button && event.pointerType !== 'touch') showHelp(button);
});
document.addEventListener('pointerout', event => {
  if (event.target.closest?.('.help-button')) hideHelp();
});
document.addEventListener('focusin', event => {
  const button = event.target.closest?.('.help-button');
  if (button) showHelp(button,helpPinned);
});
document.addEventListener('focusout', event => {
  if (event.target.closest?.('.help-button')) hideHelp();
});
document.addEventListener('click', event => {
  const button = event.target.closest?.('.help-button');
  if (button) {
    if (activeHelp === button && helpPinned) hideHelp(true);
    else showHelp(button,true);
  } else hideHelp(true);
});
document.addEventListener('keydown',event=>{ if(event.key==='Escape') hideHelp(true); });
window.addEventListener('scroll',()=>{ if (!helpPinned) hideHelp(true); },true);
document.addEventListener('visibilitychange', () => {
  state.active = !document.hidden;
  if (state.active) {
    if (BACKGROUND_REFRESH_SECONDS <= 0) state.previous = null;
    poll(true);
  }
});
function updateViewChrome() {
  document.documentElement.dataset.view = currentView;
  for (const link of document.querySelectorAll('#viewTabs a')) {
    if (link.dataset.viewLink === currentView) {
      link.setAttribute('aria-current', 'page');
      const tabs = $('viewTabs');
      if (tabs.scrollWidth > tabs.clientWidth) tabs.scrollLeft = Math.max(0, link.offsetLeft - tabs.offsetLeft - 16);
    } else link.removeAttribute('aria-current');
  }
  updateTitle();
}
// Tab title and icon: which server this is and how it is doing, readable among many tabs.
const faviconLink = document.querySelector('link[rel="icon"]');
const faviconDefault = faviconLink?.getAttribute('href');
let faviconColor = '';
function statusFavicon(color) {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="4" y="4" width="56" height="56" rx="12" fill="#020711"/>'
    + '<rect x="12" y="14" width="34" height="27" rx="4" fill="none" stroke="#fff" stroke-width="2.6"/>'
    + '<path d="M16 28h7l3.6-7.4 5.4 12.2 4.2-4.8h6" fill="none" stroke="#3affec" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
    + `<circle cx="46" cy="46" r="13" fill="${color}" stroke="#020711" stroke-width="3"/></svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}
function updateTitle() {
  const offline = !state.connected && Boolean(state.latest);
  const {severity, count} = state.health;
  const badge = offline ? '⏸ ' : severity === 2 ? `⛔ ${count} · ` : severity === 1 ? `⚠ ${count} · ` : '';
  const host = state.latest?.system?.hostname;
  const name = [host, currentView === 'overview' ? null : t(VIEW_LABELS[currentView]), host ? APP_TITLE : PAGE_TITLE].filter(Boolean).join(' · ');
  document.title = badge + name;
  const color = offline ? '#8a97a8' : severity === 2 ? '#f07e88' : severity === 1 ? '#edbd72' : '';
  if (faviconLink && color !== faviconColor) {
    faviconColor = color;
    faviconLink.setAttribute('href', color ? statusFavicon(color) : faviconDefault);
  }
}
function switchView(view, push = true) {
  if (!VIEWS.includes(view)) view = 'overview';
  if (push) history.pushState({view}, '', '?view=' + view);
  if (view === currentView) return;
  currentView = view;
  updateViewChrome();
  dashboardMeasured = false;
  applyPreferences();
  window.scrollTo(0, 0);
  if (state.latest) render(state.latest);
  requestAnimationFrame(() => rebalanceDashboardOnce());
  poll();
}
document.addEventListener('click', event => {
  const link = event.target.closest?.('a[data-view-link]');
  if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  switchView(link.dataset.viewLink);
});
window.addEventListener('popstate', () => {
  switchView(new URLSearchParams(location.search).get('view') || 'overview', false);
});
restoreHistory();
updateViewChrome();
applyStyle();
applyPreferences();
applyLanguage();
poll();
setRefresh();
  </script>
</body>
</html>