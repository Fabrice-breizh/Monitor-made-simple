<?php
/**
 * Monitor made Simple 1.0.3 — single-file Linux monitoring dashboard.
 * PHP 8.1+, no external assets or database.
 * HTTP Basic authentication is mandatory for the page and JSON API.
 */
declare(strict_types=1);

// =============================================================
// 01. CONFIGURATION
// =============================================================
const ESM_TITLE = 'Monitor made Simple';
const ESM_REFRESH_SECONDS = 5;
const ESM_AUTH_USER = 'admin';

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
const ESM_PROCESS_CACHE_SECONDS = 10;
const ESM_SERVICES_CACHE_SECONDS = 12;
const ESM_INODES_CACHE_SECONDS = 45;
const ESM_REMOTE_MOUNT_CACHE_SECONDS = 60;
const ESM_HTTP_CACHE_SECONDS = 60;
const ESM_HTTP_PROBES_PER_REQUEST = 1;
const ESM_MONITOR_REMOTE_MOUNTS = false;
// Keep remote mounts disabled by default; explicitly allow only trusted paths.
// FUSE network calls may still block when a 60-second cache entry expires.
const ESM_REMOTE_MOUNT_ALLOWLIST = ['/CLOUDS/Google_Drive'];

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

header('X-Content-Type-Options: nosniff');
header('X-Monitor-Made-Simple: 1.0.3');
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

function esmPasswordHash(): string
{
    $env = getenv('ESM_PASSWORD_HASH');
    return $env !== false && $env !== '' ? $env : ESM_PASSWORD_HASH;
}

function esmAuthorized(): bool
{
    $hash = esmPasswordHash();
    if ($hash !== '') {
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
        return hash_equals(ESM_AUTH_USER, $user) && password_verify($password, $hash);
    }
    return false;
}

if (!esmAuthorized()) {
    http_response_code(401);
    if (esmPasswordHash() !== '') {
        header('WWW-Authenticate: Basic realm="Monitor made Simple", charset="UTF-8"');
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo "Monitor made Simple: access denied. Configure ESM_PASSWORD_HASH and use HTTPS.\n";
    exit;
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
    $base = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
        . 'monitor-made-simple-' . substr(hash('sha256', __FILE__), 0, 20);
    if (!is_dir($base)) @mkdir($base, 0700);
    if (!is_dir($base) || !is_writable($base)) return null;
    $perms = @fileperms($base);
    if ($perms === false || ($perms & 0077) !== 0) return null;
    if (function_exists('posix_geteuid') && @fileowner($base) !== posix_geteuid()) return null;
    return $base;
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
function esmCachedCollect(string $key, int $seconds, callable $collector): array
{
    $previous = esmCacheRead($key);
    if ($previous !== null && isset($previous['at'], $previous['data'])
        && (time() - (int) $previous['at']) >= 0
        && (time() - (int) $previous['at']) < $seconds
        && is_array($previous['data'])) return $previous['data'];
    $data = $collector();
    if (is_array($data)) esmCacheWrite($key, ['at' => time(), 'data' => $data]);
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

function esmSystem(): array
{
    $os = 'Linux';
    $release = esmRead('/etc/os-release', 16384);
    if ($release !== null && preg_match('/^PRETTY_NAME=(.+)$/m', $release, $m)) {
        $os = trim(trim($m[1]), "\"'");
    }
    $uptimeText = esmRead('/proc/uptime', 64);
    $uptime = $uptimeText !== null && preg_match('/^([\d.]+)/', $uptimeText, $m)
        ? (int) (float) $m[1] : null;
    $cpuInfo = esmRead('/proc/cpuinfo', 1048576);
    $cores = $cpuInfo !== null ? preg_match_all('/^processor\s*:/mi', $cpuInfo) : false;
    $load = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
    return [
        'hostname' => function_exists('gethostname') ? (gethostname() ?: null) : null,
        'os' => $os,
        'kernel' => function_exists('php_uname') ? php_uname('r') : null,
        'architecture' => function_exists('php_uname') ? php_uname('m') : null,
        'php' => PHP_VERSION,
        'uptimeSeconds' => $uptime,
        'cpuModel' => esmCpuModel($cpuInfo),
        'logicalCores' => $cores !== false && $cores > 0 ? $cores : null,
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
        $key = ($dev ?? ($device . '|' . $type))
            . '|' . $total . '|' . $free;
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

// =============================================================
// 08. INODE METRICS
// =============================================================
function esmInodes(): array
{
    return esmCachedCollect('inodes', ESM_INODES_CACHE_SECONDS, static function (): array {
        $binary = is_executable('/usr/bin/df') ? '/usr/bin/df'
            : (is_executable('/bin/df') ? '/bin/df' : null);
        if ($binary === null || !function_exists('proc_open')) return [];
        $spec = [1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']];
        $proc = @proc_open([$binary, '-Pi', '-l'], $spec, $pipes);
        if (!is_resource($proc)) return [];
        stream_set_blocking($pipes[1], false);
        $text = '';
        $deadline = microtime(true) + 0.9;
        $timedOut = false;
        while (true) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) { $timedOut = true; break; }
            $reads = [$pipes[1]]; $writes = null; $except = null;
            @stream_select($reads, $writes, $except, 0, min(150000, (int) ($remaining * 1000000)));
            if ($reads) {
                $chunk = @fread($pipes[1], 8192);
                if (is_string($chunk)) $text .= $chunk;
                if (strlen($text) > 131072) { $timedOut = true; break; }
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
        if ($timedOut) return [];
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
// 09. NETWORK INTERFACES
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
function esmTemperatures(): array
{
    if (!function_exists('glob')) return [];
    $out = [];
    foreach (glob('/sys/class/thermal/thermal_zone*/temp') ?: [] as $path) {
        $n = esmNumber(esmRead($path, 64));
        if ($n === null) continue;
        $c = abs($n) >= 1000 ? $n / 1000 : $n;
        if ($c < -40 || $c > 130) continue;
        $label = esmRead(dirname($path) . '/type', 128);
        $out[] = ['name' => trim($label ?? 'Thermal'), 'celsius' => round($c, 1)];
    }
    foreach (glob('/sys/class/hwmon/hwmon*/temp*_input') ?: [] as $path) {
        $n = esmNumber(esmRead($path, 64));
        if ($n === null) continue;
        $c = $n / 1000;
        if ($c < -40 || $c > 130) continue;
        $labelPath = preg_replace('/_input$/', '_label', $path);
        $label = $labelPath ? esmRead($labelPath, 128) : null;
        $chip = esmRead(dirname($path) . '/name', 128);
        $out[] = [
            'name' => trim(($chip ?? 'Sensor') . ' ' . ($label ?? basename($path))),
            'celsius' => round($c, 1),
        ];
    }
    return array_slice($out, 0, 24);
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
    return esmCachedCollect('processes-swap-v3', ESM_PROCESS_CACHE_SECONDS, 'esmSampleProcesses');
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
        $snapshot[$id] = $ticks;
        $records[] = [
            'pid' => $pid, 'name' => mbSafeLimit($name, 64), 'start' => $parts[19],
            'ticks' => $ticks, 'rssPages' => $rssPages, 'id' => $id,
        ];
    }
    $cpu = esmCpu();
    $total = (float) ($cpu['total'] ?? 0);
    $deltaTotal = $total - $oldTotal;
    $coreCount = max(1, count($cpu['cores'] ?? []));
    foreach ($records as &$record) {
        $oldTicks = $before[$record['id']] ?? null;
        $delta = $oldTicks === null ? null : $record['ticks'] - (float) $oldTicks;
        $record['cpuPercent'] = $delta !== null && $delta >= 0 && $deltaTotal > 0
            ? round(min(100 * $coreCount, 100 * $coreCount * $delta / $deltaTotal), 1) : null;
    }
    unset($record);
    $cpuSorted = $records;
    usort($cpuSorted, static fn($a, $b): int => ($b['cpuPercent'] ?? -1) <=> ($a['cpuPercent'] ?? -1));
    $ramSorted = $records;
    usort($ramSorted, static fn($a, $b): int => $b['rssPages'] <=> $a['rssPages']);
    foreach ($records as &$rec) {
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
    foreach (array_merge(array_slice($cpuSorted, 0, 5), array_slice($ramSorted, 0, 5), array_slice($swapSorted, 0, 5)) as $rec) {
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
function esmHttpChecks(): array
{
    $checks = [];
    if (ESM_SELF_CHECK) {
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
    foreach ($checks as $check) {
        $key = hash('sha256', json_encode($check) ?: '');
        $cached = $saved[$key] ?? null;
        $fresh = is_array($cached) && isset($cached['checkedAt'])
            && time() - (int) $cached['checkedAt'] >= 0
            && time() - (int) $cached['checkedAt'] < ESM_HTTP_CACHE_SECONDS;
        if ($fresh) {
            $results[] = $cached;
        } elseif ($probed < ESM_HTTP_PROBES_PER_REQUEST) {
            $result = esmHttpProbe($check);
            if ($result !== null) {
                $result['checkedAt'] = time();
                $saved[$key] = $result;
                $results[] = $result;
                $probed++;
            }
        } elseif (is_array($cached)) {
            $cached['stale'] = true;
            $results[] = $cached;
        } else {
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
    esmCacheWrite('http-checks', ['checks' => $saved]);
    return $results;
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
    $client = @stream_socket_client(
        ($tls ? 'tls://' : 'tcp://') . $endpoint,
        $errno, $errorString, 0.55, STREAM_CLIENT_CONNECT, $context
    );
    if (!is_resource($client)) return $result;
    $request = "GET " . $path . " HTTP/1.1\r\nHost: " . $hostname
        . "\r\nConnection: close\r\nUser-Agent: Monitor-made-Simple/1.0.3\r\nAccept: */*\r\n\r\n";
    stream_set_blocking($client, false);
    $pending = $request;
    $headers = '';
    $deadline = microtime(true) + 0.65;
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
    $marker = $isSelf && (bool) preg_match('/(?:^|\r?\n)X-Monitor-Made-Simple:\s*1\./i', $headerOnly);
    $result['latencyMs'] = round((microtime(true) - $start) * 1000, 1);
    if (is_string($line) && preg_match('~^HTTP/\d(?:\.\d)?\s+(\d{3})~i', $line, $m)) {
        $status = (int) $m[1];
        $result['httpStatus'] = $status;
        $result['reachable'] = true;
        $result['online'] = ($status >= 200 && $status < 400) || ($isSelf && $status === 401);
        $result['error'] = $result['online'] ? null : 'httpFailure';
        if ($isSelf && !$marker) {
            $result['online'] = false;
            $result['error'] = 'selfProbeMismatch';
        }
    } else {
        $result['error'] = 'invalidResponse';
    }
    if ($tls && function_exists('openssl_x509_parse')) {
        $params = @stream_context_get_params($client);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if ($cert !== null) {
            $parsed = @openssl_x509_parse($cert, false);
            if (is_array($parsed) && isset($parsed['validTo_time_t'])) {
                $end = (int) $parsed['validTo_time_t'];
                $result['tlsExpiry'] = gmdate('Y-m-d', $end);
                $result['tlsDays'] = (int) floor(($end - time()) / 86400);
            }
        }
    }
    fclose($client);
    return $result;
}

// =============================================================
// 15. JSON API
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

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if ($_GET['api'] !== 'stats') {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'Not found']);
        exit;
    }
    try {
        $collectStart = microtime(true);
        $payload = [
            'ok' => true,
            'version' => '1.0.3',
            'sampleTimeMs' => round(microtime(true) * 1000),
            'system' => esmSafeCollect('system', 'esmSystem', []),
            'cpu' => esmSafeCollect('cpu', 'esmCpu', ['total'=>null, 'idle'=>null, 'cores'=>[]]),
            'memory' => esmSafeCollect('memory', 'esmMemory', ['ram'=>null, 'swap'=>null, 'swapActivity'=>null]),
            'disks' => esmSafeCollect('disks', 'esmDisks', []),
            'diskIo' => esmSafeCollect('diskIo', 'esmDiskIo', []),
            'network' => esmSafeCollect('network', 'esmNetwork', []),
            'pressure' => esmSafeCollect('pressure', 'esmPressure', []),
            'temperatures' => esmSafeCollect('temperatures', 'esmTemperatures', []),
            'services' => esmSafeCollect('services', 'esmServices', []),
            'processes' => esmSafeCollect('processes', 'esmProcesses', []),
            'httpChecks' => esmSafeCollect('httpChecks', 'esmHttpChecks', []),
        ];
        $payload['collectionMs'] = round((microtime(true) - $collectStart) * 1000, 1);
        echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $error) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'Metrics unavailable']);
        error_log('Monitor made Simple statistics error: ' . $error->getMessage());
    }
    exit;
}

// =============================================================
// 16. HTML INTERFACE
// =============================================================
header('Content-Type: text/html; charset=utf-8');
$nonce = htmlspecialchars(esmNonce(), ENT_QUOTES, 'UTF-8');
$title = htmlspecialchars(ESM_TITLE, ENT_QUOTES, 'UTF-8');
$refresh = max(2, min(60, ESM_REFRESH_SECONDS));
?><!doctype html>
<html lang="en" data-style="operations">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title><?= $title ?> · Linux dashboard</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCI+PHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByeD0iMTUiIGZpbGw9IiMwNTA3MGIiLz48cmVjdCB4PSIxMCIgeT0iMTIiIHdpZHRoPSI0NCIgaGVpZ2h0PSIzOCIgcng9IjciIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2Y3ZmFmYyIgc3Ryb2tlLXdpZHRoPSIzLjUiLz48cGF0aCBkPSJNMTQgMzNoOWw2LTEzIDggMjUgNi0xMmg3IiBmaWxsPSJub25lIiBzdHJva2U9IiM1NmQ3YzciIHN0cm9rZS13aWR0aD0iNCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+PC9zdmc+">
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
  color-scheme:light;
  --bg:#f4f0e7;--surface:#fffefa;--soft:#f6f2ea;
  --text:#3e382f;--muted:#82796b;--border:#e8e0d2;
  --accent:#9a7246;--good:#32876d;--warn:#b6823e;--bad:#c56063;
  --grid:#a37b4214;--shadow:0 3px 7px #3a2b2007,0 16px 45px #3a2b2009;
  --surface-hi:#ffffff;--surface-border:#ded4c4;
  --accent-glow:#ac825324;--chart-wash:#f9f6f0;
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
.metric-symbol {
  display:grid; place-items:center; flex:0 0 auto; width:35px; height:35px; border-radius:11px;
  color:var(--accent); background:var(--soft); font-size:19px; opacity:.88;
}
.metric:nth-child(2) .metric-symbol { color:var(--good); }
.metric:nth-child(3) .metric-symbol { color:var(--warn); }
.metric:nth-child(4) .metric-symbol { color:#7f8ec5; }
.metric:nth-child(5) .metric-symbol { color:var(--muted); }
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
  .metric-symbol { width:30px; height:30px; }
}
@media (max-width:520px) {
  .wrap { width:calc(100% - 22px); }
  .header { margin-top:11px; padding:14px; border-radius:16px; gap:12px; }
  .logo { width:44px; height:44px; border-radius:13px; font-size:23px; }
  .toolbar { gap:6px; }
  .toolbar .status { flex:1; justify-content:center; }
  .control { min-height:40px; }
  .metric { min-height:123px; padding:13px; border-radius:14px; }
  .metric-symbol { width:28px; height:28px; border-radius:9px; font-size:16px; }
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

[data-style="operations"] body {background-image:linear-gradient(180deg,#101d2d 0%,var(--bg) 440px);background-attachment:fixed;}
[data-style="operations"] .header {border-radius:13px;background:#152235;border:1px solid #344960;}
[data-style="operations"] .metric,[data-style="operations"] .panel {border-radius:12px;}
[data-style="operations"] .metric {border-top:2px solid #334d60;}
[data-style="operations"] .metric::before {width:0;}
[data-style="operations"] .metric:nth-child(1) {border-top-color:#55c7db;}
[data-style="operations"] .metric:nth-child(2) {border-top-color:#6aceaf;}
[data-style="operations"] .metric:nth-child(3) {border-top-color:#f0b66c;}
[data-style="operations"] .metric:nth-child(4) {border-top-color:#a6a4ef;}
[data-style="operations"] .metric:nth-child(5) {border-top-color:#718aa4;}
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
[data-style="pro"] .metric-symbol {border-radius:4px;}
[data-style="pro"] .big {font-weight:720;}
[data-style="pro"] .icon {border-radius:4px;}
[data-style="pro"] .item,[data-style="pro"] .process-item,[data-style="pro"] .chart-card {border-radius:4px;}
[data-style="pro"] .chart-card {background:var(--surface);}
[data-style="pro"] .control {border-radius:5px;}
[data-style="pro"] .health-banner {border-radius:5px;box-shadow:none;}
[data-style="pro"] .status {border-radius:5px;}
[data-style="pro"] .panel h2 {border-bottom:1px solid var(--border);padding-bottom:10px;}
[data-style="pro"] .metric:hover {transform:none;box-shadow:none;}

[data-style="zen"] .metric,[data-style="zen"] .panel {border-radius:19px;}
[data-style="zen"] .header {border-radius:21px;}
[data-style="zen"] .item,[data-style="zen"] .chart-card {border-radius:14px;}
[data-style="zen"] .process-item {border-radius:12px;}
[data-style="zen"] .icon {border-radius:12px;}

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
        <label class="style-picker"><span data-i18n="interfaceStyle">Style</span><select class="control" id="styleChoice" aria-label="Interface style"><option value="operations">Operations</option><option value="pro">Pro</option><option value="zen">Zen</option></select></label>
        <button type="button" class="control" id="settings" aria-label="Settings" title="Settings">⚙</button>
        <button type="button" class="control" id="refresh" aria-label="Refresh" title="Refresh">↻</button>
      </div>
    </header>

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
        <div class="metric-value-row"><div class="big" id="cpuValue">—</div><span class="metric-symbol" aria-hidden="true">◉</span></div>
        <div class="progress"><i id="cpuBar"></i></div>
        <div class="tiny" id="cpuExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="memory">Memory</div>
        <div class="metric-value-row"><div class="big" id="ramValue">—</div><span class="metric-symbol" aria-hidden="true">▥</span></div>
        <div class="progress"><i id="ramBar"></i></div>
        <div class="tiny" id="ramExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="swap">Swap</div>
        <div class="metric-value-row"><div class="big" id="swapValue">—</div><span class="metric-symbol" aria-hidden="true">⇄</span></div>
        <div class="progress"><i id="swapBar"></i></div>
        <div class="tiny" id="swapExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="disk">Disk</div>
        <div class="metric-value-row"><div class="big" id="diskValue">—</div><span class="metric-symbol" aria-hidden="true">▤</span></div>
        <div class="progress"><i id="diskBar"></i></div>
        <div class="tiny" id="diskExtra">—</div>
      </div>
      <div class="metric">
        <div class="eyebrow" data-i18n="uptime">Uptime</div>
        <div class="metric-value-row"><div class="big" id="uptimeValue">—</div><span class="metric-symbol" aria-hidden="true">◷</span></div>
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
              <svg id="cpuChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg><div class="chart-stats" id="cpuStats"></div>
            </div>
            <div class="chart-card" data-chart-card="ram">
              <div class="chart-title"><span class="chart-label" data-i18n="memoryGraph">RAM · last 3 min</span><button type="button" class="chart-expand" data-chart="ram" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <svg id="ramChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg><div class="chart-stats" id="ramStats"></div>
            </div>
            <div class="chart-card" data-chart-card="swap">
              <div class="chart-title"><span class="chart-label" data-i18n="swapGraph">Swap · last 3 min</span><button type="button" class="chart-expand" data-chart="swap" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <svg id="swapChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg><div class="chart-stats" id="swapStats"></div>
            </div>
            <div class="chart-card" data-chart-card="net">
              <div class="chart-title"><span data-i18n="networkGraph">Network traffic</span><span class="legend"><span><i></i><span data-i18n="rx">Rx</span></span><span><i class="second"></i><span data-i18n="tx">Tx</span></span></span><button type="button" class="chart-expand" data-chart="net" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <svg id="netChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg><div class="chart-stats" id="netStats"></div>
            </div>
            <div class="chart-card" data-chart-card="io">
              <div class="chart-title"><span data-i18n="diskGraph">Disk I/O</span><span class="legend"><span><i></i><span data-i18n="read">Read</span></span><span><i class="second"></i><span data-i18n="write">Write</span></span></span><button type="button" class="chart-expand" data-chart="io" aria-label="Expand graph" title="Expand graph">⤢</button></div>
              <svg id="ioChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg><div class="chart-stats" id="ioStats"></div>
            </div>
          </div>
          <div class="help-cluster"><button type="button" class="help-button" data-help="historyNote" aria-label="Help">?</button></div>
          <details class="details" id="coresDetails">
            <summary><span data-i18n="perCore">CPU usage per core</span> <span id="coreCount"></span></summary>
            <div id="coreList" class="core-grid"></div>
          </details>
        </section>

        <section class="panel" id="panel-processes" data-panel="processes">
          <h2><span class="icon" aria-hidden="true">☷</span><span data-i18n="processes">Top processes</span></h2>
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
      <div class="dialog-actions"><button type="button" class="control" id="resetSettings" data-i18n="resetSettings">Reset preferences</button><button type="button" class="control primary" id="doneSettings" data-i18n="done">Done</button></div>
    </dialog>
    <dialog class="dialog zoom-dialog" id="chartDialog" aria-labelledby="zoomTitle">
      <div class="dialog-head"><h2 id="zoomTitle">—</h2><button type="button" class="control" id="closeChart" aria-label="Close">×</button></div>
      <svg id="zoomChart" class="chart" viewBox="0 0 400 100" preserveAspectRatio="none" role="img"></svg>
      <div class="help-cluster"><button type="button" class="help-button" data-help="historyNote" aria-label="Help">?</button></div>
    </dialog>

    <footer class="foot">Monitor made Simple 1.0.3 · PHP <?= htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8') ?> · <span data-i18n="footer">One file. No dependencies. Read-only monitoring.</span></footer>
  </div>
  <script nonce="<?= $nonce ?>">
'use strict';
// =============================================================
// 19. JAVASCRIPT AND I18N
// =============================================================
const words = {
  en: {
    "contextHelp": "Help",
    "currentValue": "Current",
    "maxValue": "Peak",
    "maxShort": "max",
    "selfCheck": "This monitor (local probe)",
    "selfCheckExplanation": "Local probe with fixed IP. The TLS name is inferred from SERVER_NAME (or explicitly configured). Public TLS may require a separate HTTPS check.",
    "selfCheckNeedsConfig": "Local HTTP probe failed: check the local port and virtual host configuration.",
    "selfProbeMismatch": "The local endpoint did not return the expected monitor header.",
    "httpPending": "Pending",
    "lastCheck": "Last checked",
    "staleResult": "stale result",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "Change theme",
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
    "contextHelp": "Aide",
    "currentValue": "Actuel",
    "maxValue": "Maximum",
    "maxShort": "max.",
    "selfCheck": "Ce moniteur (sonde locale)",
    "selfCheckExplanation": "Sonde à IP locale fixe. Le nom TLS vient de SERVER_NAME (ou de la configuration). Vérifiez le TLS public avec une cible HTTPS dédiée.",
    "selfCheckNeedsConfig": "Sonde locale inaccessible : vérifier le port et le virtual host.",
    "selfProbeMismatch": "La réponse locale ne comporte pas la signature du moniteur attendue.",
    "httpPending": "En attente",
    "lastCheck": "Dernier contrôle",
    "staleResult": "résultat ancien",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "Changer le thème",
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
    "contextHelp": "Ayuda",
    "currentValue": "Actual",
    "maxValue": "Máximo",
    "maxShort": "máx.",
    "selfCheck": "Este monitor (sonda local)",
    "selfCheckExplanation": "Sonda con IP local fija. El nombre TLS proviene de SERVER_NAME o la configuración. El TLS público puede necesitar otra comprobación HTTPS.",
    "selfCheckNeedsConfig": "Falla la sonda local: compruebe el puerto y el servidor virtual.",
    "selfProbeMismatch": "La respuesta local no contiene el encabezado del monitor esperado.",
    "httpPending": "Pendiente",
    "lastCheck": "Última comprobación",
    "staleResult": "resultado antiguo",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "Cambiar tema",
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
    "contextHelp": "帮助",
    "currentValue": "当前",
    "maxValue": "峰值",
    "maxShort": "峰值",
    "selfCheck": "此监控器（本地检测）",
    "selfCheckExplanation": "固定本地 IP 探测，TLS 名称来自 SERVER_NAME 或显式配置。公网 TLS 可单独添加 HTTPS 探测。",
    "selfCheckNeedsConfig": "本地检测失败：请检查端口和虚拟主机配置。",
    "selfProbeMismatch": "本地响应缺少预期的 monitor 标头。",
    "httpPending": "等待检测",
    "lastCheck": "上次检测",
    "staleResult": "过期结果",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "更换主题",
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
    "contextHelp": "सहायता",
    "currentValue": "वर्तमान",
    "maxValue": "अधिकतम",
    "maxShort": "अधि.",
    "selfCheck": "यह मॉनिटर (स्थानीय जाँच)",
    "selfCheckExplanation": "स्थिर स्थानीय IP से जाँच; TLS नाम SERVER_NAME या स्पष्ट कॉन्फ़िगरेशन से आता है। सार्वजनिक TLS के लिए अलग HTTPS जाँच जोड़ें।",
    "selfCheckNeedsConfig": "स्थानीय जाँच विफल: पोर्ट और वर्चुअल होस्ट जाँचें।",
    "selfProbeMismatch": "स्थानीय प्रतिक्रिया में अपेक्षित monitor हेडर नहीं है।",
    "httpPending": "प्रतीक्षारत",
    "lastCheck": "अंतिम जाँच",
    "staleResult": "पुराना परिणाम",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "थीम बदलें",
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
    "contextHelp": "ヘルプ",
    "currentValue": "現在",
    "maxValue": "最大",
    "maxShort": "最大",
    "selfCheck": "このモニター（ローカル検査）",
    "selfCheckExplanation": "固定ローカルIPを検査し、TLS名にはSERVER_NAMEまたは明示設定を使用します。公開TLSには別のHTTPS検査が必要な場合があります。",
    "selfCheckNeedsConfig": "ローカル検査に失敗しました。ポートと仮想ホストを確認してください。",
    "selfProbeMismatch": "ローカル応答に予期した monitor ヘッダーがありません。",
    "httpPending": "待機中",
    "lastCheck": "最終チェック",
    "staleResult": "古い結果",
    "processPss": "PSS",
    "processRss": "RSS",
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
    "changeTheme": "テーマ変更",
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
const styles = ['operations', 'pro', 'zen'];
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

const chartKeys = {cpu:'cpuGraph',ram:'memoryGraph',swap:'swapGraph',net:'networkGraph',io:'diskGraph'};
const panelGroups = {
  left:['activity','processes','storage','services'],
  right:['system','network','http','hardware','pressure'],
};
const panelLabels = {
  activity:'activity', processes:'processes', storage:'storage', services:'services',
  system:'system', network:'network', http:'httpChecks', hardware:'hardware', pressure:'pressure',
};
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
function updateBar(id, value) {
  const fill = $(id);
  fill.style.width = (value ?? 0) + '%';
  fill.className = value >= 90 ? 'bad' : value >= 75 ? 'warn' : '';
}
function appendHistory(key, value) {
  state.history[key].push(Number.isFinite(value) ? value : null);
  if (state.history[key].length > HISTORY_LIMIT) state.history[key].shift();
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
  data.hit.setAttribute('aria-label',(data.label || id) + ' · ' + chartSampleText(data,sample));
  const x = count === 1 ? 200 : sample * 400 / (count-1);
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
function plot(id, series, scale = 100, key = 'cpu') {
  const svg = $(id);
  let data = chartData[id];
  if (!data) {
    const drawing = svgEl('g');
    const guide = svgEl('line',{x1:0,x2:0,y1:17,y2:95,stroke:'var(--accent)','stroke-width':1.5,'stroke-dasharray':'3 3'});
    guide.style.display = 'none';
    const hit = svgEl('rect',{x:0,y:0,width:400,height:100,fill:'transparent',tabindex:0,role:'slider','aria-valuemin':0,'aria-valuemax':100});
    hit.addEventListener('pointermove',event => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width) return;
      const n = Math.max(0,...(chartData[id]?.series || []).map(v=>v.length));
      if (!n) return;
      chartData[id].lastPointer = {clientX:event.clientX,clientY:event.clientY};
      const fraction = Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width));
      showChartSample(id,Math.round(fraction*(n-1)),event);
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
    data = chartData[id] = {svg,drawing,guide,hit,lastPointer:null};
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
  for (const y of [25,50,75]) data.drawing.append(svgEl('line',{x1:0,x2:400,y1:y,y2:y,stroke:'currentColor',opacity:'.12'}));
  const valid = series.flat().filter(v=>Number.isFinite(v));
  const max = scale === 'auto' ? Math.max(1,...valid)*1.12 : scale;
  const legend = svgEl('text',{x:394,y:13,'text-anchor':'end','font-size':11,fill:'currentColor',opacity:'.65'});
  legend.textContent = valid.length ? (scale === 'auto' ? speed(max) : '100 %') : '—';
  data.drawing.append(legend);
  series.forEach((values,index)=> {
    let segment = '';
    const paths = [];
    values.forEach((value,i)=> {
      if (!Number.isFinite(value)) {if (segment) paths.push(segment); segment=''; return;}
      const x = values.length === 1 ? 200 : i*400/(values.length-1);
      const y = 94-Math.max(0,Math.min(1,value/max))*85;
      segment += (segment ? ' L ' : 'M ')+x.toFixed(1)+' '+y.toFixed(1);
    });
    if (segment) paths.push(segment);
    const finite = values.map((value,i)=>({value,i})).filter(v=>Number.isFinite(v.value));
    if (finite.length===1) {
      const v=finite[0];
      data.drawing.append(svgEl('circle',{cx:values.length===1?200:v.i*400/(values.length-1),cy:94-Math.max(0,Math.min(1,v.value/max))*85,r:3,fill:index===0?'var(--accent)':'var(--good)'}));
    }
    for (const part of paths) data.drawing.append(svgEl('path',{d:part,fill:'none',stroke:index===0?'var(--accent)':'var(--good)','stroke-width':2.5,'stroke-linejoin':'round','vector-effect':'non-scaling-stroke'}));
  });
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
  plot('zoomChart', seriesForChart(key), ['net','io'].includes(key) ? 'auto' : 100, key);
}
function renderCharts() {
  for (const [key,id] of Object.entries({cpu:'cpuChart',ram:'ramChart',swap:'swapChart',net:'netChart',io:'ioChart'})) {
    const series = seriesForChart(key);
    plot(id, series, ['net','io'].includes(key) ? 'auto' : 100, key);
    const formatter = ['net','io'].includes(key) ? speed : pct;
    const stats = $(key + 'Stats');
    const summarize = samples => {
      const finite = samples.filter(Number.isFinite);
      const latest = [...finite].at(-1);
      const maximum = finite.length ? Math.max(...finite) : null;
      return t('currentValue') + localeColon() + (latest == null ? '—' : formatter(latest))
        + ' · ' + t('maxValue') + localeColon() + (maximum == null ? '—' : formatter(maximum));
    };
    if (stats) {
      stats.replaceChildren();
      const labels = key === 'net' ? ['rx','tx'] : key === 'io' ? ['read','write'] : [];
      for (let i = 0; i < series.length; i++) {
        const finite = series[i].filter(Number.isFinite);
        const last = finite.length ? finite[finite.length-1] : null;
        const peak = finite.length ? Math.max(...finite) : null;
        const shortStats = (labels[i] ? (i===0 ? '↓ ' : '↑ ') : '')
          + (last == null ? '—' : formatter(last)) + ' (' + t('maxShort') + ' '
          + (peak == null ? '—' : formatter(peak)) + ')';
        const div = node('span','',labels[i] ? shortStats : summarize(series[i]));
        stats.append(div);
        if (labels[i] && i===0) stats.append(document.createTextNode(' · '));
      }
    }
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
function renderProcesses(data) {
  const processes = data.processes?.items || [];
  const cpu = processes.filter(proc => Number.isFinite(proc.cpuPercent))
    .sort((a,b) => b.cpuPercent - a.cpuPercent).slice(0,5);
  const ram = processes.filter(proc => Number.isFinite(proc.rssBytes))
    .sort((a,b) => b.rssBytes - a.rssBytes).slice(0,5);
  const swap = processes.filter(proc => Number.isFinite(proc.swapBytes) && proc.swapBytes > 0)
    .sort((a,b) => b.swapBytes - a.swapBytes).slice(0,5);
  function fill(id, list, kind) {
    const target = $(id);
    target.replaceChildren();
    if (!list.length) { empty(target, !processes.length ? t('noProcess') : kind === 'swap' ? t('noSwapProcess') : t('estimating')); return; }
    for (const proc of list) {
      const item = node('div','process-item');
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
    }
  }
  fill('processCpuList',cpu,'cpu');
  fill('processRamList',ram,'ram');
  fill('processSwapList',swap,'swap');
  $('collaboraNote').hidden = !processes.some(proc => /^(?:forkit|kit_spare(?:_.*)?)$/i.test(proc.name || ''));
  $('processHelpCluster').querySelector('[data-help]').dataset.help = (data.processes?.partial ? 'processPartial' : 'processNote') + ',ramFormula,pssExplanation,swapProcessExplanation';
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
      let message = check.tlsDays === null ? t('tlsUnavailable') :
        `${t('tlsExpires')}${localeColon()}${number(check.tlsDays,0)} ${t('days')} (${check.tlsExpiry})`;
      const div = node('div','smalltext',message);
      if (check.tlsDays !== null && check.tlsDays < 14) div.style.color = 'var(--warn)';
      item.append(div);
    }
    if (check.error) item.append(node('div','smalltext',t(check.error)));
    target.append(item);
  }
}
function renderHealth(data) {
  const warnings = [];
  let severity = 0;
  function add(level, reason) {
    severity = Math.max(severity,level);
    warnings.push(reason);
  }
  function usage(value, threshold, key) {
    if (value === null || !Number.isFinite(value)) return;
    if (value >= Math.min(99, threshold+10)) add(2,`${t(key)}${localeColon()}${pct(value)}`);
    else if (value >= threshold) add(1,`${t(key)}${localeColon()}${pct(value)}`);
  }
  usage(state.rates.cpu, thresholds.cpu,'cpu');
  const ram = data.memory?.ram;
  usage(ram ? percentage(ram.used, ram.total) : null, thresholds.ram,'memory');
  for (const disk of data.disks || []) {
    usage(percentage(disk.used, disk.total), thresholds.disk, `${disk.mount}`);
    if (disk.inodes) usage(percentage(disk.inodes.used,disk.inodes.total),90,`${disk.mount} · ${t('inodes')}`);
  }
  const swapping = Math.max(0, state.rates.swapIn || 0) + Math.max(0, state.rates.swapOut || 0);
  if (swapping >= 100) add(2,`${t('swapActivity')}${localeColon()}${number(swapping)} ${t('pagesPerSecond')}`);
  else if (swapping >= 10) add(1,`${t('swapActivity')}${localeColon()}${number(swapping)} ${t('pagesPerSecond')}`);
  for (const [key, label] of [['memory','pressureMemory'],['io','pressureIo']]) {
    const p = data.pressure?.[key];
    if (p && p.avg10 >= 30) add(2,`${t(label)} PSI${localeColon()}${pct(p.avg10)}`);
    else if (p && p.avg10 >= 10) add(1,`${t(label)} PSI${localeColon()}${pct(p.avg10)}`);
  }
  const tcpDown = (data.services || []).filter(s => !s.online);
  if (tcpDown.length) add(1,`${t('services')}${localeColon()}${tcpDown.map(x=>x.name).slice(0,3).join(', ')}`);
  const httpDown = (data.httpChecks || []).filter(s => s.online === false && !s.stale);
  const realDown = httpDown.filter(s => !s.self);
  const selfDown = httpDown.filter(s => s.self);
  if (realDown.length) add(2,`${t('httpChecks')}${localeColon()}${realDown.map(x=>x.name).slice(0,3).join(', ')}`);
  if (selfDown.length) add(1, t('selfCheckNeedsConfig'));
  for (const check of data.httpChecks || []) {
    if (!check.stale && check.tlsDays !== null && check.tlsDays < 14 && check.online) {
      add(check.tlsDays < 3 ? 2 : 1,`${check.name}${localeColon()}${t('tlsExpires')} ${number(check.tlsDays,0)} ${t('days')}`);
    }
  }
  for (const link of data.network || []) {
    if (link.category !== 'physical') continue;
    const rate = state.rates.network[link.name];
    if (rate && ((rate.rxErrors || 0)+(rate.txErrors || 0) >= 1 || (rate.dropped || 0) >= 10)) {
      add(1,`${link.name}${localeColon()}${t('networkErrors')}`);
    }
  }
  const panel = $('healthBanner');
  panel.className = 'health-banner ' + ['ok','warn','bad'][severity];
  setText('healthTitle',t(['healthy','healthWarn','healthCritical'][severity]));
  setText('healthDescription',severity ? t('healthNeedsAttention') : t('healthAllClear'));
  const list = $('healthReasons');
  list.replaceChildren();
  for (const reason of warnings.slice(0,5)) list.append(node('span','',`• ${reason}`));
  if (warnings.length > 5) list.append(node('span','',`+${warnings.length-5}`));
  const swap = data.memory?.swap;
  if (!warnings.length && swap?.total > 0 && percentage(swap.used,swap.total) >= 50 && swapping < 1) {
    list.append(node('span','',t('swapIdle')));
  }
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
  updateBar('cpuBar', state.rates.cpu);
  setText('cpuExtra', system.load?.length ? `${t('load')}${localeColon()}${system.load.map(v => number(v)).join(' / ')}` : '—');

  setText('ramValue', pct(ramPct));
  updateBar('ramBar', ramPct);
  setText('ramExtra', ram ? `${bytes(ram.used)} / ${bytes(ram.total)}` : '—');

  setText('swapValue', swap && swap.total === 0 ? '0 %' : pct(swapPct));
  updateBar('swapBar', swapPct);
  const swapRate = Math.max(0, state.rates.swapIn || 0) + Math.max(0, state.rates.swapOut || 0);
  $('swapBar').className = swapRate >= 100 ? 'bad' : swapRate >= 10 ? 'warn' : '';
  setText('swapExtra', swap && swap.total === 0
    ? t('swapDisabled')
    : swap ? `${bytes(swap.used)} / ${bytes(swap.total)}` : t('unknown'));

  setText('diskValue', pct(diskPct));
  updateBar('diskBar', diskPct);
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
    } else if (!/^(?:fuse(?:\.|$)|nfs|cifs|smb|sshfs|davfs)/i.test(disk.type || '')) {
      item.append(node('div','inode-line', `${t('inodes')}: ${t('unknown')}`));
    }

    const aliases = (disk.mounts || []).filter(name => name !== disk.mount);
    if (aliases.length) {
      const details = node('details', 'details');
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
  target.replaceChildren(row(t('cpuModel'), s.cpuModel), row(t('cores'), s.logicalCores));
  if (!data.temperatures?.length) {
    target.append(row(t('temperature'), t('unknown')));
    return;
  }
  for (const sensor of data.temperatures) {
    target.append(row(sensor.name, number(sensor.celsius) + ' °C'));
  }
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
// 24. PANEL RENDERING
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
  if (state.latest) render(state.latest);
  setText('connectionText', state.connected ? t('online') : (state.latest ? t('offline') : t('connecting')));
  if ($('errorBanner').classList.contains('show')) {
    $('errorBanner').textContent = t('refreshError') + ' (' + state.errorDetail + ')';
  }
}
function applyStyle() {
  document.documentElement.dataset.style = visualStyle;
  $('styleChoice').value = visualStyle;
  document.querySelector('meta[name="color-scheme"]').content = visualStyle === 'operations' ? 'dark light' : 'light dark';
}
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
$('refresh').addEventListener('click', () => poll());

// =============================================================
// 26. PREFERENCES AND DIALOGS
// =============================================================
// =============================================================
// =============================================================
let currentDashboardColumns = 0;
let dashboardMeasured = false;
const panelHeights = {};
const panelWeights = {
  activity:2.8, system:1.3, processes:1.8, network:2.0, storage:1.9,
  http:1.0, services:1.0, hardware:.8, pressure:.8,
};
function layoutDashboard(force = false) {
  const dashboard = document.querySelector('.dashboard');
  const width = dashboard.clientWidth;
  const count = width >= 1940 ? 4 : width >= 1340 ? 3 : width >= 790 ? 2 : 1;
  if (!force && count === currentDashboardColumns) return;
  currentDashboardColumns = count;
  dashboard.style.setProperty('--dashboard-cols', String(count));
  const columns = Array.from({length:count}, () => node('div','column'));
  const targetLists = Array.from({length:count}, () => []);
  if (count === 1) targetLists[0].push(...panelOrder.left, ...panelOrder.right);
  else if (count === 2) {
    targetLists[0].push(...panelOrder.left);
    targetLists[1].push(...panelOrder.right);
  } else {
    const totalHeight = Array(count).fill(0);
    const ordered = [];
    const longest = Math.max(panelOrder.left.length, panelOrder.right.length);
    for (let i = 0; i < longest; i++) {
      if (panelOrder.left[i]) ordered.push(panelOrder.left[i]);
      if (panelOrder.right[i]) ordered.push(panelOrder.right[i]);
    }
    for (const id of ordered) {
      const minHeight = Math.min(...totalHeight);
      const index = totalHeight.indexOf(minHeight);
      targetLists[index].push(id);
      totalHeight[index] += hiddenPanels.has(id) ? 0.01 : (panelHeights[id] ?? panelWeights[id] ?? 1);
    }
  }
  const panels = new Map(Object.keys(panelLabels).map(id => [id, $('panel-' + id)]));
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
  for (const name of Object.keys(panelLabels)) $('panel-' + name).hidden = hiddenPanels.has(name);
  for (const name of Object.keys(chartKeys)) {
    const card = document.querySelector(`[data-chart-card="${name}"]`);
    if (card) card.hidden = hiddenCharts.has(name);
  }
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
    thresholds[name]=validChoice(input.value,Array.from({length:46},(_,i)=>i+50),85);
    input.value=String(thresholds[name]);
    saveSetting('esm32Warn'+name[0].toUpperCase()+name.slice(1),String(thresholds[name]));
    if (state.latest) renderHealth(state.latest);
  });
}
$('resetSettings').addEventListener('click', () => {
  refreshSeconds = <?= (int) $refresh ?>; graphMinutes = 3;
  Object.assign(thresholds,{cpu:85,ram:85,disk:85});
  hiddenPanels.clear(); hiddenCharts.clear();
  panelOrder={left:[...panelGroups.left],right:[...panelGroups.right]};
  for (const key of ['esm32Refresh','esm32Period','esm32WarnCpu','esm32WarnRam','esm32WarnDisk',
    'esm32HiddenPanels','esm32HiddenCharts','esm32Order']) {
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
  renderSystem(data);
  renderProcesses(data);
  renderHttp(data);
  renderCores();
  renderDisks(data);
  renderDiskIo(data);
  renderNetwork(data);
  renderServices(data);
  renderHardware(data);
  renderPressure(data);
  renderCharts();
  if (!dashboardMeasured && currentDashboardColumns >= 3) requestAnimationFrame(rebalanceDashboardOnce);
}

async function poll() {
  if (state.busy || !state.active) return;
  state.busy = true;
  try {
    const response = await fetch(location.pathname + '?api=stats', {
      cache: 'no-store', credentials: 'same-origin',
    });
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
    $('connectionDot').className = 'dot ok';
    state.connected = true;
    state.errorDetail = '';
    setText('connectionText', t('online'));
    $('errorBanner').classList.remove('show');
  } catch (error) {
    $('connectionDot').className = 'dot error';
    state.connected = false;
    setText('connectionText', t('offline'));
    state.errorDetail = String(error?.message || 'error');
    $('errorBanner').textContent = t('refreshError') + ' (' + state.errorDetail + ')';
    $('errorBanner').classList.add('show');
    state.previous = null;
  } finally {
    state.busy = false;
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
    state.previous = null;
    poll();
  }
});
applyStyle();
applyPreferences();
applyLanguage();
poll();
setRefresh();
  </script>
</body>
</html>
