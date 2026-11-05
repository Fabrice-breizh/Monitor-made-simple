# Monitor made Simple

**A lightweight Linux monitoring dashboard in a single PHP file.** No database, no agent, no external assets, no dependencies: drop `monitor.php` on your web server, set a password, and open it in your browser.

<img src="monitor_made_simple.png" alt="Monitor made Simple dashboard" width="900">

## Features

- **At a glance**: CPU, memory, swap, disk usage and uptime, plus a health banner that tells you when a threshold or a check needs attention.
- **Live charts** for CPU, RAM, swap, network traffic and disk I/O, over 1, 3 or 10 minutes, each one expandable.
- **System**: OS, kernel, architecture, PHP version, CPU model and cores, load average, cached memory, swap activity.
- **Network**: every interface, sorted into physical, virtual and VPN (WireGuard, Tailscale, tun/tap…), with IPv4/IPv6 addresses, MAC, MTU, link speed, errors and drops.
- **Storage**: mounted filesystems with duplicate mounts merged, inode usage, and per-device disk activity. Remote mounts (NFS, SMB, rclone…) are opt-in, through an allowlist.
- **Pressure Stall Information** (CPU, memory, I/O) and **hardware temperatures**.
- **Top processes**: top 5 by CPU, by RAM (with PSS) and by swap; php-fpm pools are named.
- **Service checks**: TCP ports of your local services (SSH, web server, database…), with latency.
- **HTTP/HTTPS checks**: status code, latency and **TLS certificate expiry**, including a self-check of the dashboard itself.
- **JSON API**: all metrics at `monitor.php?api=stats`, behind the same authentication.
- **6 languages**: English, Français, Español, 中文, हिन्दी, 日本語.
- **3 interface styles** (Operations, Pro, Zen) and a settings panel to show or hide panels. Your choices are remembered by your browser.

## Requirements

- A **Linux** server: metrics are read from `/proc` and `/sys`.
- **PHP 8.1 or newer**, served by any web server (Apache, Nginx + PHP-FPM, Caddy…).
- PHP must be allowed to read `/proc` and `/sys`: if `open_basedir` is set, add them to it.
- Optional: `proc_open` and `df` for inode metrics, the `openssl` extension for certificate expiry dates.

## Installation

1. **Copy `monitor.php`** to a folder served by your web server.

2. **Create a password hash** (replace `your-password`):

   ```bash
   php -r 'echo password_hash("your-password", PASSWORD_DEFAULT), PHP_EOL;'
   ```

3. **Configure the login** at the top of `monitor.php`: the default user name is `admin` (change `ESM_AUTH_USER` if you like), then give the hash to the dashboard in one of two ways:
   - **Recommended**: as the `ESM_PASSWORD_HASH` environment variable, for example in your PHP-FPM pool (`env[ESM_PASSWORD_HASH] = ...`) or with Apache's `SetEnv`.
   - Or paste it in the `ESM_PASSWORD_HASH` constant of the file.

4. **Open** `https://your-server/monitor.php` and log in.

   Tip: give the file a less obvious name, such as `stats-4f7a.php`, so that the dashboard is harder to find.

> **Use HTTPS.** The dashboard uses HTTP Basic authentication, which sends the password with every request: only HTTPS keeps it private.

If your browser keeps asking for the password with Apache and PHP-FPM, the `Authorization` header is probably not passed to PHP: add `CGIPassAuth On` to the folder's configuration.

## Configuration

Everything is set with constants in the first section of `monitor.php`:

| Constant | What it does |
|----------|--------------|
| `ESM_TITLE` | Name shown in the header |
| `ESM_REFRESH_SECONDS` | Refresh interval (2 to 60 seconds, default 5) |
| `ESM_AUTH_USER`, `ESM_PASSWORD_HASH` | Login (see Installation) |
| `ESM_SERVICES` | TCP services to check: name, host IP, port |
| `ESM_HTTP_CHECKS` | HTTP/HTTPS endpoints to check: name, IP, host name, scheme, port, path |
| `ESM_SELF_CHECK`, `ESM_SELF_CHECK_*` | Self-check of the dashboard; set `ESM_SELF_CHECK_HOST` to your certificate's DNS name for HTTPS virtual hosts |
| `ESM_MONITOR_REMOTE_MOUNTS`, `ESM_REMOTE_MOUNT_ALLOWLIST` | Remote filesystems: off by default, or only the listed paths |
| `ESM_*_CACHE_SECONDS` | How long slower metrics (processes, services, inodes, remote mounts, HTTP checks) are cached |

Example of service list:

```php
const ESM_SERVICES = [
    ['name' => 'SSH',   'host' => '127.0.0.1', 'port' => 22],
    ['name' => 'HTTPS', 'host' => '127.0.0.1', 'port' => 443],
    ['name' => 'MySQL', 'host' => '127.0.0.1', 'port' => 3306],
];
```

## Security

- **Authentication is mandatory**: without a password hash, every request, including the JSON API, is refused. There is no bypass for local addresses, because reverse proxies often connect from loopback.
- Passwords are stored as **bcrypt hashes** only, never in plain text.
- Strict **Content Security Policy** with per-request nonces, no external resources, and hardened HTTP headers (no framing, no referrer, no caching).
- Checks only connect to the IP addresses you configure, never to an address taken from the request.
- The dashboard is read-only: it shows information and never changes anything on the server.

## License

Released under the [MIT License](LICENSE).

## Support

If you find this dashboard useful, you can [buy me a coffee](https://www.buymeacoffee.com/fabricebreizh) ☕
