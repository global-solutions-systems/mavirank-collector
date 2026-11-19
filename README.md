# mavirank collector

Ships the access and error logs of your web server, pseudonymised, to the mavirank log
analysis (Googlebot behaviour, crawl budget, 404/5xx, scans). Python 3.9+, standard library
only, read-only access to the logs, no inbound connections.

The collector runs on **your** server and is the only part of mavirank that does. Its source is
public so you can check what it reads and what it sends; the analysis itself is the hosted service
[mavirank](https://mavirank.com). The ingest URL and the token come from the install page of your log
source in mavirank.

## What it does

Every 5 minutes (cron or container loop) it:

1. fetches the settings of your log source from mavirank (`GET …/ingest/config`: allowed host
   names, query string mode, error log on/off, scan rules, limits),
2. reads new lines of the configured logs (offset per file, follows logrotate; compressed
   rotations are ignored),
3. parses nginx/Apache `combined` lines (optionally with a leading virtual host, e.g. Apache
   `vhost_combined`) and nginx/Apache error logs,
4. checks Googlebot against Google's published IP lists, then pseudonymises (see below),
5. sends gzip NDJSON batches (≤ 50 000 lines, ≤ 8 MiB) to `…/ingest/logs` and only then
   moves the offsets forward. Lines older than 30 days are skipped.

## Installation

One collector belongs to one website, i.e. one log source in mavirank. It runs in a user account
that can read the log files of this website - typically the SSH account of the website - and
needs neither root nor a system service nor Docker. Several websites means several log sources,
each with its own token and its own configuration (see `--name` below).

Requirements: SSH access, Python 3.9 or newer (`python3 -V`), cron (`crontab -l` works, or a cron
tool in the hosting panel) and read access to the access logs of your website.

Download the archive of the [latest release](https://github.com/global-solutions-systems/mavirank-collector/releases/latest),
compare its SHA-256 checksum with the one published next to it, then as the user who can read
the logs:

```sh
tar -xzf mavirank-collector-0.7.1.tar.gz
cd mavirank-collector-0.7.1
./install.sh                          # --python /path/to/python3.X if python3 is older than 3.9
editor ~/.config/mavirank-collector/collector.conf   # ingest_url, token, log paths, domain
~/.local/bin/mavirank-collector check
~/.local/bin/mavirank-collector run --dry-run
./install.sh --cron                   # adds the 5 minute crontab entry (safe to run again)
```

The installer always installs for the user who runs it. It copies the package to
`~/.local/share/mavirank-collector/` (no pip, no venv, nothing is downloaded), creates the command
`~/.local/bin/mavirank-collector`, the configuration `~/.config/mavirank-collector/collector.conf`
(mode 0600; an existing file is never overwritten) and the state directory
`~/.local/state/mavirank-collector` (0700). Without `--cron` it only prints the crontab line,
e.g. for the cron tool of a hosting panel:

```
*/5 * * * * '/home/<user>/.local/bin/mavirank-collector' run >/dev/null 2>&1 # mavirank-collector (install.sh)
```

Running the installer again updates the package and keeps the configuration. Two runs never
overlap (lock file in the state directory). Without `--config`, the collector reads
`~/.config/mavirank-collector/collector.conf` (`$XDG_CONFIG_HOME` is respected; if only
`/etc/mavirank-collector/collector.conf` of an older installation exists, that one) and keeps its
state in `~/.local/state/mavirank-collector` when `[state] dir` is not set.

Root is not needed and not recommended. On a server you administer where only root or the `adm`
group can read the logs, install it as a dedicated user in that group (e.g. `sudo useradd -m -G adm
mavirank`, then run `./install.sh --cron` as that user) rather than as root; the installer works as
root too but says so.

**Several websites in one account**: give each further website a short name (lowercase letters,
digits, `-`); package and command are shared, configuration, state and crontab entry are separate:

```sh
./install.sh --name shop --cron       # ~/.config/mavirank-collector/shop.conf, state ~/.local/state/mavirank-collector/shop
~/.local/bin/mavirank-collector --config ~/.config/mavirank-collector/shop.conf check
./uninstall.sh --name shop            # removes only this instance (--purge: also its configuration and state)
```

`./uninstall.sh` removes the crontab entry, the command and the package (the latter two only once
no named instance is left); `--purge` also deletes the configuration and state.

Where the logs are depends on the hosting. Examples (check the actual paths of your hosting;
`check` reports what it can read):

| Hosting | Access log (example) |
|---|---|
| many shared hostings | `~/logs/access.log*` or `~/logs/<domain>/access.log` |
| ISPConfig | `/var/www/clients/client*/web*/log/access.log` |
| Plesk | `/var/www/vhosts/system/<domain>/logs/access_ssl_log` (and `access_log` for http) |
| own server | `/var/log/nginx/access.log`, `/var/log/apache2/access.log` (readable for group `adm`) |

When a log file cannot be read, `check` names the file, its owner, group and mode and the user
and groups the collector runs as, so you can ask your hosting provider for read access.

Limits: hostings without SSH, without Python 3.9+ or without cron cannot run the collector.
Neither can it read logs that the hosting provider does not make readable for your account.

### Hosting panels with a protected home directory

Some panels (e.g. ISPConfig) make the home directory of the website's user read-only and offer a
private subdirectory instead. The installer notices this and names the option to use:

```sh
./install.sh --home ~/private            # everything below ~/private/.local and ~/private/.config
~/private/.local/bin/mavirank-collector check
./uninstall.sh --home ~/private          # the same value when removing
```

Unpack the archive and install **outside the document root** (not in `web/`, `htdocs/` or
`public_html/`): files there can be downloaded by anyone, and the configuration holds your token.

## Docker

For servers whose web server runs in a container: the collector runs as a second container and
reads the log files from a volume shared with the web server, read-only.

```yaml
services:
  web:
    image: nginx:stable
    volumes:
      - nginx-logs:/var/log/nginx
      - ./site.conf:/etc/nginx/conf.d/default.conf:ro
  mavirank-collector:
    image: ghcr.io/global-solutions-systems/mavirank-collector:0.7.1
    restart: unless-stopped
    environment:
      MAVIRANK_COLLECTOR_TOKEN: ${MAVIRANK_COLLECTOR_TOKEN}
    volumes:
      - ./collector.conf:/etc/mavirank-collector/collector.conf:ro
      - nginx-logs:/var/log/nginx:ro
      - collector-state:/var/lib/mavirank-collector
    # group_add: ["4"]   # gid that owns the log files, if it is not 4 (adm)
volumes:
  nginx-logs:
  collector-state:
```

The collector reads files only. Many web server images log to stdout/stderr only - the official
nginx image links `/var/log/nginx/access.log` and `error.log` to `/dev/stdout` and `/dev/stderr`,
and an empty named volume mounted there takes over these links. Then there is no file to read:
let the web server write the logs to additional files on the shared volume, e.g. in `site.conf`:

```nginx
access_log /dev/stdout;                     # keeps docker logs working
access_log /var/log/nginx/site-access.log;  # combined format, read by the collector
error_log  /var/log/nginx/site-error.log warn;
```

and set `access_log = /var/log/nginx/site-access.log`, `error_log = /var/log/nginx/site-error.log`
in `collector.conf`. The files must be readable for the collector (uid 10001, groups
`mavirank-collector` and `adm`/gid 4) and need rotation (e.g. logrotate on the host with
`copytruncate`, which the collector follows). A web server on the host instead of in a container:
mount its log directory (`/var/log/nginx`, Apache `/var/log/apache2` or `/var/log/httpd`)
read-only - never all of `/var/log`.

The configuration holds the token: it belongs to the container user and stays private, never
world-readable (`chmod 644` would show the token to every local user):

```sh
sudo install -d -m 0700 -o 10001 -g 0 /etc/mavirank-collector   # when the directory is mounted
sudo chown 10001:0 collector.conf && sudo chmod 600 collector.conf
```

Alternatively leave `token` out of the file and pass `MAVIRANK_COLLECTOR_TOKEN` (as above). `check`
names the uid when the configuration cannot be read. In the image, the configuration is
`/etc/mavirank-collector/collector.conf` and the state directory `/var/lib/mavirank-collector`.

The container runs as a non-root user and repeats `run` every 300 s. For an external scheduler use
`docker run --rm … ghcr.io/global-solutions-systems/mavirank-collector:0.7.1 run`. Commands:
`docker compose run --rm mavirank-collector check` and `… run --dry-run`.

## Configuration

`~/.config/mavirank-collector/collector.conf` (Docker: `/etc/mavirank-collector/collector.conf`);
other path: `--config` or `MAVIRANK_COLLECTOR_CONFIG`. See `examples/collector.conf`:

| Section / key | Meaning |
|---|---|
| `[mavirank] ingest_url` | Ingest URL from the install page, e.g. `https://app.example.com/api/v1/ingest` |
| `[mavirank] token` | Collector token `mvrk_log_…` (or env `MAVIRANK_COLLECTOR_TOKEN`); never printed, only its prefix |
| `[mavirank] ca_file`, `timeout` | optional CA bundle (TLS is always verified), request timeout (20 s) |
| `[mavirank] allow_insecure_http` | local development only: allow `http://` |
| `[logs] access_log` | access logs, comma separated, globs allowed |
| `[logs] error_log` | error logs (sent only if the log source has the error log enabled) |
| `[logs] format` | `auto`, `nginx_combined`, `apache_combined` |
| `[logs] server` | `nginx` or `apache` |
| `[logs] domain` | host name for lines without a virtual host column (required if the website has several host names) |
| `[logs] timezone` | time zone of error log timestamps: `local` (default), `UTC`, `+01:00`, `Europe/Berlin` |
| `[state] dir` | state directory (default `~/.local/state/mavirank-collector`; Docker: `/var/lib/mavirank-collector`) |
| `[bots] verify`, `ranges_file` | Googlebot verification on/off; optional local copy of Google's IP lists |

Only lines whose host name is among the allowed host names of the log source are sent.

## Commands

| Command | Purpose |
|---|---|
| `mavirank-collector check` | configuration, readable logs and recognised format, server reachable, token valid, clock difference; exit 0 = all good |
| `mavirank-collector run --dry-run` | parse and pseudonymise, print a summary and sample records, send nothing, write nothing (`--offline`: no network at all) |
| `mavirank-collector run` | one pass (used by cron) |
| `mavirank-collector run --every 300` | loop (container) |

Exit codes: `0` ok, `1` error, `2` configuration, `3` token or log source rejected (401/403),
`75` deferred (quota reached, rate limit, server or network unavailable; retried automatically,
`Retry-After` is respected).

## Privacy

- **IP addresses never leave the server.** `ip` is `n-` plus 10 hex characters of
  HMAC-SHA256(day key, IP). The day key is 32 random bytes per UTC day, stored only in the state
  directory (mode 0600) and deleted after two days; it is never transmitted. Pseudonyms differ
  per day and per server and cannot be reversed by mavirank.
- IP addresses inside paths, referers, user agents, requests and error messages are replaced by
  their pseudonyms as well - also percent-encoded ones and IPv6 right after a word and a colon
  (`client:2001:db8::1`). The ingest gateway masks anything left as `[ip]`.
- `net` (IPv4 /24, IPv6 /48) is sent only for rejected requests (4xx) that match a scan rule
  (e.g. `/.env`, `/wp-login.php`), and only if the log source allows it (`scanNet`), so you can
  block attacking networks.
- Query strings follow the setting of the log source: parameter names kept and values replaced
  by `x` (default), kept, or removed. Referers are always sent without query string.
- Error log lines are cut to 2 KiB. The user name of the combined format is never sent.
- Googlebot is verified on the server **before** pseudonymisation against Google's IP lists
  (cached 24 h). With the lists loaded they decide alone; only without any list a reverse DNS
  lookup (googlebot.com, google.com, gae.googleusercontent.com) with forward confirmation is
  used - other googleusercontent.com names are Google Cloud VMs, not Googlebot. Only `bot_verified`
  (`true`/`false`) is sent.

## Development

```sh
python3 -m unittest discover -s tests
python3 -m mavirank_collector --config tests/fixtures/dry-run.conf run --dry-run --offline
python3 tests/fixtures/shift_dates.py /tmp/logs   # fixture logs with timestamps ending now (stack test)
```

## License

MIT, see `LICENSE`.
