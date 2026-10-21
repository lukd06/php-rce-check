# php-rce-check

A read-only Bash script that checks whether a Linux server is affected by the critical PHP remote code execution vulnerabilities published on **2026-10-21**:

| CVE | Advisory | Issue |
|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state |

**Fixed versions:** PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, or a distribution / LTS vendor package that contains the backported fix.

Official announcement: [php.net security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)

> **Affected:** every PHP installation that serves web requests: PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. The risk is highest for **mod_php**, where an unauthenticated request can trigger the attack before any application code runs.

## Quick start

```bash
git clone https://github.com/lukd06/php-rce-check.git
cd php-rce-check
sudo ./php-rce-check.sh
```

Or as a one-off without cloning:

```bash
curl -fsSLO https://raw.githubusercontent.com/lukd06/php-rce-check/main/php-rce-check.sh
less php-rce-check.sh        # always read scripts before running them as root
sudo bash php-rce-check.sh
```

Run it as **root**. Without root, the script cannot inspect other users' processes, `/proc/<pid>/exe`, some configs or containers, and the results will be incomplete.

## What it checks

1. **Installed PHP binaries**: `php`, `php-fpm`, `php-cgi`, `lsphp`, `frankenphp` in the standard paths plus Remi, Plesk, cPanel EA-PHP, CloudLinux alt-php and LiteSpeed locations. Every version is compared against the fixed releases.
2. **Distribution backports**: Debian, Ubuntu, RHEL and others often keep the old upstream version number when they backport a fix. For packaged binaries the script looks for the CVE IDs in the package changelog (`dpkg` / `rpm`). If the version is old and the CVEs are not in the changelog, the binary is reported as vulnerable.
3. **Apache mod_php**: reads the PHP version straight out of `libphp*.so` and checks whether the module is actually loaded (`apachectl -M`).
4. **Running processes**: detects FPM masters/workers, php-cgi, LiteSpeed, FrankenPHP and Apache processes that still run an **old binary or module that was replaced on disk**. This is the most common mistake after patching: the package is updated but the service was never restarted.
5. **Resource limits**: warns if PHP processes run with `RLIMIT_AS` / `RLIMIT_DATA` (systemd `LimitAS=` / `LimitDATA=`). The advisory explicitly advises against these limits because they can trigger the vulnerable allocation failure.
6. **Docker / Podman containers**: runs `php -v` (and friends) inside every running container and checks for backports in the container's packages.
7. **Mitigations** for each running FPM pool and for mod_php. These are only relevant if you cannot update right away:
   - `memory_limit=-1`, and whether it is enforced via `php_admin_value` so applications cannot override it
   - `post_max_size` (8M without uploads, at most 32M with uploads) and `upload_max_filesize < post_max_size`
   - `session.upload_progress.enabled=0`
   - `fatal_error_backtraces=0` (PHP 8.5)
   - `.htaccess` / `.user.ini` files that override these settings
   - configuration files changed **after** the workers were started, which means a restart is still needed
8. **Available PHP package updates** from the local package cache (`apt`, `dnf`, `yum`, `apk`).

The script is **read-only**: it does not install, change, restart or delete anything.

## Options

| Option | Effect |
|---|---|
| `--no-containers` | Skip the Docker / Podman check (no `exec` into containers) |
| `--no-color` | Disable colored output (also disabled automatically when not writing to a terminal) |
| `-h`, `--help` | Show help |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerable PHP installation found |
| `1` | At least one vulnerable installation, container or running process |
| `2` | Nothing clearly vulnerable, but there are warnings to review |
| `64` | Invalid option |

This makes it easy to use in monitoring, cron jobs or configuration management.

## Example output

```text
PHP RCE check - CVE-2026-109618 / CVE-2026-109619
Host: web01   Date: 2026-10-21 16:35:13 CEST

== 1. Installed PHP binaries ==
  [VULNERABLE] /usr/sbin/php-fpm8.3: PHP 8.3.6 - older than the fixed release, no backport in changelog [package: php8.3-fpm 8.3.6-0ubuntu0.24.04.12]

== 3. Running processes ==
  [VULNERABLE] PID 812 (php-fpm8.3) is still running the OLD binary that has since been replaced (PHP 8.3.6) -> restart the service

== 5. Mitigations (only relevant if you cannot update right away) ==
  PHP-FPM 8.3.6 (master PID 812, /etc/php/8.3/fpm/php-fpm.conf)
  Pool [www]
  [WARNING]    memory_limit=128M (source: php.ini) - mitigation for CVE-2026-109618: -1 via php_admin_value
  [OK]         post_max_size=8M
  [WARNING]    session.upload_progress.enabled=1 - mitigation for CVE-2026-109619: set to 0 (php.ini/pool, NOT ini_set/.user.ini) and restart all workers

== Result ==
  2 vulnerable finding(s), 2 warning(s).
```

## Fixing findings

1. Update PHP to **8.5.12, 8.4.27, 8.3.36 or 8.2.35**, or install your distribution's patched package:
   ```bash
   # Debian / Ubuntu
   sudo apt update && sudo apt install --only-upgrade 'php*' 'libapache2-mod-php*'
   # RHEL / Alma / Rocky / Fedora
   sudo dnf upgrade 'php*'
   # Alpine
   sudo apk upgrade 'php*'
   ```
2. **Restart every PHP worker and Apache**, for example `systemctl restart php8.3-fpm apache2`.
3. For containers: pull or rebuild the image and **recreate** the container. Restarting the old container is not enough.
4. Run the script again and confirm that it exits with `0`.

PHP 8.1 and older no longer receive updates from the PHP project. Check with your distribution or LTS vendor for backports, or upgrade to a supported branch. The PHP security team also published minimal source backports for [7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619) and [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619).

## Running across many servers

With SSH:

```bash
for h in web01 web02 web03; do
  echo "### $h"
  ssh "$h" 'sudo bash -s -- --no-color' < php-rce-check.sh
  echo "exit=$?"
done
```

With Ansible:

```yaml
- name: Check PHP RCE CVE-2026-109618/109619
  ansible.builtin.script: php-rce-check.sh --no-color
  become: true
  register: php_check
  failed_when: php_check.rc == 1
  changed_when: false
```

## Requirements

- Linux with `/proc`
- Bash 4 or newer
- `procps` (`ps`), coreutils, `grep`, `sed`, `awk`, `find`
- Optional: `dpkg` / `rpm` / `apk` for the backport check, `apachectl` / `apache2ctl` / `httpd` for the mod_php check, `docker` / `podman` for containers

## Limitations

- **Self-built EOL versions:** if you built PHP 7.4, 8.0 or 8.1 from the php-src backport branches, the version number does not change, so the script still reports them as vulnerable. Confirm these manually.
- **vhost-level settings:** for mod_php, `php_admin_value` / `php_value` lines are evaluated globally across the Apache config. Values set only in individual vhosts need to be checked by hand.
- **ini_set() in application code** is not scanned. An application can lower `memory_limit` at runtime unless it is set with `php_admin_value`.
- **php-cgi, LiteSpeed and FrankenPHP** are version-checked, but their ini settings (for example `php_ini` in a Caddyfile) are not evaluated against the mitigations.
- **Alpine (`apk`)** has no package changelog, so backports cannot be verified there; Alpine normally ships upstream versions.
- The backport check relies on the distribution listing the CVE IDs in the package changelog. Minimal container images that strip `/usr/share/doc` are reported as "cannot be verified".
- The mitigations reduce exposure to specific attack paths but **do not make an installation safe**. Only updating is a complete fix.

## Disclaimer

This script is provided as-is, without warranty. It is a helper for triage, not a guarantee that a system is safe. Always follow the [official advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and your vendor's guidance.
