# Usage

`lilu` has two commands: `run`, the ingest daemon, and `extend`, the
LibreNMS report. Global options come before the command.

```shell
lilu [--config <file>] [--debug] <run|extend> [command options]
lilu --help
```

## Global options

| switch            | description                                          |
|-------------------|------------------------------------------------------|
| `--config <file>` | Config file to use. Default `/usr/local/etc/lilu.toml`. |
| `--debug`         | Enable debug output (e.g. the SQL the extend runs).  |
| `--help`, `-h`    | Print the full `perldoc`-style help and exit.        |

## run

Follow the configured EVE logs and insert alerts into PostgreSQL. This does
not return; it is the long running daemon. On start it prints the DSN/user
it will use (the password is only shown as defined/undefined) and the
instances it parsed out of the config, then hands off to the follow loop.

```shell
# run in the foreground (good for a first test)
lilu run

# daemonize, dropping privileges to the lilith user/group
lilu run --daemonize --user lilith --group lilith
```

| switch          | description                                                   |
|-----------------|--------------------------------------------------------------|
| `--daemonize`   | Fork into the background. Pid file `/var/run/lilu/pid`.       |
| `--user <user>` | User to drop to when daemonizing. Default `0`.                |
| `--group <grp>` | Group to drop to when daemonizing. Default `0`.               |

The user needs read access to the followed EVE files and network reach to
the database. A malformed instance is skipped with a warning rather than
taking the daemon down; errors also go to syslog (facility `daemon`). See
[architecture](architecture.md), and [security](security.md) for
running him unprivileged and the least-privilege database grants.

## extend

Print a [LibreNMS](https://www.librenms.org/) style extend of the Suricata
and Sagan alerts ingested **on this host** recently — the same format and
classification buckets as `lilith extend`.

```shell
# the last five minutes, compact JSON
lilu extend

# the last fifteen minutes, human readable
lilu extend -m 15 --pretty

# gzip+base64 compressed, as snmpd wants it
lilu extend -Z
```

| switch     | description                                                        |
|------------|-------------------------------------------------------------------|
| `-m <min>` | How far back to search, in minutes. Default `5`.                  |
| `-Z`       | Gzip+base64 compress the output, LibreNMS style.                  |
| `--pretty` | Pretty print (and canonically order) the JSON. Ignored with `-Z`. |

Wire it into `snmpd.conf` so LibreNMS can poll it:

```
extend lilu /usr/local/bin/lilu extend
```

Two notes, carried over from [architecture](architecture.md): the extend
counts Suricata and Sagan only (CAPE detonations are ingested but not
counted), and there is no `class_ignore` / `sid_ignore` trimming — every
classification is reported.
