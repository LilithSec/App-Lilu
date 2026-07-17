# Security considerations

Lilu is a small thing on purpose, and most of what could go wrong is about
the two things he touches: the config that holds a database password, and
the Lilith database he writes the raw EVE into. He carries; he does not
guard — the annals he feeds are Lilith's to protect. Read this before
pointing a sensor at a real database.

## A small attack surface

Lilu opens no listening socket and serves nothing. `lilu run` only reads
the configured EVE files and makes an outbound connection to PostgreSQL;
`lilu extend` only reads from that same database and prints to stdout.
There is no web frontend, no control socket, no CLI search — none of
Lilith's larger surface is present. What remains to get right is file
permissions and database grants, below.

## The config holds a cleartext password

`/usr/local/etc/lilu.toml` carries the `dsn`, `user`, and `pass` for the
database in the clear. Whoever can read it can write into the annals as
that user. Keep it owned by the account Lilu runs as (or root) and not
group- or world-readable...

```shell
chown lilith /usr/local/etc/lilu.toml
chmod 600 /usr/local/etc/lilu.toml
```

`lilu run` never prints the password — on startup it reports it only as
`***defined***` or `***undefined***` — so it is safe to leave a `run`
banner in a log. The file is the only place the secret lives; guard that.

## Least-privilege database grants

Lilu does **not** own the schema and must not be handed rights to change
it. He only ever `INSERT`s alerts and, for the extend, `SELECT`s two
tables. Give the connection user exactly that and nothing more...

```sql
GRANT INSERT ON suricata_alerts, sagan_alerts, cape_alerts TO lilith;
GRANT SELECT ON suricata_alerts, sagan_alerts TO lilith;   -- only if you run lilu extend
```

He never touches the escalation columns and tables a central Lilith
maintains (`escalations`, `auto_escalations`, the per-row `escalations`
array, ...) — so there is no reason for the sensor's user to reach them.
A compromised sensor should be able to add noise to the annals, not
rewrite what a central Lilith has already judged.

## The raw EVE he carries is sensitive

Every alert is stored with its entire EVE record in the `raw` jsonb
column — the flow tuple, hostnames, the matched signature, and whatever
else the watcher emitted. That is real detail about your network and its
traffic, and it is now sitting in the Lilith database. Protecting the
database is Lilith's concern (see Lilith's own `docs/security.md`), but
Lilu is the one filling it, so size the database's protection to the most
sensitive thing any sensor feeds in, not the least.

## Run him unprivileged

The daemon needs only two things: **read** on the EVE files it follows and
network **reach** to the database. It never needs root. When daemonizing,
drop to a dedicated account...

```shell
lilu run --daemonize --user lilith --group lilith
```

Give that account read on the EVE files by group membership rather than by
loosening the files themselves, and make `/var/run/lilu` (where the pid
file lands) writable by it. A malformed instance is skipped with a warning
rather than taking the daemon down, and errors also go to syslog
(facility `daemon`), so a single bad `[eves.*]` entry can not be used to
silence monitoring of the good ones.

## The extend is only counts

`lilu extend` emits per-classification alert counts for this host — no IPs,
no payloads, just tallies in the LibreNMS extend shape. It is low
sensitivity, but it still rides whatever transport you wire it to; if that
is snmpd, secure snmpd as you would for any extend (a v3 user or a tight
community and ACL). The counts reveal roughly how noisy a sensor is, which
is usually fine to expose to your own monitoring and nothing you would
want on a public community string.
