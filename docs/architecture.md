# Architecture

## The shape of it

```
  Suricata            Sagan              CAPEv2 (via CAPE::Utils)
  eve.json            eve.json           eve-ish json
     |                   |                  |
     v                   v                  v
  +---------------------------------------------+
  |  lilu run --- the ingest daemon             |
  |  one POE::Wheel::FollowTail per [eves.*]    |
  +---------------------|-----------------------+
                        v
                  PostgreSQL  (a Lilith database; Lilith owns the schema)
     suricata_alerts / sagan_alerts / cape_alerts
                        |
              +---------+---------+
              v                   v
        lilu extend         central Lilith (elsewhere)
      LibreNMS counts       search, event, escalate, web
```

Lilu is two things and no more: a long running ingest daemon (`lilu run`)
and a run-to-completion report (`lilu extend`). There is nothing else — no
CLI search, no web frontend, no escalation, no schema of his own. The
database is the meeting point, and it belongs to Lilith.

## The ingest daemon

`lilu run` reads the config, and for every instance under `[eves.*]`
creates a [POE](https://metacpan.org/pod/POE) session with a
`POE::Wheel::FollowTail` following that EVE file. Each line is decoded as
JSON; anything that is not an `alert` event is ignored. A malformed
instance (missing `eve` or an unknown `type`) is warned about and skipped,
so one bad entry does not stop monitoring of the valid ones. Errors also go
to syslog (facility `daemon`).

For every alert an `event_id` is computed as the SHA256 (base64) of
instance + host + timestamp + flow id + interface — the *same* recipe
Lilith uses — giving a stable handle for the event independent of its row
ID. The interesting fields are pulled into real columns and the entire EVE
record is stored alongside them in the `raw` jsonb column, so nothing is
lost to the flattening.

With `--daemonize` it forks into the background via
[Net::Server::Daemonize](https://metacpan.org/pod/Net::Server::Daemonize),
optionally dropping to `--user` / `--group`; the pid file is
`/var/run/lilu/pid`. It needs read access to the EVE files and reach to the
database, and nothing else.

This is deliberately a straight lift of Lilith's own ingest daemon. Same
tables, same event IDs, same `[eves.*]` config shape — so a box running
Lilu and a box running `lilith run` are interchangeable as far as the
annals are concerned.

## The tables

PostgreSQL is required — the `raw` column is jsonb. Lilu does **not** create
or migrate these tables; they are created and versioned by
[Lilith](https://github.com/LilithSec/Lilith) (via
[DBIx::Class::Migration](https://metacpan.org/pod/DBIx::Class::Migration)).
Lilu simply inserts into them.

| table             | what                                                                 |
|-------------------|----------------------------------------------------------------------|
| `suricata_alerts` | Suricata alerts — flow tuple, classification, sig, gid/sid/rev, flow counters, `raw` |
| `sagan_alerts`    | Sagan alerts — as above plus facility, level, priority, program, xff, and both the sending `host` and the `instance_host` the instance runs on |
| `cape_alerts`     | CAPEv2 detonations — target, task, malscore, hashes, package, slug, submission source, start/stop |

The escalation-related columns and tables Lilith maintains
(`escalations`, `auto_escalations`, the per-row `escalations` array, etc.)
are none of Lilu's concern — he never touches them. A central Lilith reads
and writes those over the alerts Lilu carried in.

## The LibreNMS extend

`lilu extend` connects to the database, counts the Suricata and Sagan
alerts ingested **on this host** in the last few minutes (`-m`, default 5),
buckets them by a short SNMP-safe classification name, and prints a
[LibreNMS](https://www.librenms.org/) style JSON structure — optionally
gzip+base64 compressed (`-Z`). It is the same extend format as
`lilith extend` and uses the same classification map, so an existing
LibreNMS application ingests either without change.

Two differences from Lilith's extend worth knowing:

- It covers Suricata and Sagan only — CAPE detonations are ingested by
  `lilu run` but are not counted in the extend.
- There is no `class_ignore` / `sid_ignore` trimming; Lilu reports every
  classification. (That trimming is a central Lilith concern.)

See [usage.md](usage.md).

## Where Lilu sits in the pantheon

- **[Baphomet](https://github.com/LilithSec/Baphomet)** reads logs and
  *accuses*: consigns repeat offenders to Ereshkigal.
- **[Ereshkigal](https://github.com/LilithSec/Ereshkigal)** works the
  firewall and *punishes*: holds the banned below.
- **[Lamashtu](https://github.com/LilithSec/Lamashtu)** *remembers*: hoards
  the raw packets in rotating pcaps.
- **[Virani](https://github.com/LilithSec/Virani)** *reads*: carves the
  matching packets back out of the hoard.
- **Lilu** *carries*: a cut down Lilith — only the ingest daemon and the
  extend — for sensor boxes that just feed the annals.
- **[Lilith](https://github.com/LilithSec/Lilith)** *knows*: the alerts of
  the watchers — Suricata, Sagan, CAPEv2 — are written into her annals to be
  searched, examined, and sent onward.

Lilu depends on none of the household — not even on Lilith's code. His only
tie is the database he writes into, which is Lilith's. Suricata, Sagan, and
CAPEv2 are not part of the household; they are the watchers in the night
whose cries he carries.
