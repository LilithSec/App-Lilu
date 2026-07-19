# Configuration

The config file is TOML, default `/usr/local/etc/lilu.toml`. Both commands
take another via `lilu --config <file> <command>`.

It is a subset of Lilith's config: just the database connection and the
`[eves.*]` instances. Lilith-only settings (`class_ignore`, the web
frontend keys, `[virani.*]`, ...) are simply not read by Lilu — a shared
`lilith.toml` works unchanged, Lilu ignores the parts that are not his.

## Top level settings

| key    | description                                                                 |
|--------|-----------------------------------------------------------------------------|
| `dsn`  | The [DBI](https://metacpan.org/pod/DBI) DSN, e.g. `dbi:Pg:dbname=lilith;host=192.168.1.2`. PostgreSQL only ([DBD::Pg](https://metacpan.org/pod/DBD::Pg)). Required unless `lilith_url` is set. |
| `user` | User for the connection. Default `lilith`.                                  |
| `pass` | Password for the connection.                                                |
| `lilith_url`    | Base URL of a remote Lilith web receiver, e.g. `http://192.168.1.2:8081`. When set, `run` pushes alerts to the receiver over HTTP instead of inserting into a local database (see below). |
| `lilith_apikey` | Bearer API key sent to `lilith_url`. Must match one of the receiver's configured `[receiver] apikeys`. |
| `lilith_verify_ssl` | Whether to verify the receiver's TLS certificate for an `https` `lilith_url`. Set `false` to skip (e.g. a self-signed cert). Default `true` (verify). |
| `lilith_websocket` | When `true`, treat `lilith_url` as a WebSocket endpoint and stream alerts to it as JSON frames over a kept-open connection instead of one HTTP request per alert (see below). Default `false`. |
| `baphomet_event_ignore` | Array of Baphomet event types to drop on ingest (`found`, `banish`, `noted`, `alert`, `sighting`, `sighted`). Applies only to `type=baphomet` instances. Default `[]` (ingest all six). |

## Pushing to a remote receiver: `lilith_url`

By default `lilu run` inserts alerts straight into PostgreSQL, which means
every sensor needs database credentials. Alternatively a sensor can push its
alerts to a central [Lilith](https://github.com/LilithSec/Lilith) web receiver
(`mojo_lilith_receiver`) over HTTP, so only the receiver host touches the
database.

Set `lilith_url` (and normally `lilith_apikey`) and drop `dsn`/`user`/`pass`:

```toml
lilith_url="http://192.168.1.2:8081"
lilith_apikey="change-me"

[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"
```

Each parsed alert is `POST`ed to `<lilith_url>/eve/<table>` (where `<table>` is
`suricata_alerts`, `sagan_alerts`, or `cape_alerts`) with an
`Authorization: Bearer <lilith_apikey>` header and the row as a JSON body. The
`lilith_apikey` must be listed in the receiver's `[receiver] apikeys`.

Notes:

- When `lilith_url` is set, `run` never opens a local database connection, so
  no `dsn` is required.
- For an `https` receiver the certificate is verified by default. If the
  receiver uses a self-signed certificate, set `lilith_verify_ssl=false` to
  skip verification:

  ```toml
  lilith_url="https://192.168.1.2:8081"
  lilith_apikey="change-me"
  lilith_verify_ssl=false
  ```
- `extend` always queries the local database, so it still needs `dsn` even in
  receiver mode. On a push-only sensor with no local database, don't use
  `extend`.
- A non-2xx response (bad key, unknown table, insert failure) is warned about
  and logged to syslog, just like a failed local `INSERT`.

### Streaming over a WebSocket: `lilith_websocket`

By default each alert is its own HTTP request. On a busy sensor that is a lot of
connection churn. Set `lilith_websocket=true` to instead keep a WebSocket open
and stream alerts to it as JSON frames:

```toml
lilith_url="http://192.168.1.2:8081"
lilith_apikey="change-me"
lilith_websocket=true
```

The `http`/`https` scheme is upgraded to `ws`/`wss` and the same
`/eve/<table>` path and `Authorization: Bearer <lilith_apikey>` header are used,
so routing and auth are unchanged — only the transport differs. One connection
is opened per table (`suricata_alerts`, `sagan_alerts`, `cape_alerts`), lazily
on that table's first alert, and reopened automatically if it drops.

## EVE instances: `[eves.*]`

Each EVE file to follow is a sub table under `eves`. The sub table name is
the instance name unless `instance` overrides it.

| key        | required | description                                             |
|------------|----------|----------------------------------------------------------|
| `eve`      | yes      | The EVE file to follow.                                  |
| `type`     | yes      | `suricata`, `sagan`, `cape`, or `baphomet`.             |
| `instance` | no       | Instance name; defaults to the sub table name.           |

```toml
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# instance name defaults to the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"

# Baphomet's own judgment log
[eves.baphomet-sshd]
type="baphomet"
eve="/var/log/baphomet/eve.json"
```

`cape` is for the EVE-ish logs generated by
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils) from CAPEv2 detonations.

`baphomet` ingests the EVE [Baphomet](https://github.com/LilithSec/Baphomet)
emits about its own verdicts (`eve_type` `baphomet`; event types
`found`/`banish`/`noted`/`alert`/`sighting`/`sighted`) into the
`baphomet_alerts` table. The offender IP is stored as `src_ip` and a non-IP
subject in its own `subject` column; only the scalar fields become columns, the
nested detail stays in `raw`. Set the top-level `baphomet_event_ignore` (an
array of event types) to drop ones you do not want stored.

A malformed instance (missing `eve`, or an unknown `type`) is warned about
and skipped rather than killing the daemon. Note: like Lilith after 4.0.0,
instances must live under `[eves.*]`. A stray top-level table
(`[suricata-eve]`) is ignored, with a warning from `lilu run` suggesting you
meant `[eves.suricata-eve]`.

## A complete example

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

# a suricata instance
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

# a second suricata instance
[eves.another-eve]
instance="foo2-pie"
type="suricata"
eve="/var/log/suricata/alert2.json"

# a sagan instance; instance name is the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"

# CAPEv2 detonations, via CAPE::Utils
[eves.cape]
type="cape"
eve="/var/log/cape/eve.json"

# Baphomet's own judgment log
[eves.baphomet-sshd]
type="baphomet"
eve="/var/log/baphomet/eve.json"
```
