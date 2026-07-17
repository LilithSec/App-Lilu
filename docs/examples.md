# Examples

Worked scenarios to copy from. Paths assume the defaults; adjust to taste.
The database in every case is a Lilith PostgreSQL — Lilu never creates it,
he only writes into it (see [install](install.md)).

## A single Suricata sensor feeding a remote Lilith

The common case: one sensor box, one EVE file, a central Lilith database
elsewhere.

`/usr/local/etc/lilu.toml`...

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"
```

Try it in the foreground first — it prints the DSN and the instances it
parsed, then starts following...

```shell
lilu run
```

Once it looks right, daemonize it dropping to an unprivileged account, and
point a LibreNMS extend at what it ingests here...

```shell
lilu run --daemonize --user lilith --group lilith
lilu extend
```

## Several watchers on one box

Suricata, Sagan, and CAPEv2 detonations, all carried into the same
database. Each is its own sub table under `[eves.*]`; the instance name is
the sub table name unless `instance` overrides it.

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

# two suricata interfaces, distinct instance names
[eves.suricata-eve]
instance="foo-pie"
type="suricata"
eve="/var/log/suricata/alert.json"

[eves.another-eve]
instance="foo2-pie"
type="suricata"
eve="/var/log/suricata/alert2.json"

# sagan; instance name defaults to the sub table name, 'foo-lae'
[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"

# CAPEv2 detonations, via CAPE::Utils
[eves.cape]
type="cape"
eve="/var/log/cape/eve.json"
```

```shell
lilu run --daemonize --user lilith --group lilith
```

## Wiring the extend into snmpd

`lilu extend` prints the same LibreNMS extend shape as `lilith extend`, so
it drops into the same LibreNMS application. In `snmpd.conf`...

```
extend lilu /usr/local/bin/lilu extend
```

LibreNMS wants it gzip+base64 compressed for anything but the smallest
output; the `-Z` switch does that...

```
extend lilu /usr/local/bin/lilu extend -Z
```

Widen the window with `-m` if your poll interval is longer than the default
five minutes — `lilu extend -m 15 -Z` counts the last fifteen. Remember the
extend covers Suricata and Sagan only; CAPE detonations are ingested but
not counted (see [architecture](architecture.md)).

## Reusing a shared lilith.toml

Lilu reads a strict subset of Lilith's config — just `dsn`/`user`/`pass`
and the `[eves.*]` instances — and simply ignores everything else. So on a
box that also has a `lilith.toml`, you can point Lilu straight at it
instead of maintaining a second file...

```shell
lilu --config /usr/local/etc/lilith.toml run --daemonize \
    --user lilith --group lilith
```

The web frontend keys, `class_ignore`, `[virani.*]`, and the rest of
Lilith's settings are read by neither `run` nor `extend`.

## A first test against a throwaway table set

Before wiring a new sensor into a production Lilith, point it at a scratch
database so a misconfigured instance can not muddy the real annals. Deploy
the Lilith schema there once with `dbic-migration` (see Lilith's
`docs/install.md`), then...

```toml
dsn="dbi:Pg:dbname=lilith_scratch;host=127.0.0.1"
user="lilith"
pass="scratch"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"
```

```shell
lilu run                 # foreground; watch the parsed instances and any warnings
lilu extend --pretty     # confirm counts are showing up, human readable
```

When it behaves, swap the `dsn` for the real Lilith and daemonize.
