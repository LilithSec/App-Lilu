# Lilu

Lilu is the lesser kinsman of [Lilith](https://github.com/LilithSec/Lilith) —
a night spirit who keeps no court of his own. He does not search, does not
judge, does not send word onward. He only *carries*: whatever the watchers
cry out in the dark, he writes into Lilith's annals and moves on.

In the world above, Lilu (`App::Lilu`) is a cut down, standalone
reimplementation of the `run` and `extend` commands of Lilith, for sensor
boxes that only need to feed the annals. He follows the EVE logs of
[Suricata](https://suricata.io/) and
[Sagan](https://github.com/quadrantsec/sagan) (plus detonation reports from
[CAPEv2](https://github.com/kevoreilly/CAPEv2) via
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils)) and writes every alert
into PostgreSQL — the interesting fields as columns, the full EVE record as
jsonb beside them. Same tables, same event IDs, same `[eves.*]` config
shape as Lilith, and the same LibreNMS extend — but **no dependency on
Lilith itself**, so the sensors carry a much smaller dependency chain (no
Mojolicious, DBIx::Class, or App::Cmd).

Lilu holds no database of his own. He writes into a Lilith PostgreSQL
database, which owns and manages the schema; a central Lilith then
searches, examines, and escalates over everything the sensors carried in.
See [docs/architecture.md](docs/architecture.md).

Feeding the annals and reporting to LibreNMS looks like this...

```shell
# follow the configured EVE files into PostgreSQL
lilu run --daemonize --user lilith --group lilith

# a LibreNMS style extend of what was ingested here recently
lilu extend
```

...with the instances to follow named in `/usr/local/etc/lilu.toml`:

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"

[eves.lae]
type="sagan"
eve="/var/log/sagan/alert.json"
```

## Install

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

Or straight from CPAN:

```shell
cpanm App::Lilu
```

PostgreSQL is required — the raw EVE records are jsonb — but Lilu does not
create or migrate the schema himself. He writes into a database created and
managed by [Lilith](https://github.com/LilithSec/Lilith); see
[docs/install.md](docs/install.md) for the per-OS dependency lists, pointing
Lilu at that database, and running at boot.

## Documentation

To continue your journey go to [docs/index.md](docs/index.md).

Also...

- `perldoc App::Lilu`
- `perldoc lilu`

## The pantheon

Lilu is a member of the LilithSec household, which is named for
[Lilith](https://github.com/LilithSec/Lilith), the demoness of the night.

- **[Baphomet](https://github.com/LilithSec/Baphomet)** accuses.
- **[Ereshkigal](https://github.com/LilithSec/Ereshkigal)** punishes.
- **[Lamashtu](https://github.com/LilithSec/Lamashtu)** remembers.
- **[Virani](https://github.com/LilithSec/Virani)** reads.
- **Lilu** carries.
- **[Lilith](https://github.com/LilithSec/Lilith)** knows.
