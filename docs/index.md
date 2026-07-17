# Lilu documentation

Lilu is the lesser kinsman of [Lilith](https://github.com/LilithSec/Lilith),
the demoness of the night. Where Lilith keeps the annals, consults them, and
sends word onward, Lilu keeps no court of his own. He only *carries*: he
follows the EVE logs of the watchers and writes what they cry out into
Lilith's book, and reports to LibreNMS what passed through him. Nothing else.

In the world above, Lilu (`App::Lilu`) is a cut down, standalone
reimplementation of just the `run` and `extend` commands of Lilith. He
follows the EVE logs of [Suricata](https://suricata.io/) and
[Sagan](https://github.com/quadrantsec/sagan) (and detonation reports from
[CAPEv2](https://github.com/kevoreilly/CAPEv2) via
[CAPE::Utils](https://metacpan.org/pod/CAPE::Utils)) and writes every alert
into PostgreSQL. He writes the *same* tables with the *same* event IDs as
Lilith and reads the *same* `[eves.*]` config shape — but with **no
dependency on Lilith itself**, so a sensor box carries a much smaller
dependency chain (no DBIx::Class or App::Cmd; Mojolicious is pulled in only
for its user agent, used to push alerts to a remote receiver).

He holds no database of his own. Lilu writes into a Lilith PostgreSQL
database, which creates and manages the schema; a central Lilith then does
the searching, examining, and escalating over everything the sensors carried
in. See [architecture](architecture.md) for how he relates.

- [architecture](architecture.md) :: the ingest daemon, the tables he
  writes, the LibreNMS extend, and where Lilu sits in the pantheon

- [install](install.md) :: dependencies in detail, per-OS install,
  pointing Lilu at a Lilith database, and running at boot

- [configuration](configuration.md) :: the `lilu.toml` reference and a
  complete example

- [usage](usage.md) :: the `lilu` CLI — `run` and `extend`

- [security](security.md) :: the small attack surface, the cleartext
  database password, least-privilege grants, and the sensitivity of the raw
  EVE he carries

- [examples](examples.md) :: copy-paste scenarios — a sensor feeding a
  remote Lilith, the extend in snmpd, and reusing a shared `lilith.toml`

Also...

- `perldoc App::Lilu`
- `perldoc lilu`
