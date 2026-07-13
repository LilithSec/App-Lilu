# Install

## Dependencies

Declared in `Makefile.PL`; the load bearing ones are below. Note how much
smaller the chain is than Lilith's — no Mojolicious, DBIx::Class, or
App::Cmd.

| module                    | why                                              |
|---------------------------|--------------------------------------------------|
| `POE`                     | the ingest daemon's FollowTail sessions          |
| `DBI`, `DBD::Pg`          | talking to PostgreSQL                            |
| `JSON`                    | decoding the EVE records and printing the extend |
| `TOML`                    | the config file                                 |
| `File::Slurp`             | reading the config file                         |
| `Digest::SHA`             | the per-alert event IDs                         |
| `Net::Server::Daemonize`  | `run --daemonize`                               |

Also used from the Perl core: `Sys::Syslog`, `Sys::Hostname`,
`MIME::Base64` and `IO::Compress::Gzip` (the extend's `-Z`), `Getopt::Long`,
and `Pod::Usage`.

## From source

Dependencies are declared in Makefile.PL, so with
[cpanminus](https://metacpan.org/pod/App::cpanminus)...

```shell
cpanm --installdeps .
perl Makefile.PL
make
make test
make install
```

## From CPAN

```shell
cpanm App::Lilu
```

## FreeBSD

```shell
pkg install p5-App-cpanminus p5-DBI p5-DBD-Pg p5-Digest-SHA \
    p5-File-Slurp p5-JSON p5-MIME-Base64 p5-Net-Server p5-POE \
    p5-Sys-Syslog p5-TOML
cpanm App::Lilu
```

## Debian

```shell
apt-get install cpanminus zlib1g-dev libdbi-perl libdbd-pg-perl \
    libdigest-sha-perl libfile-slurp-perl libjson-perl \
    libnet-server-perl libpoe-perl libtoml-perl
cpanm App::Lilu
```

## The database

Lilu really does need PostgreSQL — the raw EVE records live in jsonb
columns — but he does **not** create or migrate the schema. He writes into a
database created and managed by
[Lilith](https://github.com/LilithSec/Lilith). On a sensor box that is
normally a *remote* central Lilith database; the schema is deployed once,
there, with `dbic-migration` (see Lilith's `docs/install.md`). Lilu's job is
only to point at it.

Write the connection details into `/usr/local/etc/lilu.toml` (see
[configuration.md](configuration.md)):

```toml
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="WhateverYouSetAsApassword"
```

The `user` needs `INSERT` on `suricata_alerts`, `sagan_alerts`, and
`cape_alerts`, and `SELECT` on the first two if you also run `lilu extend`.

## Running at boot

### The ingest daemon

Run the daemon as a user with read access to the followed EVE files:

```shell
lilu run --daemonize --user lilith --group lilith
```

It writes its pid to `/var/run/lilu/pid`; make sure `/var/run/lilu` exists
and is writable by that user (or created at boot, e.g. via a `tmpfiles.d`
entry on systemd or the rc script on FreeBSD).

### The LibreNMS extend

If using snmpd, wire the extend into `snmpd.conf` so LibreNMS can poll the
alert counts ingested on this sensor:

```
extend lilu /usr/local/bin/lilu extend
```

`lilu extend` produces the same LibreNMS extend format as `lilith extend`,
so it drops into the same LibreNMS application. See [usage.md](usage.md).
