# Install

## Dependencies

Declared in `Makefile.PL`. Note how much smaller the chain is than
Lilith's — no DBIx::Class or App::Cmd — which is the whole point of Lilu on a
sensor box. Mojolicious is the one heavier dependency, pulled in only for its
`Mojo::UserAgent` (pushing alerts to a remote receiver over HTTP or WebSocket).

| CPAN module                          | FreeBSD pkg      | Debian pkg          |
|--------------------------------------|------------------|---------------------|
| DBI                                  | p5-DBI           | libdbi-perl         |
| DBD::Pg                              | p5-DBD-Pg        | libdbd-pg-perl      |
| Mojolicious                          | p5-Mojolicious   | libmojolicious-perl |
| POE                                  | p5-POE           | libpoe-perl         |
| JSON                                 | p5-JSON       | libjson-perl        |
| TOML                                 | p5-TOML       | libtoml-perl        |
| File::Slurp                          | p5-File-Slurp | libfile-slurp-perl  |
| Digest::SHA                          | p5-Digest-SHA | libdigest-sha-perl  |
| Net::Server (Net::Server::Daemonize) | p5-Net-Server | libnet-server-perl  |

Package names are current as of writing. Anything missing from your
release installs cleanly from CPAN via
[cpanminus](https://metacpan.org/pod/App::cpanminus). The rest of what Lilu
needs comes from the Perl core: `Sys::Syslog`, `Sys::Hostname`,
`MIME::Base64` and `IO::Compress::Gzip` (the extend's `-Z`), `Getopt::Long`,
and `Pod::Usage`.

## From source

Dependencies are declared in Makefile.PL, so from a checkout or an
unpacked release tarball...

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
[configuration](configuration.md)):

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
so it drops into the same LibreNMS application. See [usage](usage.md).
