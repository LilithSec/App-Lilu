#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use File::Temp qw( tempfile );

use_ok('App::Lilu') or BAIL_OUT('App::Lilu failed to load');

# ---------------------------------------------------------------------------
# A well formed lilu.toml parses into the expected structure.
# ---------------------------------------------------------------------------
{
	my ( $fh, $filename ) = tempfile( UNLINK => 1 );
	print {$fh} <<'TOML';
dsn="dbi:Pg:dbname=lilith;host=192.168.1.2"
user="lilith"
pass="secret"

[eves.pie]
type="suricata"
eve="/var/log/suricata/alert.json"

[eves.foo-lae]
type="sagan"
eve="/var/log/sagan/alert.json"
TOML
	close($fh);

	my $toml = App::Lilu->read_config($filename);
	is( ref($toml),                     'HASH',                                  'read_config returns a hashref' );
	is( $toml->{dsn},                   'dbi:Pg:dbname=lilith;host=192.168.1.2', 'dsn parsed' );
	is( $toml->{user},                  'lilith',                                'user parsed' );
	is( $toml->{pass},                  'secret',                                'pass parsed' );
	is( $toml->{eves}{pie}{type},       'suricata',                              'eves.pie type parsed' );
	is( $toml->{eves}{pie}{eve},        '/var/log/suricata/alert.json',          'eves.pie eve parsed' );
	is( $toml->{eves}{'foo-lae'}{type}, 'sagan',                                 'eves.foo-lae type parsed' );

	# and it feeds eve_instances cleanly
	my $lilu  = App::Lilu->new( dsn => $toml->{dsn} );
	my %files = $lilu->eve_instances($toml);
	is_deeply( [ sort keys %files ], [ 'foo-lae', 'pie' ], 'parsed config yields both instances' );
}

# ---------------------------------------------------------------------------
# Failure modes: no argument, a missing file, and unparseable TOML.
# ---------------------------------------------------------------------------
dies_ok { App::Lilu->read_config() } 'read_config dies with no file argument';
dies_ok { App::Lilu->read_config('/nonexistent/path/should/not/exist.toml') } 'read_config dies on a missing file';

{
	my ( $fh, $filename ) = tempfile( UNLINK => 1 );
	print {$fh} "this is not = valid = toml [\n";
	close($fh);
	dies_ok { App::Lilu->read_config($filename) } 'read_config dies on unparseable TOML';
}

done_testing();
