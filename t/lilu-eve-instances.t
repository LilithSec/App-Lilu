#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('App::Lilu') or BAIL_OUT('App::Lilu failed to load');

my $lilu = App::Lilu->new( dsn => 'dbi:Pg:dbname=test' );

# ---------------------------------------------------------------------------
# Instances are read from [eves.*] and keyed by the sub-table name.
# ---------------------------------------------------------------------------
{
	my @warnings;
	local $SIG{__WARN__} = sub { push @warnings, $_[0] };

	my $toml = {
		dsn  => 'dbi:Pg:dbname=test',
		user => 'lilith',               # scalar, not an instance
		eves => {
			'suricata-eve' => { instance => 'foo-pie', type => 'suricata', eve => '/var/log/a.json' },
			'sagan-eve'    => { type     => 'sagan',   eve  => '/var/log/b.json' },
		},
	};

	my %files = $lilu->eve_instances($toml);

	is_deeply( [ sort keys %files ], [ 'sagan-eve', 'suricata-eve' ], 'instances come from the [eves.*] table' );
	is( $files{'suricata-eve'}{eve},      '/var/log/a.json', 'instance eve carried through' );
	is( $files{'suricata-eve'}{type},     'suricata',        'instance type carried through' );
	is( $files{'suricata-eve'}{instance}, 'foo-pie',         'explicit instance name carried through' );
	is( scalar(@warnings),                0,                 'no warnings for a clean [eves.*] config' );
}

# ---------------------------------------------------------------------------
# No eves table => no instances (and no false positives from other config).
# ---------------------------------------------------------------------------
{
	my @warnings;
	local $SIG{__WARN__} = sub { push @warnings, $_[0] };

	my %files = $lilu->eve_instances( { dsn => 'x', user => 'lilith' } );
	is_deeply( \%files, {}, 'no [eves.*] table yields no instances' );
	is( scalar(@warnings), 0, 'scalars do not trigger warnings' );
}

# ---------------------------------------------------------------------------
# A stray top-level table (old-style instance) is ignored but warned about.
# ---------------------------------------------------------------------------
{
	my @warnings;
	local $SIG{__WARN__} = sub { push @warnings, $_[0] };

	my $toml = {
		dsn            => 'x',
		'suricata-eve' => { type      => 'suricata', eve => '/var/log/old.json' },               # old top-level style
		eves           => { 'new-eve' => { type => 'suricata', eve => '/var/log/new.json' } },
	};

	my %files = $lilu->eve_instances($toml);

	is_deeply( [ keys %files ], ['new-eve'], 'stray top-level table is not treated as an instance' );
	ok(
		( grep { /\[suricata-eve\].*\[eves\.suricata-eve\]/ } @warnings ),
		'stray top-level table warns with a "did you mean [eves.X]" hint'
	);
}

done_testing();
