#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;

use_ok('App::Lilu') or BAIL_OUT('App::Lilu failed to load');

# new() requires dsn -- should die without it
dies_ok { App::Lilu->new() } 'new() dies when dsn is not provided';
dies_ok { App::Lilu->new( user => 'lilith' ) } 'new() dies when dsn is missing but other opts given';

# minimal valid construction (no database connection happens in new())
my $lilu;
lives_ok {
	$lilu = App::Lilu->new( dsn => 'dbi:Pg:dbname=test' );
}
'new() lives with only dsn';

isa_ok( $lilu, 'App::Lilu' );

# defaults
is( $lilu->{user},  'lilith', 'default user is "lilith"' );
is( $lilu->{pass},  undef,    'default pass is undef' );
is( $lilu->{debug}, undef,    'default debug is undef' );

# explicit values pass through
my $lilu2 = App::Lilu->new(
	dsn   => 'dbi:Pg:dbname=test',
	user  => 'myuser',
	pass  => 'secret',
	debug => 1,
);
is( $lilu2->{user},  'myuser', 'explicit user is stored' );
is( $lilu2->{pass},  'secret', 'explicit pass is stored' );
is( $lilu2->{debug}, 1,        'explicit debug is stored' );

# the classification maps get built
is( ref( $lilu->{class_map} ),      'HASH', 'class_map is a hashref' );
is( ref( $lilu->{snmp_class_map} ), 'HASH', 'snmp_class_map is a hashref' );
ok( scalar( keys %{ $lilu->{snmp_class_map} } ) > 0, 'snmp_class_map was populated from class_map' );

# the column map is exported and covers the three alert tables
is( ref( \%App::Lilu::alert_columns ), 'HASH', '%App::Lilu::alert_columns exists' );
foreach my $type (qw( suricata sagan cape )) {
	is( ref( $App::Lilu::alert_columns{$type} ), 'ARRAY', "alert_columns{$type} is an arrayref" );
	ok( scalar( @{ $App::Lilu::alert_columns{$type} } ) > 0, "alert_columns{$type} is non-empty" );
}

done_testing();
