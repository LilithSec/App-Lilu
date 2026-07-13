#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use_ok('App::Lilu') or BAIL_OUT('App::Lilu failed to load');

my $lilu = App::Lilu->new( dsn => 'dbi:Pg:dbname=test' );

# undef and unknown classifications get their sentinel short names
is( $lilu->get_short_class_snmp(undef), 'undefC', 'undef classification -> undefC' );
is( $lilu->get_short_class_snmp('some classification that does not exist'),
	'unknownC', 'unknown classification -> unknownC' );

# a straightforward mapping
is( $lilu->get_short_class_snmp('Misc activity'), 'MiscActivity', 'known classification maps to its short name' );

# the lookup is case-insensitive
is( $lilu->get_short_class_snmp('MISC ACTIVITY'), 'MiscActivity', 'classification lookup is case-insensitive' );

# a leading "!" in the short name becomes "not_" for SNMP safety
is( $lilu->get_short_class_snmp('Attempted Information Leak'), 'not_IL', 'leading ! short name becomes not_ for SNMP' );

# a space in the short name becomes an underscore
is( $lilu->get_short_class_snmp('Detection of a non-standard protocol or event'),
	'NS_PoE', 'a space in the short name becomes an underscore' );

# the empty classification has its own bucket
is( $lilu->get_short_class_snmp(''), 'blankC', 'empty classification -> blankC' );

done_testing();
