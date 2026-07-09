#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'App::Lilu' ) || print "Bail out!\n";
}

diag( "Testing App::Lilu $App::Lilu::VERSION, Perl $], $^X" );
