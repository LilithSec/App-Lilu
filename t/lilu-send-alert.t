#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use Test::Exception;
use JSON qw( decode_json );

use_ok('App::Lilu') or BAIL_OUT('App::Lilu failed to load');

#
# new() and the receiver options
#

# lilith_url substitutes for dsn -- new() lives without a dsn
my $lilu;
lives_ok {
	$lilu = App::Lilu->new(
		lilith_url    => 'http://192.168.1.2:8081',
		lilith_apikey => 'change-me',
	);
}
'new() lives with lilith_url and no dsn';
isa_ok( $lilu, 'App::Lilu' );

is( $lilu->{lilith_url},    'http://192.168.1.2:8081', 'lilith_url is stored' );
is( $lilu->{lilith_apikey}, 'change-me',               'lilith_apikey is stored' );
isa_ok( $lilu->{ua}, 'Mojo::UserAgent', 'a UA is built when lilith_url is set' );

# websocket streaming is off unless asked for
is( $lilu->{lilith_websocket}, 0, 'lilith_websocket defaults to 0 (one POST per alert)' );

#
# lilith_verify_ssl
#

# defaults on; the UA is left secure (insecure => 0)
is( $lilu->{lilith_verify_ssl}, 1, 'lilith_verify_ssl defaults to 1 (verify)' );
is( $lilu->{ua}->insecure,      0, 'the UA verifies TLS by default (insecure off)' );

# an explicit false value turns verification off, on both the object and the UA
my $noverify = App::Lilu->new(
	lilith_url        => 'https://192.168.1.2:8081',
	lilith_verify_ssl => 0,
);
is( $noverify->{lilith_verify_ssl}, 0, 'lilith_verify_ssl=0 is stored as 0' );
is( $noverify->{ua}->insecure,      1, 'the UA skips TLS verification (insecure on)' );

# any other false-y value (e.g. empty string, as a stringly TOML false) coerces to 0
my $noverify2 = App::Lilu->new( lilith_url => 'https://x', lilith_verify_ssl => '' );
is( $noverify2->{lilith_verify_ssl}, 0, 'a false-y lilith_verify_ssl coerces to 0' );

# a true-y value keeps verification on
my $verify = App::Lilu->new( lilith_url => 'https://x', lilith_verify_ssl => 1 );
is( $verify->{lilith_verify_ssl}, 1, 'lilith_verify_ssl=1 keeps verification on' );

# still dies when neither dsn nor lilith_url is given
dies_ok { App::Lilu->new() } 'new() dies with neither dsn nor lilith_url';

# no UA is built for a plain local-insert setup
my $local = App::Lilu->new( dsn => 'dbi:Pg:dbname=test' );
ok( !defined( $local->{ua} ), 'no UA is built without lilith_url' );

# a trailing slash on the url is trimmed so send_alert can append /eve/<table>
my $trimmed = App::Lilu->new( lilith_url => 'http://192.168.1.2:8081///' );
is( $trimmed->{lilith_url}, 'http://192.168.1.2:8081', 'trailing slashes are trimmed from lilith_url' );

#
# send_alert()
#

# calling send_alert without lilith_url is a programmer error
dies_ok { $local->send_alert( type => 'suricata', row => {} ) }
'send_alert dies when lilith_url is not set';

# unknown type and bad row are rejected
dies_ok { $lilu->send_alert( type => 'bogus',    row => {} ) } 'send_alert dies on unknown type';
dies_ok { $lilu->send_alert( type => 'suricata', row => 'x' ) } 'send_alert dies when row is not a hash ref';

#
# send_alert() request construction -- swap in a fake UA that captures the call.
# The fake mimics just enough of a Mojo::Transaction: $tx->res is the tx itself,
# exposing is_success/code/message/body, plus $tx->error.
#
{
	package FakeTx;
	sub new         { my ( $c, %a ) = @_; return bless {%a}, $c }
	sub res         { return $_[0] }
	sub is_success  { return $_[0]{success} }
	sub code        { return $_[0]{code} }
	sub message     { return $_[0]{message} }
	sub body        { return $_[0]{body} }
	sub error       { return $_[0]{error} }
}
{
	package FakeUA;
	sub new { return bless { calls => [] }, shift }
	sub post {
		my ( $self, $url, $headers, $body ) = @_;
		push @{ $self->{calls} }, { url => $url, headers => $headers, body => $body };
		return FakeTx->new( success => 1, code => 201, message => 'Created', body => '{"status":"ok","id":42}' );
	}
}

my $fake = FakeUA->new;
$lilu->{ua} = $fake;

my $row = { instance => 'foo-pie', src_ip => '1.2.3.4', raw => '{"event_type":"alert"}' };
my $resp = $lilu->send_alert( type => 'suricata', row => $row );

is( $resp->res->code, 201, 'send_alert returns the transaction on success' );
is( scalar( @{ $fake->{calls} } ), 1, 'the UA was called exactly once' );

my $call = $fake->{calls}[0];
is( $call->{url}, 'http://192.168.1.2:8081/eve/suricata_alerts', 'suricata posts to /eve/suricata_alerts' );
is(
	$call->{headers}{'Authorization'},
	'Bearer change-me',
	'the api key is sent as a bearer token'
);
is( $call->{headers}{'Content-Type'}, 'application/json', 'content type is application/json' );
is_deeply( decode_json( $call->{body} ), $row, 'the row is sent verbatim as the JSON body' );

# the type -> table mapping for the other two types
$lilu->send_alert( type => 'sagan', row => {} );
is( $fake->{calls}[1]{url}, 'http://192.168.1.2:8081/eve/sagan_alerts', 'sagan posts to /eve/sagan_alerts' );
$lilu->send_alert( type => 'cape', row => {} );
is( $fake->{calls}[2]{url}, 'http://192.168.1.2:8081/eve/cape_alerts', 'cape posts to /eve/cape_alerts' );

# a non-2xx response dies so the caller can log it
{
	package FailUA;
	sub new { return bless {}, shift }
	sub post {
		return FakeTx->new( success => 0, code => 401, message => 'Unauthorized', body => 'nope' );
	}
}
$lilu->{ua} = FailUA->new;
dies_ok { $lilu->send_alert( type => 'suricata', row => {} ) } 'send_alert dies on a non-2xx response';

# omitting the api key omits the Authorization header entirely
my $nokey = App::Lilu->new( lilith_url => 'http://127.0.0.1:8081' );
my $nokey_fake = FakeUA->new;
$nokey->{ua} = $nokey_fake;
$nokey->send_alert( type => 'suricata', row => {} );
ok(
	!exists $nokey_fake->{calls}[0]{headers}{'Authorization'},
	'no Authorization header is sent when lilith_apikey is undef'
);

#
# lilith_websocket streaming
#

# a websocket-mode object streams over a kept-open connection instead of posting.
# FakeWS stands in for a live Mojo WebSocket transaction: it records each frame
# and drains synchronously so send_alert never has to start a real IOLoop.
{
	package FakeWS;
	sub new         { return bless { sent => [] }, shift }
	sub is_finished { return 0 }
	sub send {
		my ( $self, $msg, $cb ) = @_;
		push @{ $self->{sent} }, $msg;
		$cb->() if $cb;
		return $self;
	}
}

my $wslilu = App::Lilu->new(
	lilith_url       => 'http://192.168.1.2:8081',
	lilith_apikey    => 'change-me',
	lilith_websocket => 1,
);
is( $wslilu->{lilith_websocket}, 1, 'lilith_websocket=1 is stored' );

# a live connection for this table is reused, so no handshake is attempted here
my $fakews = FakeWS->new;
$wslilu->{ws}{suricata_alerts} = $fakews;

my $wrow = { instance => 'foo-pie', src_ip => '1.2.3.4' };
$wslilu->send_alert( type => 'suricata', row => $wrow );

is( scalar( @{ $fakews->{sent} } ), 1, 'exactly one frame is streamed over the websocket' );
is_deeply( $fakews->{sent}[0], { json => $wrow }, 'the row is streamed as a json frame' );

# the handshake upgrades http(s) -> ws(s), keeps /eve/<table>, and carries auth.
# FakeWSUA captures the websocket() call and drives the handshake callback with a
# fake transaction so _ws_connect returns without a real network round trip.
{
	package FakeHandshakeTx;
	sub new          { return bless {}, shift }
	sub is_websocket { return 1 }
	sub is_finished  { return 0 }
	sub on           { return }
	sub send         { my ( $s, $msg, $cb ) = @_; $cb->() if $cb; return $s }
}
{
	package FakeWSUA;
	sub new { return bless { calls => [] }, shift }
	sub websocket {
		my ( $self, $url, $headers, $cb ) = @_;
		push @{ $self->{calls} }, { url => $url, headers => $headers };
		$cb->( $self, FakeHandshakeTx->new );
		return;
	}
}

my $wshandshake = App::Lilu->new(
	lilith_url       => 'https://10.0.0.1:8081',
	lilith_apikey    => 'secret',
	lilith_websocket => 1,
);
my $fakewsua = FakeWSUA->new;
$wshandshake->{ua} = $fakewsua;
$wshandshake->send_alert( type => 'sagan', row => {} );

is(
	$fakewsua->{calls}[0]{url},
	'wss://10.0.0.1:8081/eve/sagan_alerts',
	'the websocket upgrades to wss and keeps the /eve/<table> path'
);
is(
	$fakewsua->{calls}[0]{headers}{'Authorization'},
	'Bearer secret',
	'the api key is sent as a bearer token on the websocket handshake'
);

done_testing();
