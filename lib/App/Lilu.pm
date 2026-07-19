package App::Lilu;

use 5.006;
use strict;
use warnings;
use POE                    qw( Wheel::FollowTail );
use JSON                   qw( decode_json encode_json );
use DBI                    ();
use Mojo::UserAgent        ();
use Mojo::IOLoop           ();
use Digest::SHA            qw( sha256_base64 );
use Sys::Hostname          qw( hostname );
use Sys::Syslog            qw( closelog openlog syslog );
use TOML                   qw( from_toml );
use File::Slurp            qw( read_file );
use Net::Server::Daemonize ();

=head1 NAME

App::Lilu - Read Suricata/Sagan/CAPEv2/Baphomet alert EVE logs into PostgreSQL for Lilith

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

# Column order for each alert table, the single source of truth shared by
# parse_eve() (which returns a hash keyed by these names) and run() (which
# builds the INSERT and its bind list from them), so the two cannot drift.
our %alert_columns = (
	suricata => [
		qw(
			instance host timestamp flow_id event_id in_iface
			src_ip src_port dest_ip dest_port proto app_proto
			flow_pkts_toserver flow_bytes_toserver
			flow_pkts_toclient flow_bytes_toclient flow_start
			classification signature gid sid rev raw
		)
	],
	sagan => [
		qw(
			instance instance_host timestamp event_id flow_id in_iface
			src_ip src_port dest_ip dest_port proto facility host
			level priority program xff stream
			classification signature gid sid rev raw
		)
	],
	cape => [
		qw(
			instance target instance_host task start stop malscore
			subbed_from_ip subbed_from_host pkg md5 sha1 sha256 slug
			url url_hostname proto src_ip src_port dest_ip dest_port size raw
		)
	],
	baphomet => [
		qw(
			instance host timestamp event_id event_type kur path score
			signature severity classification src_ip dest_ip subject
			ban_time recidive country raw
		)
	],
);

# The event types Baphomet emits in its EVE (eve_type "baphomet"); a record with
# any other event_type is not ingested. baphomet_event_ignore (per instance)
# narrows this further.
my %BAPHOMET_EVENT_TYPES = map { $_ => 1 } qw( found banish noted alert sighting sighted );

=head1 SYNOPSIS

    use App::Lilu ();

    my $toml = App::Lilu->read_config('/usr/local/etc/lilu.toml');

    my $lilu = App::Lilu->new(
        dsn   => $toml->{dsn},
        user  => $toml->{user},
        pass  => $toml->{pass},
        debug => $debug,
    );

    # follow the EVE logs and insert alerts into PostgreSQL
    my %files = $lilu->eve_instances($toml);
    $lilu->run( files => \%files );

    # or return a LibreNMS style extend
    my $data = $lilu->extend( go_back_minutes => 5 );

=head1 DESCRIPTION

App::Lilu is a smaller, standalone reimplementation of the C<run> and C<extend>
subcommands of L<Lilith>.

=head1 METHODS

=head2 new

Instantiates the object.

    my $lilu = App::Lilu->new(
        dsn   => $toml->{dsn},
        user  => $toml->{user},
        pass  => $toml->{pass},
        debug => 0,
    );

The arguments are as below.

    - dsn :: The DSN to use with DBI. Required unless C<lilith_url> is set, in
      which case alerts are pushed to a remote Lilith receiver instead of being
      inserted locally.

    - user :: User for the DBI connection.
      Default :: lilith

    - pass :: Password for the DBI connection.
      Default :: undef

    - lilith_url :: Base URL of a L<Lilith::Receiver> to POST parsed alerts to,
      e.g. C<http://192.168.1.2:8081>. When set, L</run> sends alerts to the
      receiver rather than inserting them into PostgreSQL. A trailing slash is
      trimmed.
      Default :: undef

    - lilith_apikey :: Bearer API key sent in the C<Authorization> header when
      pushing to C<lilith_url>.
      Default :: undef

    - lilith_verify_ssl :: Whether to verify the receiver's TLS certificate when
      C<lilith_url> is an C<https> URL. Set to a false value to skip verification
      (e.g. a self-signed receiver cert). Ignored for plain C<http>.
      Default :: 1 (verify)

    - lilith_websocket :: When true, C<lilith_url> is treated as a WebSocket
      endpoint. Rather than sending one HTTP request per alert, L</send_alert>
      keeps a WebSocket connection open per receiver table and streams each
      parsed alert to it as a JSON frame. The C<http>/C<https> scheme of
      C<lilith_url> is upgraded to C<ws>/C<wss> and the same C</eve/<table>>
      path is used, so routing and the C<lilith_apikey> bearer auth are
      unchanged.
      Default :: 0 (one HTTP POST per alert)

    - baphomet_event_ignore :: Array ref of Baphomet event types to drop on
      ingest (C<found>, C<banish>, C<noted>, C<alert>, C<sighting>, C<sighted>).
      Applies only to C<type=baphomet> instances.
      Default :: [] (ingest all six)

    - debug :: Enable debug warnings.
      Default :: undef

=cut

sub new {
	my ( $class, %opts ) = @_;

	# A DSN is required for local inserts, but a sensor that only feeds a
	# remote receiver has no database of its own, so lilith_url is an
	# acceptable substitute.
	if ( !defined( $opts{dsn} ) && !defined( $opts{lilith_url} ) ) {
		die('neither "dsn" nor "lilith_url" is defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	# Normalize the receiver URL so send_alert can append '/eve/<table>'
	# without producing a doubled slash.
	if ( defined( $opts{lilith_url} ) ) {
		$opts{lilith_url} =~ s{/+\z}{};
	}

	# TLS cert verification defaults on; only an explicit false value (0,
	# false in TOML, etc) turns it off. Coerced to 1/0 below for the UA.
	if ( !defined( $opts{lilith_verify_ssl} ) ) {
		$opts{lilith_verify_ssl} = 1;
	}

	if ( ref( $opts{baphomet_event_ignore} ) ne 'ARRAY' ) {
		$opts{baphomet_event_ignore} = [];
	}

	my $self = {
		'dsn'                   => $opts{'dsn'},
		'user'                  => $opts{'user'},
		'pass'                  => $opts{'pass'},
		'lilith_url'            => $opts{'lilith_url'},
		'lilith_apikey'         => $opts{'lilith_apikey'},
		'lilith_verify_ssl'     => ( $opts{'lilith_verify_ssl'} ? 1 : 0 ),
		'lilith_websocket'      => ( $opts{'lilith_websocket'}  ? 1 : 0 ),
		'baphomet_event_ignore' => $opts{'baphomet_event_ignore'},
		'debug'                 => $opts{'debug'},
		'stats'             => {
			'read_bytes'          => 0,
			'read_events'         => 0,
			'parse_errors_bytes'  => 0,
			'parse_errors_events' => 0,
		},
		'suricata_instance_stats' => {

		},
		'suricata_stats' => {
			'read_bytes'          => 0,
			'read_events'         => 0,
			'parse_errors_bytes'  => 0,
			'parse_errors_events' => 0,
		},
		'sagan_instance_stats' => {

		},
		'sagan_stats' => {
			'read_bytes'          => 0,
			'read_events'         => 0,
			'parse_errors_bytes'  => 0,
			'parse_errors_events' => 0,
		},
		'capev2_instance_stats' => {

		},
		'capev2_stats' => {
			'read_bytes'          => 0,
			'read_events'         => 0,
			'parse_errors_bytes'  => 0,
			'parse_errors_events' => 0,
		},

		# Long classification name to short SNMP name mapping, used by
		# extend to bucket alerts. Copied from Lilith so the two produce
		# the same extend output.
		class_map => {
			'Not Suspicious Traffic'                                      => '!SusT',
			'Unknown Traffic'                                             => 'UnknownT',
			'Attempted Information Leak'                                  => '!IL',
			'Information Leak'                                            => 'IL',
			'Large Scale Information Leak'                                => 'LrgSclIL',
			'Attempted Denial of Service'                                 => 'ADoS',
			'Denial of Service'                                           => 'DoS',
			'Attempted User Privilege Gain'                               => 'AUPG',
			'Unsuccessful User Privilege Gain'                            => '!SucUsrPG',
			'Successful User Privilege Gain'                              => 'SucUsrPG',
			'Attempted Administrator Privilege Gain'                      => '!SucAdmPG',
			'Successful Administrator Privilege Gain'                     => 'SucAdmPG',
			'Decode of an RPC Query'                                      => 'DRPCQ',
			'Executable code was detected'                                => 'ExeCode',
			'A suspicious string was detected'                            => 'SusString',
			'A suspicious filename was detected'                          => 'SusFilename',
			'An attempted login using a suspicious username was detected' => '!LoginUser',
			'A system call was detected'                                  => 'Syscall',
			'A TCP connection was detected'                               => 'TCPconn',
			'A Network Trojan was detected'                               => 'NetTrojan',
			'A client was using an unusual port'                          => 'OddClntPrt',
			'Detection of a Network Scan'                                 => 'NetScan',
			'Detection of a Denial of Service Attack'                     => 'DOS',
			'Detection of a non-standard protocol or event'               => 'NS PoE',
			'Generic Protocol Command Decode'                             => 'GPCD',
			'access to a potentially vulnerable web application'          => 'PotVulWebApp',
			'Web Application Attack'                                      => 'WebAppAtk',
			'Misc activity'                                               => 'MiscActivity',
			'Misc Attack'                                                 => 'MiscAtk',
			'Generic ICMP event'                                          => 'GenICMP',
			'Inappropriate Content was Detected'                          => '!AppCont',
			'Potential Corporate Privacy Violation'                       => 'PotCorpPriVio',
			'Attempt to login by a default username and password'         => '!DefUserPass',
			'Targeted Malicious Activity was Detected'                    => 'TargetedMalAct',
			'Exploit Kit Activity Detected'                               => 'ExpKit',
			'Device Retrieving External IP Address Detected'              => 'RetrExtIP',
			'Domain Observed Used for C2 Detected'                        => 'C2domain',
			'Possibly Unwanted Program Detected'                          => 'PotUnwantedProg',
			'Successful Credential Theft Detected'                        => 'CredTheft',
			'Possible Social Engineering Attempted'                       => 'PosSocEng',
			'Crypto Currency Mining Activity Detected'                    => 'Mining',
			'Malware Command and Control Activity Detected'               => 'MalC2act',
			'Potentially Bad Traffic'                                     => 'PotBadTraf',
			'Unsuccessful Admin Privilege'                                => 'SucAdmPG',
			'Exploit Attempt'                                             => 'ExpAtmp',
			'Program Error'                                               => 'ProgErr',
			'Suspicious Command Execution'                                => 'SusProgExec',
			'Network event'                                               => 'NetEvent',
			'System event'                                                => 'SysEvent',
			'Configuration Change'                                        => 'ConfChg',
			'Spam'                                                        => 'Spam',
			'Attempted Access To File or Directory'                       => 'FoDAccAtmp',
			'Suspicious Traffic'                                          => 'SusT',
			'Configuration Error'                                         => 'ConfErr',
			'Hardware Event'                                              => 'HWevent',
			''                                                            => 'blankC',
		},
		snmp_class_map => {},
	};
	bless $self;

	# Build the SNMP class map, the only derived map extend needs.
	foreach my $key ( keys( %{ $self->{class_map} } ) ) {
		my $lc_key = lc($key);
		$self->{snmp_class_map}{$lc_key} = $self->{class_map}{$key};
		$self->{snmp_class_map}{$lc_key} =~ s/^\!/not\_/;
		$self->{snmp_class_map}{$lc_key} =~ s/\ /\_/;
	}

	# O(1) lookup of the baphomet event types to skip on ingest
	$self->{baphomet_event_ignore_map} = { map { $_ => 1 } @{ $self->{baphomet_event_ignore} } };

	# One reusable user agent for pushing to the receiver. Only built when a
	# receiver URL is configured, so plain local-insert setups pull in nothing.
	if ( defined( $self->{lilith_url} ) ) {
		my $ua = Mojo::UserAgent->new;
		$ua->transactor->name( 'App-Lilu/' . $VERSION );

		# insecure is the inverse of verify: verification off => allow insecure.
		$ua->insecure( $self->{lilith_verify_ssl} ? 0 : 1 );

		# A streamed WebSocket is meant to stay open between alerts, so drop the
		# idle timeout that would otherwise tear an idle connection down.
		if ( $self->{lilith_websocket} ) {
			$ua->inactivity_timeout(0);
			$self->{ws} = {};
		}

		$self->{ua} = $ua;
	} ## end if ( defined( $self->{lilith_url} ) )

	return $self;
} ## end sub new

=head2 read_config

Reads and parses a TOML config file, returning the config hash ref. Dies if the
file is missing or does not parse.

    my $toml = App::Lilu->read_config('/usr/local/etc/lilu.toml');

=cut

sub read_config {
	my ( $class, $file ) = @_;

	if ( !defined($file) ) {
		die("no config file specified\n");
	}
	if ( !-f $file ) {
		die( '"' . $file . '" does not exist' . "\n" );
	}

	my $raw = read_file($file) or die( 'Failed to read "' . $file . '"' . "\n" );

	my ( $toml, $err ) = from_toml($raw);
	unless ($toml) {
		die "Error parsing toml,'" . $file . "'" . $err;
	}

	return $toml;
} ## end sub read_config

=head2 eve_instances

Builds the instance => config hash for L</run> from the parsed TOML. EVE
instances live under the C<[eves.*]> table; any leftover top-level table is
warned about in case it is an old-style instance definition.

    my %files = $lilu->eve_instances($toml);

=cut

sub eve_instances {
	my ( $self, $toml ) = @_;

	my %files;
	if ( ref( $toml->{eves} ) eq 'HASH' ) {
		foreach my $name ( keys( %{ $toml->{eves} } ) ) {
			next unless ref( $toml->{eves}{$name} ) eq 'HASH';
			$files{$name} = $toml->{eves}{$name};
		}
	}

	# Warn about stray top-level tables, which were instances prior to the move
	# under [eves.*].
	foreach my $key ( keys( %{$toml} ) ) {
		next if $key eq 'eves';
		next unless ref( $toml->{$key} ) eq 'HASH';
		warn(     'Top-level table ['
				. $key
				. '] is no longer used as an EVE instance; '
				. 'did you mean [eves.'
				. $key . ']?'
				. "\n" );
	} ## end foreach my $key ( keys( %{$toml} ) )

	return %files;
} ## end sub eve_instances

=head2 parse_eve

Parse a decoded EVE record into a row hash for its alert table. Returns a hash
ref keyed by column name (the same keys as C<@{ $App::Lilu::alert_columns{$type} }>),
or undef if the record is not an C<alert> event and so should be skipped.

    my $row = $lilu->parse_eve(
        type     => 'suricata',
        json     => $decoded,
        instance => 'foo-pie',
        host     => 'sensor1',
        raw      => $raw_line,
    );

Arguments.

    - type :: 'suricata', 'sagan', 'cape', or 'baphomet'. Required.

    - json :: The decoded EVE record, a hash ref. Required.

    - instance :: Instance name recorded on the row. For baphomet it falls back
      to the record's C<kur> when not given.

    - host :: Host the instance runs on. Stored as C<host> for Suricata and as
      C<instance_host> for Sagan and CAPE. For baphomet the C<host> column is
      the record's own C<hostname>, falling back to this argument.

    - raw :: The raw EVE line, stored verbatim in the C<raw> column.

For Suricata and Sagan an C<event_id> is derived as the SHA256 (base64) of
instance + host + timestamp + flow_id + in_iface, matching L<Lilith> so the two
produce the same handle for a given event. Baphomet has no flow identity, so its
C<event_id> uses a different recipe; see L</_parse_baphomet>.

=cut

sub parse_eve {
	my ( $self, %opts ) = @_;

	my $json = $opts{json};

	# every parser needs a decoded record to work from
	if ( !defined($json) || ref($json) ne 'HASH' ) {
		return undef;
	}

	my $type     = $opts{type};
	my $instance = $opts{instance};
	my $host     = $opts{host};

	# Baphomet has its own event_type vocabulary (found/banish/noted/alert/
	# sighting/sighted) and row shape, so it is dispatched on the configured type
	# before the suricata/sagan/cape 'alert'-only guard below -- which would
	# otherwise drop every Baphomet record.
	if ( defined($type) && $type eq 'baphomet' ) {
		return $self->_parse_baphomet( $json, \%opts );
	}

	# for the suricata/sagan/cape sources only alert events are stored;
	# anything else is skipped
	if ( !defined( $json->{event_type} ) || $json->{event_type} ne 'alert' ) {
		return undef;
	}

	# stable per-event handle; undef parts stringify to '' just as before
	my $event_id
		= sha256_base64( ( defined($instance) ? $instance : '' )
			. ( defined($host)                ? $host              : '' )
			. ( defined( $json->{timestamp} ) ? $json->{timestamp} : '' )
			. ( defined( $json->{flow_id} )   ? $json->{flow_id}   : '' )
			. ( defined( $json->{in_iface} )  ? $json->{in_iface}  : '' ) );

	if ( defined($type) && $type eq 'suricata' ) {
		return {
			instance            => $instance,
			host                => $host,
			timestamp           => $json->{timestamp},
			flow_id             => $json->{flow_id},
			event_id            => $event_id,
			in_iface            => $json->{in_iface},
			src_ip              => $json->{src_ip},
			src_port            => $json->{src_port},
			dest_ip             => $json->{dest_ip},
			dest_port           => $json->{dest_port},
			proto               => $json->{proto},
			app_proto           => $json->{app_proto},
			flow_pkts_toserver  => $json->{flow}{pkts_toserver},
			flow_bytes_toserver => $json->{flow}{bytes_toserver},
			flow_pkts_toclient  => $json->{flow}{pkts_toclient},
			flow_bytes_toclient => $json->{flow}{bytes_toclient},
			flow_start          => $json->{flow}{start},
			classification      => $json->{alert}{category},
			signature           => $json->{alert}{signature},
			gid                 => $json->{alert}{gid},
			sid                 => $json->{alert}{signature_id},
			rev                 => $json->{alert}{rev},
			raw                 => $opts{raw},
		};
	} elsif ( defined($type) && $type eq 'sagan' ) {
		return {
			instance       => $instance,
			instance_host  => $host,
			timestamp      => $json->{timestamp},
			event_id       => $event_id,
			flow_id        => $json->{flow_id},
			in_iface       => $json->{in_iface},
			src_ip         => $json->{src_ip},
			src_port       => $json->{src_port},
			dest_ip        => $json->{dest_ip},
			dest_port      => $json->{dest_port},
			proto          => $json->{proto},
			facility       => $json->{facility},
			host           => $json->{host},
			level          => $json->{level},
			priority       => $json->{priority},
			program        => $json->{program},
			xff            => $json->{xff},
			stream         => $json->{stream},
			classification => $json->{alert}{category},
			signature      => $json->{alert}{signature},
			gid            => $json->{alert}{gid},
			sid            => $json->{alert}{signature_id},
			rev            => $json->{alert}{rev},
			raw            => $opts{raw},
		};
	} elsif ( defined($type) && $type eq 'cape' ) {
		return $self->_parse_cape( $json, $instance, $host, $opts{raw} );
	}

	return undef;
} ## end sub parse_eve

# Pull a CAPEv2 detonation record apart into its cape_alerts row. Kept out of
# parse_eve only because the field-by-field fallbacks (cape_submit vs
# suricata_extract_submit vs row) are long. Faithful to the original run() body.
sub _parse_cape {
	my ( $self, $json, $instance, $host, $raw ) = @_;

	my $ces = ref( $json->{cape_submit} ) eq 'HASH'             ? $json->{cape_submit}             : {};
	my $ses = ref( $json->{suricata_extract_submit} ) eq 'HASH' ? $json->{suricata_extract_submit} : {};

	# the submitted sample's name: most specific source first, then basename
	my $target;
	if ( defined( $ces->{name} ) ) {
		$target = $ces->{name};
	} elsif ( defined( $ses->{name} ) ) {
		$target = $ses->{name};
	} else {
		$target = $json->{row}{target};
	}
	if ( defined($target) ) {
		$target =~ s/^.*\///;
	}

	# hashes: cape_submit first, else suricata_extract_submit
	my $md5    = defined( $ces->{md5} )    ? $ces->{md5}    : $ses->{md5};
	my $sha1   = defined( $ces->{sha1} )   ? $ces->{sha1}   : $ses->{sha1};
	my $sha256 = defined( $ces->{sha256} ) ? $ces->{sha256} : $ses->{sha256};

	# slug preference is the other way round: suricata_extract_submit first
	my $slug = defined( $ses->{slug} ) ? $ses->{slug} : $ces->{slug};

	my $size;
	if ( defined( $ces->{size} ) ) {
		$size = $ces->{size};
	} elsif ( defined( $json->{fileinfo} ) && defined( $json->{fileinfo}{size} ) ) {
		$size = $json->{fileinfo}{size};
	}

	return {
		instance         => $instance,
		target           => $target,
		instance_host    => $host,
		task             => $json->{row}{id},
		start            => $json->{row}{started_on},
		stop             => $json->{row}{completed_on},
		malscore         => $json->{malscore},
		subbed_from_ip   => $ces->{remote_ip},
		subbed_from_host => $ses->{host},
		pkg              => $json->{row}{package},
		md5              => $md5,
		sha1             => $sha1,
		sha256           => $sha256,
		slug             => $slug,
		url              => ( defined( $json->{http} ) ? $json->{http}{url}      : undef ),
		url_hostname     => ( defined( $json->{http} ) ? $json->{http}{hostname} : undef ),
		proto            => $json->{proto},
		src_ip           => $json->{src_ip},
		src_port         => $json->{src_port},
		dest_ip          => $json->{dest_ip},
		dest_port        => $json->{dest_port},
		size             => $size,
		raw              => $raw,
	};
} ## end sub _parse_cape

=head2 _parse_baphomet

Pull a Baphomet judgment record (top-level C<eve_type> "baphomet") apart into a
C<baphomet_alerts> row. Kept out of L</parse_eve> for the same reason as
L</_parse_cape>. Returns undef for an C<event_type> outside the six Baphomet
emits (found/banish/noted/alert/sighting/sighted) or one listed in this
instance's C<baphomet_event_ignore>.

Baphomet's offender IP maps to C<src_ip> so it lines up with the other tables;
its C<subject> (a non-IP offender, e.g. a username) gets its own column. As with
the suricata/sagan/cape sources, only the scalar fields worth
filtering/sorting/grouping by are promoted to columns; the nested detail
(C<attack>, C<rule>, C<found>, C<marks_set>, C<references>, ...) is left in
C<raw>. Matches L<Lilith> so a sensor running Lilu and Lilith itself compute the
same row for a given record.

Baphomet has no flow identity, so C<event_id> is the SHA256 (base64) of hostname
+ kur + timestamp + event_type + rule name + offender (the ip, or the subject
when there is no ip). The rule name is read from the C<raw> record even though
C<rule> itself is not promoted to a column.

=cut

sub _parse_baphomet {
	my ( $self, $json, $opts ) = @_;

	my $event_type = $json->{event_type};
	return undef unless defined($event_type) && $BAPHOMET_EVENT_TYPES{$event_type};
	return undef if $self->{baphomet_event_ignore_map}{$event_type};

	# instance is the configured name, falling back to the record's kur; host is
	# the record's own hostname, falling back to the sensor host the caller passed
	my $instance = defined( $opts->{instance} ) ? $opts->{instance} : $json->{kur};
	my $host     = defined( $json->{hostname} ) ? $json->{hostname} : $opts->{host};

	# offender is the ip when present, else the subject; it keeps the derived
	# event_id stable for a subject-only verdict
	my $rule_name = ref( $json->{rule} ) eq 'HASH' ? $json->{rule}{name} : undef;
	my $offender  = defined( $json->{ip} ) ? $json->{ip} : $json->{subject};

	my $event_id
		= sha256_base64( ( defined($host)                ? $host              : '' )
			. ( defined( $json->{kur} )       ? $json->{kur}       : '' )
			. ( defined( $json->{timestamp} ) ? $json->{timestamp} : '' )
			. ( defined($event_type)          ? $event_type        : '' )
			. ( defined($rule_name)           ? $rule_name         : '' )
			. ( defined($offender)            ? $offender          : '' ) );

	return {
		instance       => $instance,
		host           => $host,
		timestamp      => $json->{timestamp},
		event_id       => $event_id,
		event_type     => $event_type,
		kur            => $json->{kur},
		path           => $json->{path},
		score          => $json->{score},
		signature      => $json->{msg},
		severity       => $json->{severity},
		classification => $json->{classtype},
		src_ip         => $json->{ip},
		dest_ip        => $json->{dest_ip},
		subject        => $json->{subject},
		ban_time       => $json->{ban_time},
		recidive       => _baphomet_bool( $json->{recidive} ),
		country        => $json->{country},
		raw            => $opts->{raw},
	};
} ## end sub _parse_baphomet

# Coerce a Baphomet JSON boolean (a JSON::PP::Boolean, which stringifies to ''
# for false and would not bind as a Postgres boolean) to 1/0, leaving undef as
# SQL NULL. Plain function, not a method.
sub _baphomet_bool {
	my ($value) = @_;
	return undef unless defined $value;
	return $value ? 1 : 0;
}

# type -> receiver table name. The receiver routes on the table, not the type,
# so this is the same suricata/sagan/cape/baphomet -> *_alerts mapping run() uses
# for its local INSERTs, and the same allow-list Lilith::Receiver accepts.
my %receiver_table = (
	suricata => 'suricata_alerts',
	sagan    => 'sagan_alerts',
	cape     => 'cape_alerts',
	baphomet => 'baphomet_alerts',
);

=head2 send_alert

Send a parsed alert row to the configured L<Lilith::Receiver>. Requires
C<lilith_url> (and normally C<lilith_apikey>) to have been passed to L</new>.

By default the row is C<POST>ed as a JSON body in its own HTTP request, and the
method dies on a transport error or any non-2xx response so the caller can log
it. When C<lilith_websocket> was passed to L</new>, the row is instead streamed
as a JSON frame over a persistent WebSocket connection (one per receiver table),
opened lazily on the first alert for that table.

    $lilu->send_alert( type => 'suricata', row => $row );

Arguments.

    - type :: 'suricata', 'sagan', 'cape', or 'baphomet'. Required. Selects the
      receiver table (C<< POST /eve/<type>_alerts >>).

    - row :: The row hash ref from L</parse_eve>. Required. Sent verbatim as the
      JSON body; the receiver validates it against its own column set.

=cut

sub send_alert {
	my ( $self, %opts ) = @_;

	if ( !defined( $self->{lilith_url} ) ) {
		die('send_alert called but "lilith_url" is not set');
	}

	my $table = $receiver_table{ $opts{type} // '' };
	if ( !defined($table) ) {
		die( 'unknown type "' . ( defined( $opts{type} ) ? $opts{type} : '' ) . '" passed to send_alert' );
	}
	if ( ref( $opts{row} ) ne 'HASH' ) {
		die('"row" must be a hash ref');
	}

	# WebSocket mode: stream the row as a JSON frame over a kept-open
	# connection instead of a fresh HTTP request per alert.
	if ( $self->{lilith_websocket} ) {
		my $ws = $self->_ws_connect($table);

		# Drain the frame before returning. Mojo runs the drain callback from
		# inside the IOLoop, so start it and let the callback stop it -- unless
		# the send already drained synchronously (e.g. a test double), in which
		# case there is nothing to wait on.
		my $drained = 0;
		$ws->send( { json => $opts{row} } => sub { $drained = 1; Mojo::IOLoop->stop; } );
		Mojo::IOLoop->start unless $drained;

		return $ws;
	} ## end if ( $self->{lilith_websocket} )

	my $url = $self->{lilith_url} . '/eve/' . $table;

	my %headers = (
		'Content-Type' => 'application/json',
		(
			defined( $self->{lilith_apikey} )
			? ( 'Authorization' => 'Bearer ' . $self->{lilith_apikey} )
			: ()
		),
	);

	my $tx  = $self->{ua}->post( $url => \%headers => encode_json( $opts{row} ) );
	my $res = $tx->res;

	if ( !$res->is_success ) {
		my $err = $tx->error;
		die(      'POST '
				. $url
				. ' failed: '
				. ( $res->code    // ( ref($err) eq 'HASH' ? $err->{code}    // '?' : '?' ) ) . ' '
				. ( $res->message // ( ref($err) eq 'HASH' ? $err->{message} // '' : '' ) ) . ' ... '
				. ( $res->body    // '' )
				. "\n" );
	} ## end if ( !$res->is_success )

	return $tx;
} ## end sub send_alert

# Open (or reuse) a streaming WebSocket to the receiver for a given table. The
# http(s) receiver URL is upgraded to ws(s) and the same /eve/<table> path used,
# so a single sensor can keep one connection per table alive and stream frames
# to it. Dies if the handshake fails so the caller can log and carry on.
sub _ws_connect {
	my ( $self, $table ) = @_;

	# Reuse a live connection; a finished one is discarded and reopened.
	if ( defined( $self->{ws}{$table} ) && !$self->{ws}{$table}->is_finished ) {
		return $self->{ws}{$table};
	}

	# http -> ws, https -> wss.
	( my $ws_url = $self->{lilith_url} ) =~ s{^http}{ws};
	$ws_url .= '/eve/' . $table;

	my %headers = (
		defined( $self->{lilith_apikey} )
		? ( 'Authorization' => 'Bearer ' . $self->{lilith_apikey} )
		: ()
	);

	my $err;
	$self->{ua}->websocket(
		$ws_url => \%headers => sub {
			my ( $ua, $tx ) = @_;
			if ( !$tx->is_websocket ) {
				my $e = $tx->error;
				$err = ref($e) eq 'HASH' ? ( $e->{message} // 'handshake failed' ) : 'handshake failed';
				Mojo::IOLoop->stop;
				return;
			}

			# Forget the connection once it closes so the next alert reopens it.
			$tx->on( finish => sub { delete $self->{ws}{$table}; } );

			$self->{ws}{$table} = $tx;
			Mojo::IOLoop->stop;
		}
	);

	# websocket() is non-blocking, so pump the loop until the handshake callback
	# fires -- unless it already ran synchronously (e.g. a test double).
	Mojo::IOLoop->start unless defined( $self->{ws}{$table} ) || defined($err);

	if ( !defined( $self->{ws}{$table} ) ) {
		die(      'WebSocket connect to '
				. $ws_url
				. ' failed: '
				. ( defined($err) ? $err : 'unknown error' )
				. "\n" );
	} ## end if ( !defined( $self->{ws}{$table...}))

	return $self->{ws}{$table};
} ## end sub _ws_connect

=head2 run

Start processing the EVE logs. This method is not expected to return.

If C<lilith_url> was passed to L</new>, each parsed alert is POSTed to that
remote L<Lilith::Receiver> via L</send_alert> instead of being inserted into a
local PostgreSQL database, and no C<dsn> is required.

    $lilu->run(
        files => {
            foo => {
                type     => 'suricata',
                instance => 'foo-pie',
                eve      => '/var/log/suricata/alerts-pie.json',
            },
        },
        daemonize => { user => 0, group => 0 },
    );

Arguments.

    - files :: Hash of hashes of instances to follow. The keys of each are:

        - type :: 'suricata', 'sagan', 'cape', or 'baphomet'.

        - eve :: Path to the EVE file to read.

        - instance :: Instance name. The key is used if not specified.

    - daemonize :: If a hash ref, daemonize before following the logs, using
                   its C<user> and C<group> keys and a pid file of
                   C</var/run/lilu/pid>.
      Default :: undef

=cut

sub run {
	my ( $self, %opts ) = @_;

	# Daemonize first, before opening any handles, when asked to.
	if ( ref( $opts{daemonize} ) eq 'HASH' ) {
		Net::Server::Daemonize::daemonize(
			$opts{daemonize}{user}  || 0,
			$opts{daemonize}{group} || 0,
			'/var/run/lilu/pid'
		);
	}

	# When pushing to a remote receiver there is no local database to open;
	# otherwise warm the cached handle up front so a bad DSN is noticed at
	# startup rather than on the first alert.
	if ( !defined( $self->{lilith_url} ) ) {
		my $dbh;
		eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
		if ($@) {
			warn($@);
			openlog( 'lilu', undef, 'daemon' );
			syslog( 'LOG_ERR', $@ );
			closelog;
		}
	} ## end if ( !defined( $self->{lilith_url} ) )

	# process each file
	foreach my $item_key ( keys( %{ $opts{files} } ) ) {
		my $item = $opts{files}->{$item_key};
		if ( !defined( $item->{instance} ) ) {
			warn( 'No instance name specified for ' . $item_key . ' so using that as the instance name' );
			$item->{instance} = $item_key;
		}

		# Skip malformed instances with a warning rather than dying, so one bad
		# entry does not take down monitoring of the valid ones.
		if ( !defined( $item->{type} ) ) {
			warn( 'No type specified for ' . $item->{instance} . '; skipping this instance' );
			next;
		} elsif ($item->{type} ne 'suricata'
			&& $item->{type} ne 'sagan'
			&& $item->{type} ne 'cape'
			&& $item->{type} ne 'baphomet' )
		{
			warn(     'Type, '
					. $item->{type}
					. ', for instance '
					. $item->{instance}
					. ' is not a known type; skipping this instance' );
			next;
		}

		if ( !defined( $item->{eve} ) ) {
			warn( 'No file specified for ' . $item->{instance} . '; skipping this instance' );
			next;
		}

		# create each POE session out for each EVE file we are following
		POE::Session->create(
			inline_states => {
				_start => sub {
					$_[HEAP]{tailor} = POE::Wheel::FollowTail->new(
						Filename   => $_[HEAP]{eve},
						InputEvent => "got_log_line",
					);
				},
				got_log_line => sub {
					my $self = $_[HEAP]{self};
					my $json;
					eval { $json = decode_json( $_[ARG0] ) };
					if ($@) {
						return;
					}

					# Only need a database handle for the local-insert path.
					my $dbh;
					if ( !defined( $self->{lilith_url} ) ) {
						eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
						if ($@) {
							warn($@);
							openlog( 'lilu', undef, 'daemon' );
							syslog( 'LOG_ERR', $@ );
							closelog;
						}
					}

					eval {
						my $row = $self->parse_eve(
							type     => $_[HEAP]{type},
							json     => $json,
							instance => $_[HEAP]{instance},
							host     => $_[HEAP]{host},
							raw      => $_[ARG0],
						);
						if ( defined($row) ) {
							if ( defined( $self->{lilith_url} ) ) {
								# Push the parsed row to the remote receiver instead
								# of touching a database.
								$self->send_alert( type => $_[HEAP]{type}, row => $row );
							} else {
								my $table
									= $_[HEAP]{type} eq 'suricata' ? 'suricata_alerts'
									: $_[HEAP]{type} eq 'sagan'    ? 'sagan_alerts'
									: $_[HEAP]{type} eq 'cape'     ? 'cape_alerts'
									:                                'baphomet_alerts';
								my @cols = @{ $alert_columns{ $_[HEAP]{type} } };
								my $sql
									= 'insert into '
									. $table . ' ( '
									. join( ', ', @cols )
									. ' ) VALUES ( '
									. join( ', ', ('?') x scalar(@cols) ) . ' );';
								my $sth = $dbh->prepare($sql);
								$sth->execute( map { $row->{$_} } @cols );
							} ## end else [ if ( defined( $self->{lilith_url} ) ) ]
						} ## end if ( defined($row) )
					};
					if ($@) {
						my $what
							= defined( $self->{lilith_url} ) ? 'receiver push issue... ' : 'SQL INSERT issue... ';
						warn( $what . $@ );
						openlog( 'lilu', undef, 'daemon' );
						syslog( 'LOG_ERR', $what . $@ );
						closelog;
					}

				},
			},
			heap => {
				eve      => $item->{eve},
				type     => $item->{type},
				host     => hostname,
				instance => $item->{instance},
				self     => $self,
			},
		);

	} ## end foreach my $item_key ( keys( %{ $opts{files} } ...))

	POE::Kernel->run;

	return;
} ## end sub run

=head2 extend

Returns a LibreNMS style extend hash ref, summarizing the Suricata and Sagan
alerts ingested on this host in the last few minutes.

    my $data = $lilu->extend( go_back_minutes => 5 );

Arguments.

    - go_back_minutes :: How far back, in minutes, to look.
      Default :: 5

=cut

sub extend {
	my ( $self, %opts ) = @_;

	if ( !defined( $opts{go_back_minutes} ) ) {
		$opts{go_back_minutes} = 5;
	}

	# librenms return hash
	my $to_return = {
		data => {
			totals             => { total => 0, },
			sagan_instances    => {},
			suricata_instances => {},
			sagan_totals       => { total => 0, },
			suricata_totals    => { total => 0, },
		},
		version     => 1,
		error       => '0',
		errorString => '',
	};

	#
	# Do the search in eval incase of failure
	#

	my $sagan_found    = ();
	my $suricata_found = ();
	eval {
		my $dbh;
		eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
		if ($@) {
			die( 'DBI->connect_cached failure.. ' . $@ );
		}

		my $hostname = hostname;

		#
		# suricata SQL bit
		#

		my $sql
			= 'select * from suricata_alerts'
			. " where timestamp >= CURRENT_TIMESTAMP - interval '"
			. $opts{go_back_minutes}
			. " minutes' and host ='"
			. $hostname . "'";

		$sql = $sql . ';';
		if ( $self->{debug} ) {
			warn( 'SQL search "' . $sql . '"' );
		}
		my $sth = $dbh->prepare($sql);
		$sth->execute();

		while ( my $row = $sth->fetchrow_hashref ) {
			push( @{$suricata_found}, $row );
		}

		#
		# Sagan SQL bit
		#

		$sql
			= 'select * from sagan_alerts'
			. " where timestamp >= CURRENT_TIMESTAMP - interval '"
			. $opts{go_back_minutes}
			. " minutes' and instance_host = '"
			. $hostname . "'";

		$sql = $sql . ';';
		if ( $self->{debug} ) {
			warn( 'SQL search "' . $sql . '"' );
		}
		$sth = $dbh->prepare($sql);
		$sth->execute();

		while ( my $row = $sth->fetchrow_hashref ) {
			push( @{$sagan_found}, $row );
		}

	};
	if ($@) {
		$to_return->{error}       = 1;
		$to_return->{errorString} = $@;
	}

	foreach my $row ( @{$suricata_found} ) {
		$to_return->{data}{totals}{total}++;
		$to_return->{data}{suricata_totals}{total}++;
		my $snmp_class = $self->get_short_class_snmp( $row->{classification} );
		if ( !defined( $to_return->{data}{totals}{$snmp_class} ) ) {
			$to_return->{data}{totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{suricata_totals}{$snmp_class} ) ) {
			$to_return->{data}{suricata_totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{suricata_totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{suricata_instances}{ $row->{instance} } ) ) {
			$to_return->{data}{suricata_instances}{ $row->{instance} } = { total => 0 };
		}
		$to_return->{data}{suricata_instances}{ $row->{instance} }{total}++;
		if ( !defined( $to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class} ) ) {
			$to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class} = 1;
		} else {
			$to_return->{data}{suricata_instances}{ $row->{instance} }{$snmp_class}++;
		}
	} ## end foreach my $row ( @{$suricata_found} )

	foreach my $row ( @{$sagan_found} ) {
		$to_return->{data}{totals}{total}++;
		$to_return->{data}{sagan_totals}{total}++;
		my $snmp_class = $self->get_short_class_snmp( $row->{classification} );
		if ( !defined( $to_return->{data}{totals}{$snmp_class} ) ) {
			$to_return->{data}{totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{sagan_totals}{$snmp_class} ) ) {
			$to_return->{data}{sagan_totals}{$snmp_class} = 1;
		} else {
			$to_return->{data}{sagan_totals}{$snmp_class}++;
		}
		if ( !defined( $to_return->{data}{sagan_instances}{ $row->{instance} } ) ) {
			$to_return->{data}{sagan_instances}{ $row->{instance} } = { total => 0 };
		}
		$to_return->{data}{sagan_instances}{ $row->{instance} }{total}++;
		if ( !defined( $to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class} ) ) {
			$to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class} = 1;
		} else {
			$to_return->{data}{sagan_instances}{ $row->{instance} }{$snmp_class}++;
		}
	} ## end foreach my $row ( @{$sagan_found} )

	return $to_return;
} ## end sub extend

=head2 get_short_class_snmp

Get the SNMP short class name for a classification. This is the short class
name with a leading C<!> replaced with C<not_>.

    my $snmp_class_name = $lilu->get_short_class_snmp($class);

=cut

sub get_short_class_snmp {
	my ( $self, $class ) = @_;

	if ( !defined($class) ) {
		return ('undefC');
	}

	if ( defined( $self->{snmp_class_map}->{ lc($class) } ) ) {
		return $self->{snmp_class_map}->{ lc($class) };
	}

	return ('unknownC');
} ## end sub get_short_class_snmp

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-lilu at rt.cpan.org>, or
through the web interface at
L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-Lilu>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::Lilu

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;    # End of App::Lilu
