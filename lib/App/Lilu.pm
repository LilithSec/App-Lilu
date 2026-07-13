package App::Lilu;

use 5.006;
use strict;
use warnings;
use POE                    qw( Wheel::FollowTail );
use JSON                   qw( decode_json );
use DBI                    ();
use Digest::SHA            qw( sha256_base64 );
use Sys::Hostname          qw( hostname );
use Sys::Syslog            qw( closelog openlog syslog );
use TOML                   qw( from_toml );
use File::Slurp            qw( read_file );
use Net::Server::Daemonize ();

=head1 NAME

App::Lilu - Read Suricata/Sagan/CAPEv2 alert EVE logs into PostgreSQL for Lilith

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

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

    - dsn :: The DSN to use with DBI. Required.

    - user :: User for the DBI connection.
      Default :: lilith

    - pass :: Password for the DBI connection.
      Default :: undef

    - debug :: Enable debug warnings.
      Default :: undef

=cut

sub new {
	my ( $class, %opts ) = @_;

	if ( !defined( $opts{dsn} ) ) {
		die('"dsn" is not defined');
	}

	if ( !defined( $opts{user} ) ) {
		$opts{user} = 'lilith';
	}

	my $self = {
		'dsn'   => $opts{'dsn'},
		'user'  => $opts{'user'},
		'pass'  => $opts{'pass'},
		'debug' => $opts{'debug'},
		'stats' => {
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

=head2 run

Start processing the EVE logs. This method is not expected to return.

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

        - type :: 'suricata', 'sagan', or 'cape'.

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

	my $dbh;
	eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
	if ($@) {
		warn($@);
		openlog( 'lilu', undef, 'daemon' );
		syslog( 'LOG_ERR', $@ );
		closelog;
	}

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
		} elsif ( $item->{type} ne 'suricata' && $item->{type} ne 'sagan' && $item->{type} ne 'cape' ) {
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

					my $dbh;
					eval { $dbh = DBI->connect_cached( $self->{dsn}, $self->{user}, $self->{pass} ); };
					if ($@) {
						warn($@);
						openlog( 'lilu', undef, 'daemon' );
						syslog( 'LOG_ERR', $@ );
						closelog;
					}

					eval {
						if (   defined($json)
							&& defined( $json->{event_type} )
							&& $json->{event_type} eq 'alert' )
						{
							# put the event ID together
							my $event_id
								= sha256_base64( $_[HEAP]{instance}
									. $_[HEAP]{host}
									. $json->{timestamp}
									. $json->{flow_id}
									. $json->{in_iface} );

							# handle if suricata
							if ( $_[HEAP]{type} eq 'suricata' ) {
								my $sth
									= $dbh->prepare( 'insert into suricata_alerts'
										. ' ( instance, host, timestamp, flow_id, event_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, app_proto, flow_pkts_toserver, flow_bytes_toserver, flow_pkts_toclient, flow_bytes_toclient, flow_start, classification, signature, gid, sid, rev, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $json->{flow_id},
									$event_id,                    $json->{in_iface},
									$json->{src_ip},              $json->{src_port},
									$json->{dest_ip},             $json->{dest_port},
									$json->{proto},               $json->{app_proto},
									$json->{flow}{pkts_toserver}, $json->{flow}{bytes_toserver},
									$json->{flow}{pkts_toclient}, $json->{flow}{bytes_toclient},
									$json->{flow}{start},         $json->{alert}{category},
									$json->{alert}{signature},    $json->{alert}{gid},
									$json->{alert}{signature_id}, $json->{alert}{rev},
									$_[ARG0]
								);
							} ## end if ( $_[HEAP]{type} eq 'suricata' )

							#handle if sagan
							elsif ( $_[HEAP]{type} eq 'sagan' ) {
								my $sth
									= $dbh->prepare( 'insert into sagan_alerts'
										. ' ( instance, instance_host, timestamp, event_id, flow_id, in_iface, src_ip, src_port, dest_ip, dest_port, proto, facility, host, level, priority, program, proto, xff, stream, classification, signature, gid, sid, rev, raw) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);
								$sth->execute(
									$_[HEAP]{instance},           $_[HEAP]{host},
									$json->{timestamp},           $event_id,
									$json->{flow_id},             $json->{in_iface},
									$json->{src_ip},              $json->{src_port},
									$json->{dest_ip},             $json->{dest_port},
									$json->{proto},               $json->{facility},
									$json->{host},                $json->{level},
									$json->{priority},            $json->{program},
									$json->{proto},               $json->{xff},
									$json->{stream},              $json->{alert}{category},
									$json->{alert}{signature},    $json->{alert}{gid},
									$json->{alert}{signature_id}, $json->{alert}{rev},
									$_[ARG0],
								);
							} elsif ( $_[HEAP]{type} eq 'cape' ) {
								my $sth
									= $dbh->prepare( 'insert into cape_alerts'
										. ' ( instance, target, instance_host, task, start, stop, malscore, subbed_from_ip, subbed_from_host, pkg, md5, sha1, sha256, slug, url, url_hostname, proto, src_ip, src_port, dest_ip, dest_port, size, raw ) '
										. ' VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );'
									);

								my $url;
								if ( defined( $json->{http} ) && defined( $json->{http}{url} ) ) {
									$url = $json->{http}{url};
								}

								my $url_hostname;
								if ( defined( $json->{http} ) && defined( $json->{http}{hostname} ) ) {
									$url_hostname = $json->{http}{hostname};
								}

								my $proto;
								if ( defined( $json->{proto} ) ) {
									$proto = $json->{proto};
								}

								my $src_ip;
								if ( defined( $json->{src_ip} ) ) {
									$src_ip = $json->{src_ip};
								}

								my $src_port;
								if ( defined( $json->{src_port} ) ) {
									$src_port = $json->{src_port};
								}

								my $dest_ip;
								if ( defined( $json->{dest_ip} ) ) {
									$dest_ip = $json->{dest_ip};
								}

								my $dest_port;
								if ( defined( $json->{dest_port} ) ) {
									$dest_port = $json->{dest_port};
								}

								my $size;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{size} ) ) {
									$size = $json->{cape_submit}{size};
								} elsif ( defined( $json->{fileinfo} ) && defined( $json->{fileinfo}{size} ) ) {
									$size = $json->{fileinfo}{size};
								}

								# figure out what to use for the target
								my $target;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{name} ) ) {
									$target = $json->{cape_submit}{name};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{name} ) )
								{
									$target = $json->{suricata_extract_submit}{name};
								} else {
									$target = $json->{row}{target};
								}

								my $subbed_from_ip;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{remote_ip} ) )
								{
									$subbed_from_ip = $json->{cape_submit}{remote_ip};
								}

								my $subbed_from_host;
								if (   defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{host} ) )
								{
									$subbed_from_host = $json->{suricata_extract_submit}{host};
								}

								my $md5;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{md5} ) ) {
									$md5 = $json->{cape_submit}{md5};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{md5} ) )
								{
									$md5 = $json->{suricata_extract_submit}{md5};
								}

								my $sha1;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{sha1} ) ) {
									$sha1 = $json->{cape_submit}{sha1};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{sha1} ) )
								{
									$sha1 = $json->{suricata_extract_submit}{sha1};
								}

								my $sha256;
								if ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{sha256} ) ) {
									$sha256 = $json->{cape_submit}{sha256};
								} elsif ( defined( $json->{suricata_extract_submit} )
									&& defined( $json->{suricata_extract_submit}{sha256} ) )
								{
									$sha256 = $json->{suricata_extract_submit}{sha256};
								}

								my $slug;
								if ( defined( $json->{suricata_extract_submit}{slug} ) ) {
									$slug = $json->{suricata_extract_submit}{slug};
								} elsif ( defined( $json->{cape_submit} ) && defined( $json->{cape_submit}{slug} ) )
								{
									$slug = $json->{cape_submit}{slug};
								}

								$target =~ s/^.*\///g;
								$sth->execute(
									$_[HEAP]{instance},       $target,
									$_[HEAP]{host},           $json->{row}{id},
									$json->{row}{started_on}, $json->{row}{completed_on},
									$json->{malscore},        $subbed_from_ip,
									$subbed_from_host,        $json->{row}{package},
									$md5,                     $sha1,
									$sha256,                  $slug,
									$url,                     $url_hostname,
									$proto,                   $src_ip,
									$src_port,                $dest_ip,
									$dest_port,               $size,
									$_[ARG0],
								);
							} ## end elsif ( $_[HEAP]{type} eq 'cape' )
						} ## end if ( defined($json) && defined( $json->{event_type...}))
						if ($@) {
							warn( 'SQL INSERT issue... ' . $@ );
							openlog( 'lilu', undef, 'daemon' );
							syslog( 'LOG_ERR', 'SQL INSERT issue... ' . $@ );
							closelog;
						}
					};

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
