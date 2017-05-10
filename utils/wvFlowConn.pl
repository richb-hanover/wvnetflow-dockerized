#!/usr/bin/perl

# wvFlowConn.pl  - stitch together connections

#  v1.0   2013-02-27   initial version
#  v1.01  2013-08-15   fixed hash overlap bug

use strict;
use Cflow qw(:flowvars :tcpflags find);		# for reading Cflowd data files
use POSIX;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

$| = 1;

# session structure fields
our $SK_FLOWS = 0;
our $SK_BYTES = 1;
our $SK_PKTS = 2;
our $SK_TCP_FLAGS = 3;
our $SK_CONFIDENCE = 4;
our $SK_PROTOCOL = 5;
our $SK_ADDR1 = 6;
our $SK_PORT1 = 7;
our $SK_ADDR2 = 8;
our $SK_PORT2 = 9;
our $SK_START = 10;
our $SK_END = 11;
our $SK_DURATION = 12;
our $SK_EXPS = 13;
our $SK_LABEL = 14;

# exporter structure fields
our $EXPK_TX = 0;
our $EXPK_RX = 1;

# interface structure fields
our $IFK_FLOWS = 0;
our $IFK_BYTES = 1;
our $IFK_PKTS = 2;
our $IFK_IF_INGRESS = 3;
our $IFK_IF_INGRESS_MULTIPLE = 4;
our $IFK_IF_EGRESS = 5;
our $IFK_IF_EGRESS_MULTIPLE = 6;
our $IFK_DSCP_LAST = 7;
our $IFK_DSCP_MULTIPLE = 8;
our $IFK_FIRST_TIME = 9;
our $IFK_LAST_TIME = 10;
our $IFK_FIRST_TCP_FLAGS = 11;
our $IFK_LAST_TCP_FLAGS = 12;

# sort fields
our $D_FLOWS = 0;
our $D_PKTS = 1;
our $D_BYTES = 2;
our $D_STARTIME = 3;
our $D_ENDTIME = 4;
our $D_INTERFACE = 5;

our $UDP_SESSION_TIMEOUT_BUFFER = 15;			# seconds
our $TCP_SESSION_TIMEOUT_BUFFER = 90;			# seconds
our $CLOCK_SNAFU_CUTOFF = 86400;			# seconds
our $EXPORTER_CLOCK_FUDGE = 0.005;			# don't trust chronology from exporter if flow start time delta < 5 ms

# GLOBALS for speed

our ($wantedClock, $wantedMark, $wantedCount);

our $sessions = {};
our (@tcpHighPorts, @udpHighPorts);
our ($sessionp, $exporterp, $interfacep);
our ($sessionKey1, $sessionKey2);
our ($stime, $etime, $dscp, $dir, $flags);

our (%STIME, %ETIME);

our $sessionCount = 0;
our $sessionMax = 100_000;
our $sessionPurge = 20_000;

our $indexTemplate = "CLLSS";		# char long long short short

our $DEBUG = 0;

select STDERR;
$| = 1;
select STDOUT;

# process arguments

our @files;
our $sortBy = $SK_START;
our $simple = 1;
our $pipe = 0;
our $topResults = 100;
our $detail = "simple";

foreach (@ARGV) {
	if (-f $_) {
		push(@files, $_);
	}
	elsif ( /^-$/ ) {
		$pipe = 1;
	}
	elsif (/^--sort=(flows|packets|octets|bytes|time|duration)$/) {
		if (($1 eq 'octets') || ($1 eq 'bytes')) { $sortBy = $SK_BYTES; }
		elsif ($1 eq 'flows') { $sortBy = $SK_FLOWS; }
		elsif ($1 eq 'packets') { $sortBy = $SK_PKTS; }
		elsif ($1 eq 'time') { $sortBy = $SK_START; }
		elsif ($1 eq 'duration') { $sortBy = $SK_DURATION; }
	}
	elsif (/^--top=(\d+)$/) {
		$topResults = $1;
	}
	elsif (/^--type=(simple|multihop)$/) {
		$detail = $1;
	}
	elsif (/^--debug/i) { $DEBUG = 1; }
}

our $exporters = {};

if ($detail eq 'simple') {
	print "# recn: exaddr,ip-protocol,ip-client-addr,ip-client-port,ip-server-addr,ip-server-port,analysis,start,duration,dscp,c2s-pkts,c2s-octets,s2c-pkts,s2c-octets\n";
}
else {
	print "# recn: exaddr,input,output,ip-protocol,ip-client-addr,ip-client-port,ip-server-addr,ip-server-port,analysis,tcp_flags,start_ms,end_ms,duration,c2s-flows,c2s-pkts,c2s-octets,c2s-tos,s2c-flows,s2c-pkts,s2c-octets,s2c-tos\n";
}


if ($pipe) {
	Cflow::find(\&wanted, \&perfile, "-");
}
else {
	Cflow::find(\&wanted, \&perfile, @files);
}

print "sessions = $sessionCount; sort by $sortBy\n" if ($DEBUG);

my @sess;

if ($sortBy == $SK_START) {		# close all sessions first and use forward sort
	map { &closeSession($_) } values %$sessions;
	@sess = (sort { $a->[$sortBy] <=> $b->[$sortBy] } values %$sessions);
	splice(@sess, $topResults);
}
elsif ($sortBy == $SK_DURATION) {	# close all sessions first and use reverse sort
	map { &closeSession($_) } values %$sessions;
	@sess = (sort { $b->[$sortBy] <=> $a->[$sortBy] } values %$sessions);
	splice(@sess, $topResults);
}
else {					# sort/splice first and then close only the necessary sessions.
	@sess = (sort { $b->[$sortBy] <=> $a->[$sortBy] } values %$sessions);
	splice(@sess, $topResults);
	map { &closeSession($_) } @sess;
}

foreach (@sess) {
	if ($detail eq 'simple')	{ &dumpSessionSimple($_); }
	else				{ &dumpSessionDetail($_); }
}

exit;

sub debugSession
{
	my $sessionp = shift @_;

	my $sk = {
		'SK_FLOWS' => $SK_FLOWS,
		'SK_BYTES' => $SK_BYTES,
		'SK_PKTS' => $SK_PKTS,
		'SK_TCP_FLAGS' => $SK_TCP_FLAGS,
		'SK_CONFIDENCE' => $SK_CONFIDENCE,
		'SK_PROTOCOL' => $SK_PROTOCOL,
		'SK_ADDR1' => $SK_ADDR1,
		'SK_PORT1' => $SK_PORT1,
		'SK_ADDR2' => $SK_ADDR2,
		'SK_PORT2' => $SK_PORT2,
		'SK_START' => $SK_START,
		'SK_END' => $SK_END,
		'SK_DURATION' => $SK_DURATION,
		'SK_LABEL' => $SK_LABEL,
	};

	my $ifk = {
		'IFK_FLOWS' => $IFK_FLOWS,
		'IFK_BYTES' => $IFK_BYTES,
		'IFK_PKTS' => $IFK_PKTS,
		'IFK_IF_INGRESS' => $IFK_IF_INGRESS,
		'IFK_IF_INGRESS_MULTIPLE' => $IFK_IF_INGRESS_MULTIPLE,
		'IFK_IF_EGRESS' => $IFK_IF_EGRESS,
		'IFK_IF_EGRESS_MULTIPLE' => $IFK_IF_EGRESS_MULTIPLE,
		'IFK_DSCP_LAST' => $IFK_DSCP_LAST,
		'IFK_DSCP_MULTIPLE' => $IFK_DSCP_MULTIPLE,
		'IFK_FIRST_TIME' => $IFK_FIRST_TIME,
		'IFK_LAST_TIME' => $IFK_LAST_TIME,
		'IFK_FIRST_TCP_FLAGS' => $IFK_FIRST_TCP_FLAGS,
		'IFK_LAST_TCP_FLAGS'  => $IFK_LAST_TCP_FLAGS,
	};

	print STDERR join("\n",
		"[session $sessionp]",
		( map { $_ . ' = ' .  ( (/ADDR/) ? &unhackIP($sessionp->[$sk->{$_}]) : $sessionp->[$sk->{$_}]) }
			(sort {$sk->{$a} <=> $sk->{$b}} keys %$sk) ),

		( map {
			my $exporter = $_;
			my $ep = $sessionp->[$SK_EXPS]->{$exporter};

			"  [exporter " . &unhackIP($exporter) . "]",
			"    TX",
			( map { "      $_ = " . $ep->[$EXPK_TX]->[$ifk->{$_}] } (sort {$ifk->{$a} <=> $ifk->{$b}} keys %$ifk) ),
			"    RX",
			( map { "      $_ = " . $ep->[$EXPK_RX]->[$ifk->{$_}] } (sort {$ifk->{$a} <=> $ifk->{$b}} keys %$ifk) )
		  } (sort keys %{$sessionp->[$SK_EXPS]})
		),
		undef
	);
}

sub dumpSessionSimple
{
	my $sessionp = shift @_;
	my @fields;

	my $tally = [ [], [] ];
	my $expcount = 0;
	my ($dscp, $dscpm);

	foreach my $exporter (sort {$a <=> $b} keys %{$sessionp->[$SK_EXPS]}) {
		$expcount++;
		my $ep = $sessionp->[$SK_EXPS]->{$exporter};
		
		foreach my $dir ($EXPK_TX, $EXPK_RX) {
			next if (! @{$ep->[$dir]});
			if (! defined $dscp) {
				$dscp = $ep->[$dir]->[$IFK_DSCP_LAST];
				$dscpm = $ep->[$dir]->[$IFK_DSCP_MULTIPLE];
			}
			elsif ($dscp != $ep->[$dir]->[$IFK_DSCP_LAST]) {
				$dscpm = 1;
			}
			elsif ($ep->[$dir]->[$IFK_DSCP_MULTIPLE]) {
				$dscpm = 1;
			}

			if ((scalar @{$tally->[$dir]} == 0) || ($tally->[$dir]->[$IFK_BYTES] < $ep->[$dir]->[$IFK_BYTES]))  {
				@{$tally->[$dir]} = @{$ep->[$dir]};
			}
		}
	}

	$dscp .= '*' if ($dscpm);

	print join(',',
		&unhackIP($exporter) . (($expcount > 1) ? '*' : ''),
		$sessionp->[$SK_PROTOCOL],
		&unhackIP($sessionp->[$SK_ADDR1]),
		$sessionp->[$SK_PORT1],
		&unhackIP($sessionp->[$SK_ADDR2]),
		$sessionp->[$SK_PORT2],
		$sessionp->[$SK_LABEL],
		$sessionp->[$SK_START],
		$sessionp->[$SK_DURATION],
		$dscp,

		map {
			(
			  $tally->[$_]->[$IFK_PKTS],
			  $tally->[$_]->[$IFK_BYTES],
			)
		} ($EXPK_TX, $EXPK_RX)

	) . "\n";
}

sub dumpSessionDetail
{
	my $sessionp = shift @_;
	my @fields;

	my $expcount = 0;

	my $flags = '';
	if ($sessionp->[$SK_PROTOCOL] == 6) {
		$flags .= ($sessionp->[$SK_TCP_FLAGS] & $TH_SYN) ? 'S' : '.';
		$flags .= ($sessionp->[$SK_TCP_FLAGS] & $TH_RST) ? 'R' : '.';
		$flags .= ($sessionp->[$SK_TCP_FLAGS] & $TH_FIN) ? 'F' : '.';
	}

	foreach my $exporter (sort {$a <=> $b} keys %{$sessionp->[$SK_EXPS]}) {
		$expcount++;
		my $ep = $sessionp->[$SK_EXPS]->{$exporter};
		
		my ($estart, $eend);
		foreach my $dir ($EXPK_TX, $EXPK_RX) {
			next if (! @{$ep->[$dir]});
			$estart = $ep->[$dir]->[$IFK_FIRST_TIME] if ( (! defined $estart) || ($ep->[$dir]->[$IFK_FIRST_TIME] < $estart) );
			$eend = $ep->[$dir]->[$IFK_LAST_TIME] if ( (! defined $eend) || ($ep->[$dir]->[$IFK_LAST_TIME] > $eend) );
		}
		my $eduration = int( ($eend - $estart + 0.0005) * 1000 ) / 1000;

		my ($srcIf, $srcMultiple, $dstIf, $dstMultiple);

		# combine bidirectional interfaces into one
		$srcIf = $ep->[$EXPK_TX]->[$IFK_IF_INGRESS];
		if (! ($srcMultiple = $ep->[$EXPK_TX]->[$IFK_IF_INGRESS_MULTIPLE])) {
			$srcMultiple = 1 if ($srcIf != $ep->[$EXPK_RX]->[$IFK_IF_EGRESS]);
		}
		$dstIf = $ep->[$EXPK_TX]->[$IFK_IF_EGRESS];
		if (! ($dstMultiple = $ep->[$EXPK_TX]->[$IFK_IF_EGRESS_MULTIPLE])) {
			$dstMultiple = 1 if ($dstIf != $ep->[$EXPK_RX]->[$IFK_IF_INGRESS]);
		}

#	print "# recn: exaddr,input,output,ip-protocol,ip-client-addr,ip-client-port,ip-server-addr,ip-server-port,tcp_flags,start,end,duration,c2s-flows,c2s-pkts,c2s-octets,c2s-tos,s2c-flows,s2c-pkts,s2c-octets,s2c-tos\n";

		print join(',',
			&unhackIP($exporter),
			$srcIf . ($srcMultiple ? '*' : ''),
			$dstIf . ($dstMultiple ? '*' : ''),
			$sessionp->[$SK_PROTOCOL],
			&unhackIP($sessionp->[$SK_ADDR1]),
			$sessionp->[$SK_PORT1],
			&unhackIP($sessionp->[$SK_ADDR2]),
			$sessionp->[$SK_PORT2],
			$sessionp->[$SK_LABEL],
			$flags,
			$sessionp->[$SK_START],
			$sessionp->[$SK_END],
			$sessionp->[$SK_DURATION],

			map {
				(
				  $ep->[$_]->[$IFK_FLOWS],
				  $ep->[$_]->[$IFK_PKTS],
				  $ep->[$_]->[$IFK_BYTES],
				  $ep->[$_]->[$IFK_DSCP_LAST] .  ($ep->[$IFK_DSCP_MULTIPLE] ? '*' : ''),
				)
			} ($EXPK_TX, $EXPK_RX)
		) . "\n";
	}
}

sub closeSession
{
	my $sessionp = shift @_;
	my ($flip, $backupflip);

	# logic to figure out who is the source

#	&debugSession($sessionp) if ($DEBUG);

	# TEST #1 -- look for bidirectional TCP SYN on the same router. If found, choose the earliest

	if ($sessionp->[$SK_PROTOCOL] == 6) {
		foreach my $exporterp (values %{$sessionp->[$SK_EXPS]}) {
			my $etx = $exporterp->[$EXPK_TX];
			my $erx = $exporterp->[$EXPK_RX];
			next if ((! @$etx) || (! @$erx));

			if ( ($etx->[$IFK_FIRST_TCP_FLAGS] & $TH_SYN) && ($erx->[$IFK_FIRST_TCP_FLAGS] & $TH_SYN) ) {

				my $delta = $etx->[$IFK_FIRST_TIME] - $erx->[$IFK_FIRST_TIME];

				# bidirectional TCP SYN observed; choose the earliest start time, if time delta > $EXPORTER_CLOCK_FUDGE
				if ( abs($delta) > $EXPORTER_CLOCK_FUDGE ) {
					$flip = ($etx->[$IFK_FIRST_TIME] > $erx->[$IFK_FIRST_TIME]);
					$sessionp->[$SK_CONFIDENCE] = 1;
					print STDERR "closed by test #1, flip=$flip\n" if ($DEBUG);
					last;
				}
				else {
					$backupflip = ($etx->[$IFK_FIRST_TIME] > $erx->[$IFK_FIRST_TIME]);
					print STDERR "test #1 suggests backupflip=$backupflip\n" if ($DEBUG);
				}
			}
		}
	}

	# TEST #2 -- look for a UDP/TCP port under 1024

	if (! defined $flip) {

		if ( ( $sessionp->[$SK_PORT1] < 1024 ) && ( $sessionp->[$SK_PORT2] >= 1024 ) ) {
			$flip = 1;
			$sessionp->[$SK_CONFIDENCE] = 2;
		}
		elsif ( ( $sessionp->[$SK_PORT2] < 1024 ) && ($sessionp->[$SK_PORT1] >= 1024 ) ) {
			$flip = 0;
			$sessionp->[$SK_CONFIDENCE] = 2;
		}
		print STDERR "closed by test #2, flip=$flip\n" if ((defined $flip) && ($DEBUG));
	}

	# TEST #3 -- look up each high port in a count of high port frequency

	if (! defined $flip) {
		my $hparray = ($sessionp->[$SK_PROTOCOL] == 6) ? \@tcpHighPorts : \@udpHighPorts;
		my $p1count = $hparray->[$sessionp->[$SK_PORT1]];
		my $p2count = $hparray->[$sessionp->[$SK_PORT2]];
		my $pratio = $p2count ? ($p1count / $p2count) : 0;

		if ($pratio < 0.8) {		# p2 is showing up much more than p1
			$flip = 0;
			$sessionp->[$SK_CONFIDENCE] = 3;
		}
		elsif ($pratio > 1.25) {	# p1 is showing up much more than p2
			$flip = 1;
			$sessionp->[$SK_CONFIDENCE] = 3;
		}
		print STDERR "closed by test #3, flip=$flip\n" if ((defined $flip) && ($DEBUG));
	}

	# TEST #4 -- check for unidirectional stream

	my $txuni = 1;
	my $rxuni = 1;
	foreach my $exporterp (values %{$sessionp->[$SK_EXPS]}) {
		my $etx = $exporterp->[$EXPK_TX];
		my $erx = $exporterp->[$EXPK_RX];

		$txuni=0 if (@{$exporterp->[$EXPK_TX]});
		$rxuni=0 if (@{$exporterp->[$EXPK_RX]});
	}

	if ($txuni != $rxuni) {
		$flip = $rxuni if (! defined $flip);
		$sessionp->[$SK_LABEL] = 'unidirectional';
		print STDERR "closed by test #4, flip=$flip\n" if ((defined $flip) && ($DEBUG));
	}
	elsif (! defined $flip) {
		$flip = $backupflip;
		print STDERR "closed with default behavior\n" if ($DEBUG);
	}

	# END OF TESTS -- at this point, we stick with the first packet we've ever seen...

	if ($flip) {
		my $addr1 = $sessionp->[$SK_ADDR1];
		my $port1 = $sessionp->[$SK_PORT1];
		$sessionp->[$SK_ADDR1] = $sessionp->[$SK_ADDR2];
		$sessionp->[$SK_PORT1] = $sessionp->[$SK_PORT2];
		$sessionp->[$SK_ADDR2] = $addr1;
		$sessionp->[$SK_PORT2] = $port1;

		foreach my $exporterp (values %{$sessionp->[$SK_EXPS]}) {
			my $txdata = $exporterp->[$EXPK_TX];
			$exporterp->[$EXPK_TX] = $exporterp->[$EXPK_RX];
			$exporterp->[$EXPK_RX] = $txdata;
		}
	}

	# COMPUTE DURATION

	my ($start, $end, $duration);
	my $improvise = 0;

	if (! defined $sessionp->[$SK_LABEL]) {
		if (! $sessionp->[$SK_TCP_FLAGS]) {		# not getting this field, must improvise like with UDP
			$improvise = 1;
			$sessionp->[$SK_LABEL] = 'complete';		# default, may be overwritten below
		}
		elsif ($sessionp->[$SK_PROTOCOL] == 6) {
			if ( ($sessionp->[$SK_TCP_FLAGS] & $TH_SYN) && ( ($sessionp->[$SK_TCP_FLAGS] & $TH_RST) || ($sessionp->[$SK_TCP_FLAGS] & $TH_FIN) ) ) {
				$sessionp->[$SK_LABEL] = 'complete';
			}
			else {
				$sessionp->[$SK_LABEL] = 'partial';
			}
		}
	}

	foreach my $exporter (keys %{$sessionp->[$SK_EXPS]}) {
		my $ep = $sessionp->[$SK_EXPS]->{$exporter};
		my ($estart, $eend);

		foreach my $dir ($EXPK_TX, $EXPK_RX) {
			next if (! @{$ep->[$dir]});
#			print join(',', "dir=$dir", @{$ep->[$dir]}) . "\n";
			$estart = $ep->[$dir]->[$IFK_FIRST_TIME] if ( (! defined $estart) || ($ep->[$dir]->[$IFK_FIRST_TIME] < $estart) );
			$eend = $ep->[$dir]->[$IFK_LAST_TIME] if ( (! defined $eend) || ($ep->[$dir]->[$IFK_LAST_TIME] > $eend) );
		}
		my $eduration = int( ($eend - $estart + 0.0005) * 1000 ) / 1000;

#		print "estart=$estart,eend=$eend,eduration=$eduration\n";

		if ($eduration >= $duration) {
			($duration, $start, $end) = ($eduration, $estart, $eend);
		}

		if ($improvise) {
			my $sbuf = $estart - $STIME{$exporter};
			my $ebuf = $ETIME{$exporter} - $eend;

			if ($sessionp->[$SK_PROTOCOL] == 17) {
				$sessionp->[$SK_LABEL] = 'partial' if (($sbuf < $UDP_SESSION_TIMEOUT_BUFFER) || ($ebuf < $UDP_SESSION_TIMEOUT_BUFFER))
			}
			elsif ($sessionp->[$SK_PROTOCOL] == 6) {
				$sessionp->[$SK_LABEL] = 'partial' if (($sbuf < $TCP_SESSION_TIMEOUT_BUFFER) || ($ebuf < $TCP_SESSION_TIMEOUT_BUFFER))
			}
		}
	}
	$sessionp->[$SK_START] = $start;
	$sessionp->[$SK_END] = $end;
	$sessionp->[$SK_DURATION] = $duration;

	&debugSession($sessionp) if ($DEBUG);
}

sub unhackIP     # integer -> dotted decimal
{
	my(@x) = ($_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
	return join(".", @x);
}

sub wanted
{
	$wantedCount++;
	if (time > $wantedMark) {
		$wantedMark = time + 1;
		my $msg = "time=" . (time - $wantedClock);
		$msg .= ", flows=$wantedCount" if (! $pipe);
		$msg .= ", fps=" . int($wantedCount / ((time - $wantedClock) || 1)) .  ", sessions=$sessionCount\n";
		print STDERR $msg;
	}

	if ($protocol == 6) {
		if (($srcport >= 1024) && ($dstport >= 1024)) {
			$tcpHighPorts[$srcport]++; $tcpHighPorts[$dstport]++;
		}
		$flags = $tcp_flags;
	}
	elsif ($protocol == 17) {
		if (($srcport >= 1024) && ($dstport >= 1024)) {
			$udpHighPorts[$srcport]++; $udpHighPorts[$dstport]++;
		}
		$flags = 0;
	}
	else {
		return;						# skip all but TCP and UDP
	}

	$stime = $startime + ($start_msecs / 1000);
	$etime = $endtime + ($end_msecs / 1000);
	$dscp = $tos & 0xfc;					# strip ECN

	return if ( ($stime < $CLOCK_SNAFU_CUTOFF) || ($etime < $CLOCK_SNAFU_CUTOFF) );		# clock is whacked

	if (! exists $STIME{$exporter}) {
		$STIME{$exporter} = $stime;
		$ETIME{$exporter} = $etime;
	}
	else {
		if ( (my $sdelta = $STIME{$exporter} - $stime) > 0 ) {
			return if ($sdelta > $CLOCK_SNAFU_CUTOFF);		# clock is whacked
			$STIME{$exporter} = $stime;
		}
		if ( (my $edelta = $etime - $ETIME{$exporter}) > 0 ) {
			return if ($edelta > $CLOCK_SNAFU_CUTOFF);		# clock is whacked
			$ETIME{$exporter} = $etime;
		}
	}

#	print "flow, $srcip $srcport, $dstip $dstport,stime=$stime,etime=$etime,startime=$startime,endtime=$endtime \n";

	# create/manage session structure
	my $index = pack $indexTemplate, $protocol, $srcaddr, $dstaddr, $srcport, $dstport;

	if ($sessionp = $sessions->{ $index } ) {
		$dir = $EXPK_TX;
		$sessionp->[$SK_FLOWS] ++;
		$sessionp->[$SK_BYTES] += $bytes;
		$sessionp->[$SK_PKTS] += $pkts;
		$sessionp->[$SK_TCP_FLAGS] |= $flags;
	}
	elsif ($sessionp = $sessions->{ pack $indexTemplate, $protocol, $dstaddr, $srcaddr, $dstport, $srcport } ) {
		$dir = $EXPK_RX;
		$sessionp->[$SK_FLOWS] ++;
		$sessionp->[$SK_BYTES] += $bytes;
		$sessionp->[$SK_PKTS] += $pkts;
		$sessionp->[$SK_TCP_FLAGS] |= $flags;
	}
	else {
		return if ($pkts < 5);

		$sessionp = $sessions->{ $index } =
			[
				1,			# $SK_FLOWS
				$bytes,			# $SK_BYTES
				$pkts,			# $SK_PKTS
				$flags,			# $SK_TCP_FLAGS
				0,			# $SK_CONFIDENCE
				$protocol,		# $SK_PROTOCOL
				$srcaddr,		# $SK_ADDR1
				$srcport,		# $SK_PORT1
				$dstaddr,		# $SK_ADDR2
				$dstport,		# $SK_PORT2
				0,			# $SK_START
				0,			# $SK_END
				0,			# $SK_DURATION
				{ }, 			# $SK_EXPS
				undef,			# $SK_LABEL
			];

		$dir = $EXPK_TX;

		if (++$sessionCount > $sessionMax) {			# must trim our session list of the least worthy

			print "session wrap\n" if ($DEBUG);

			foreach( (sort { $sessions->{$a}->[$sortBy] <=> $sessions->{$b}->[$sortBy] } keys %$sessions)[1..$sessionPurge]) {
				delete $sessions->{$_};
			}
			$sessionCount = scalar keys %$sessions;		# $sessionPurge;
		}
	}

	# create/manage exporter structure

	if (! exists $sessionp->[$SK_EXPS]->{$exporter}) {		# FIRST FLOW
		$exporterp = $sessionp->[$SK_EXPS]->{$exporter} = [ [], [] ];
	}
	else {
		$exporterp = $sessionp->[$SK_EXPS]->{$exporter};
	}

	if (! @{$exporterp->[$dir]}) {			# RECORD NEW FLOW

		$exporterp->[$dir] = 
			[
				1,			# $IFK_FLOWS
				$bytes,			# $IFK_BYTES
				$pkts,			# $IFK_PKTS
				$input_if,		# $IFK_IF_INGRESS
				0,			# $IFK_IF_INGRESS_MULTIPLE
				$output_if,		# $IFK_IF_EGRESS
				0,			# $IFK_IF_EGRESS_MULTIPLE
				$dscp,			# $IFK_DSCP_LAST
				0,			# $IFK_DSCP_MULTIPLE
				$stime,			# $IFK_FIRST_TIME
				$etime,			# $IFK_LAST_TIME
				$flags,			# $IFK_FIRST_TCP_FLAGS
			];
	}
	else {						# UPDATE EXISTING FLOW
		my $edp = $exporterp->[$dir];

		if ($stime < $edp->[$IFK_FIRST_TIME]) {
			$edp->[$IFK_FIRST_TIME] = $stime;
			$edp->[$IFK_FIRST_TCP_FLAGS] = $flags;
		}

		if ($etime > $edp->[$IFK_LAST_TIME]) {
			$edp->[$IFK_LAST_TIME] = $etime;
		}

		$edp->[$IFK_FLOWS] ++;
		$edp->[$IFK_BYTES] += $bytes;
		$edp->[$IFK_PKTS] += $pkts;

		if ($edp->[$IFK_DSCP_LAST] != $dscp) {
			$edp->[$IFK_DSCP_LAST] = $dscp;
			$edp->[$IFK_DSCP_MULTIPLE] = 1;
		}

		if ($edp->[$IFK_IF_INGRESS] != $input_if) {
			$edp->[$IFK_IF_INGRESS_MULTIPLE] = 1 if (defined $edp->[$IFK_IF_INGRESS]);
			$edp->[$IFK_IF_INGRESS] = $input_if;
		}

		if ($edp->[$IFK_IF_EGRESS] != $output_if) {
			$edp->[$IFK_IF_EGRESS_MULTIPLE] = 1 if (defined $edp->[$IFK_IF_EGRESS]);
			$edp->[$IFK_IF_EGRESS] = $output_if;
		}
	}
}

sub perfile
{
	my $fname = shift;
	print STDERR "$0 working file=$fname\n" if (! $pipe);
	$wantedClock = time;
	$wantedMark = time + 1;
	$wantedCount = 0;
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

sub datefmt
{
        my($secs,$msecs) = @_;
	if ( int($secs) != $secs ) {
		$msecs = $secs - int($secs);
		$secs = int($secs);
	}
        return POSIX::strftime("%Y-%m-%d %H:%M:%S", localtime($secs)) . sprintf(".%03d", $msecs);
}

sub secfmt
{
        my($secs,$msecs) = @_;
	if ( int($secs) != $secs ) {
		$msecs = $secs - int($secs);
		$secs = int($secs);
	}
        return sprintf("%d:%02d:%02d.%04d", 
		int($secs / 3600),
		int( ($secs % 3600) / 60),
		($secs % 60),
		int($msecs * 1000)
	);
}

