#!/usr/bin/perl

# exporter.cgi -- display a quick table of all exporters
#
#  v1.0  2-10-2012 initial version

use CGI qw(:standard :html3 *table escape -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use POSIX;
use Time::Local;
use Storable;
use strict;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $DEBUG = 0;

our $REPORTPERIOD = 60;			# show flow data for last 60 minutes
our $DIR_RX = 0;
our $DIR_TX = 1;
our $DIR_EX = 2;

our $highcolor = "#00c0c0";

our $title = "Webview Exporter Status from " .
	POSIX::strftime("%l:%M%P", localtime(time - $REPORTPERIOD * 60)) . " to " .
	POSIX::strftime("%l:%M%P", localtime(time)) . " on " .
	POSIX::strftime("%F", localtime(time));

our $exporters = &loadData;

if (my $zoom = param('zoom')) {
	&zoom($zoom);
}
else {
	&main();
}

exit 0;

sub zoom
{
	my $ip = shift;

	my $STYLE = <<EOT;
body,td { font-family:monospace; font-size:8pt; white-space: nowrap; }
table { empty-cells: show; border-collapse:collapse; }
td.num { text-align: right; }
EOT

	my $title = $exporters->{$ip}->{name} . ' interfaces';

	print header(),
		start_html( {
			-title=>$title,
			-style=>{-code=>$STYLE},
		}),

		h3($title),

		table({-border=>1, -cellpadding=>3, -cellspacing=>0},

			Tr( map { th($_) } qw/ifIndex ifAlias ifDescr ifSpeed rx-flows rx-bytes rx-pkts tx-flows tx-bytes tx-pkts/),

			map {
				my $ifx = $exporters->{$ip}->{interfaces}->{$_};

				Tr(
					td($_),
					td($ifx->{ifDescr}),
					td($ifx->{ifAlias}),
					td({-class=>'num'}, &commafy($ifx->{ifSpeed})),
					(map { td({-class=>'num'}, &commafy($ifx->{$DIR_RX}->{$_})) } qw/flows bytes pkts/),
					(map { td({-class=>'num'}, &commafy($ifx->{$DIR_TX}->{$_})) } qw/flows bytes pkts/),
				)
			} sort {$a <=> $b} keys %{$exporters->{$ip}->{interfaces}}
		),
		end_html;
}

sub main
{
	my $total = scalar keys %$exporters;

	my $STYLE = <<EOT;
body {
	height:100%;
	margin:5px;
	padding:0;
}

BODY,select,td,tr {
	font-size: 8pt;
	white-space: nowrap;
}

tr.main:hover { color: $highcolor; }
tr.sub { color: $highcolor; }
td.num { text-align: right; }
EOT

	print header(),
		start_html(-title=>$title,
			-style => [
				{ -code => $STYLE },
			],
		),
		h1($title);

	my $sort = param('sort') || 'name';
	Delete('sort');

	my @exporters;
	if ($sort =~ /^(name|sysname)$/i) {
		@exporters = sort {
			my $a1 = $exporters->{$a}->{$sort};
			my $b1 = $exporters->{$b}->{$sort};
			$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
			$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
			(lc($a1) cmp lc($b1));
		} keys %$exporters;
	}
	elsif ($sort =~ /^snmp$/i) {
		@exporters = sort { $exporters->{$a}->{snmpHost} cmp $exporters->{$b}->{snmpHost} } keys %$exporters;
	}
	elsif ($sort =~ /^(lastpolltime|startime|endtime)$/i) {
		@exporters = sort { $exporters->{$a}->{$sort} cmp $exporters->{$b}->{$sort} } keys %$exporters;
	}
	elsif ($sort =~ /^(flows|bytes|pkts|duration)$/i) {
		@exporters = sort { $exporters->{$b}->{flow}->{$sort} <=> $exporters->{$a}->{flow}->{$sort} } keys %$exporters;
	}
	elsif ($sort =~ /^(exlost%|exreset|exdup)$/i) {
		my $sort2 = ($sort eq 'exlost%') ? 'exlost' : 'expkts';
		@exporters = sort { ( $exporters->{$b}->{$sort} <=> $exporters->{$a}->{$sort} ) ||
			( $exporters->{$b}->{$sort2} <=> $exporters->{$a}->{$sort2} )
		} keys %$exporters;
	}
	elsif ($sort =~ /^(exver|expkts|exlost)$/i) {
		@exporters = sort { $exporters->{$b}->{$sort} <=> $exporters->{$a}->{$sort} } keys %$exporters;
	}
	else {
		@exporters = sort byPaddedNum keys %$exporters;
	}

	my $refs = { map { $_, self_url(-relative=>1) . '?sort=' . lc($_) } qw/IP Name sysName snmp lastPollTime flows bytes pkts exver expkts exlost exlost% exdup exreset starTime endTime duration/ };

	print start_table({-border=>1, -cellspacing=>0, -cellpadding=>3, -style=>"padding:1px 3px;"});
	print colgroup({-span=>2, -style=>'background-color:#e0e0ff'}),
		colgroup({-span=>3, -style=>'background-color:#e0ffe0'}),
		colgroup({-span=>6, -style=>'background-color:#ffe0e0'}),
		colgroup({-span=>6, -style=>'background-color:#ffffe0'});

	print thead(
		Tr( th({-colspan=>2}, 'Exporter'), th({-colspan=>3}, 'SNMP'), th({-colspan=>6}, 'Export Traffic'), th({-colspan=>6}, 'Flow Data') ),

		Tr( map { th($_) } map { a({-href=>$refs->{$_}}, $_) } qw/IP Name sysName snmp lastPollTime exver expkts exlost exlost% exdup exreset flows bytes pkts starTime endTime duration/)
	);
	my $count = 0;

	Delete_all();
	foreach my $ip (@exporters) {
		$count++;

		my $secs = $exporters->{$ip}->{flow}->{duration};
		my $self = self_url(-relative=>1) . "?zoom=$ip";

		print Tr( {-class=>'main', -onClick=>"window.open('$self')"}, 		# "showPopWin('$self',1000,400,null)"},
			td($ip),
			(map { td($exporters->{$ip}->{$_}) } qw/name sysName/),
			td( &hackSnmpHost($exporters->{$ip}->{snmpHost}) ),
			td( &datestr($exporters->{$ip}->{lastPollTime}) ),
			td( $exporters->{$ip}->{exver}),
			(map { td({-class=>'num'}, &commafy($exporters->{$ip}->{$_})) } qw/expkts exlost exlost% exdup exreset/),
			(map { td({-class=>'num'}, &commafy($exporters->{$ip}->{flow}->{$_})) } qw/flows bytes pkts/),
			td( &datestr($exporters->{$ip}->{flow}->{startime}) ),
			td( &datestr($exporters->{$ip}->{flow}->{endtime}) ),
			td( sprintf("%d:%02d:%02d", int($secs/3600), int($secs / 60) % 60, $secs %60) ),
		);
	}
	print end_table;

	print end_html();
}

sub hackSnmpHost
{
	my $s = &str2hash(shift);

	return $s->{-version} ? 'v' . $s->{-version} . '/' . ( $s->{-community} || $s->{-username} ) : '';

#	-authpassword=Lib3rty1!-authprotocol=MD5-hostname=10.103.255.118-privpassword=2004r3ds0x-privprotocol=DES-username=telecom-version=3
#	-community=equin0x-hostname=10.103.255.114-port=161-version=2

}

sub str2hash
{
	my $hp = {};
	foreach (split(/$;/, shift)) { if (/^(.*)=(.*)$/) { $hp->{$1} = $2; } }
	return $hp;
}


sub datestr
{
	my $date = shift;
	my $datestr = "%Y-%m-%d %H:%M:%S";

	return undef if (! $date);
	return POSIX::strftime($datestr, localtime($date));
}

sub loadData
{
	my $cacheFile = "/tmp/exporter-report.cache";
	my $age = time;

	if ( (-f $cacheFile) && ( (time - (stat($cacheFile))[9]) < 300) ) {
		return retrieve($cacheFile);
	}

	my $exporters = {};
	&loadInterfaces($exporters);
	&loadFlows($exporters);
	&loadPeerStats($exporters);

	foreach my $ip (keys %$exporters) {
		my $p = $exporters->{$ip};

		$p->{flow}->{duration} = $exporters->{$ip}->{flow}->{endtime} - $exporters->{$ip}->{flow}->{startime};

		$p->{exver} = $p->{lastver}->{last};
		$p->{expkts} = $p->{packets}->{tally};
		$p->{exdup} = $p->{dup}->{tally};
		$p->{exreset} = $p->{reset}->{tally};
		$p->{exlost} = $p->{lost}->{tally}; 		# lost packets (v9) or flows (v5/v7)

		my $total;

		if ($p->{exver} == 9) {		# calculate lost by packets
			$total = $p->{expkts} - $p->{exdup} + $p->{exlost};
		}
		else {
			$total = $p->{flow}->{flows} + $p->{exlost};
		}

		$p->{'exlost%'} = ($total) ? int(100 * $p->{exlost} / $total) : 0;
	}

	store $exporters, $cacheFile;
	return $exporters;
}

sub dumpText
{
	my $cacheFile = "/tmp/exporter-report.cache";
	if (1) {
		open(OUT, ">$cacheFile");

		foreach my $ip (keys %$exporters) {
			print OUT join("\t",
				$ip,
				(map { $exporters->{$ip}->{$_} } qw /name sysName sysUpTime ifTableLastChanged lastPollTime snmpHost cacheFileName cacheFileTime/),
				(map { $exporters->{$ip}->{flow}->{$_} } qw/flows bytes pkts startime endtime/),
			) . "\n";
		}
		print OUT "\n";

		foreach my $ip (keys %$exporters) {
			foreach my $ifIndex (keys %{$exporters->{$ip}->{interfaces}}) {
				print OUT join("\t",
					$ip, $ifIndex,
					(map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$_} } qw/ifDescr ifAlias ifSpeed/),
					(map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$DIR_RX}->{$_} } qw/flows bytes pkts/),
					(map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$DIR_TX}->{$_} } qw/flows bytes pkts/),
				) . "\n";
			}
		}
		close(OUT);
	}
	else {
		return retrieve($cacheFile);

		open(IN, $cacheFile);
		while ( <IN> ) {		# read exporters
			chomp;
			last if (/^$/);		# move to next section
			my ($ip, @x) = split(/\t/);
			map { $exporters->{$ip}->{$_} = shift @x } qw/name sysName sysUpTime ifTableLastChanged lastPollTime cacheFileName cacheFileTime/;
			map { $exporters->{$ip}->{flow}->{$_} = shift @x } qw/flows bytes pkts startime endtime/;
		}
		while ( <IN> ) {		# read interfaces
			chomp;
			my ($ip, $ifIndex, @x) = split(/\t/);
			map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$_} = shift @x } qw/ifDescr ifAlias ifSpeed/;
			map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$DIR_RX}->{$_} = shift @x } qw/flows bytes pkts/;
			map { $exporters->{$ip}->{interfaces}->{$ifIndex}->{$DIR_TX}->{$_} = shift @x } qw/flows bytes pkts/;
		}
		close(IN);
	}
}

sub loadPeerStats
{
	my $exporters = shift;
	my $last;

	my %months = (
		'jan' => 0, 'feb' => 1, 'mar' => 2, 'apr' => 3, 'may' => 4, 'jun' => 5, 'jul' => 6, 'aug' => 7, 'sep' => 8, 'oct' => 9, 'nov' => 10, 'dec' => 11
	);

	open(IN, $flowdSyslog);
	while ( <IN> ) {
		next if (! /^(\w\w\w)\s+(\d+)\s+(\d\d)\:(\d\d)\:\d\d \S+ flowd\[\d+\]\: peer \d+ - ip=(\S+) (.*)/);
		next if $last eq "$1$2$3$4";
		$last = "$1$2$3$4";

		next if (! exists $months{lc($1)});

		my $ip = $5;
		my $stuff = $6;
		my $t = timelocal(0, $4, $3, $2, $months{lc($1)}, (localtime())[5]);
		next if ($t < time - $REPORTPERIOD * 60);
		undef $last;

		$stuff =~ s/(\w+)=(\S+)/&tallyPeer($exporters->{$ip},$1,$2)/ge;
	}
# Apr 19 17:05:01 vxpit-hnetfl01 flowd[8676]: peer 536 - ip=10.254.6.44 packets=305 flows=5021 lost=0 invalid=0 reset=0 dup=0 no_template=0 firstseen=2012-04-19T20:00:51.615 lastseen=2012-04-19T21:04:49.717 lastver=5
	close(IN);

	sub tallyPeer {
		my($p, $k, $v) = @_;
		if (exists $p->{$k}->{last}) {
			if ($v < $p->{$k}->{last}) {		# wrap
				$p->{$k}->{tally} += $v;
			}
			else {
				$p->{$k}->{tally} += ($v - $p->{$k}->{last});
			}
		}
		$p->{$k}->{last} = $v;
	}
}

sub loadFlows
{
	my $exporters = shift;

	my $watchDir = $flowDirs{$flowDirActive};

	my $findCmd = "find $watchDir -name 'summary-*' -mmin -$REPORTPERIOD";
	print "findCmd = $findCmd", br, "\n" if ($DEBUG);
	my $findResults = `$findCmd`;

	my @flowFiles = map { "$1$2" if /^(.*)summary-(.*)/ } split(/\n/, $findResults);
	print "flowfiles = $#flowFiles", br, "\n" if ($DEBUG);

	my $count = 0;
	my $flowCmd = "$flowCheck --full @flowFiles";
	print "flowCmd = $flowCmd", br, "\n" if ($DEBUG);

	open(IN, "$flowCmd |");
	while ( <IN> ) {
		chomp;
		next if (/^#/);
		my ($exporterip,$if,$direction,$flows,$bytes,$pkts,$startime,$endtime) = split(/,/);
		$count++;

		if ($direction == $DIR_EX) {
			$exporters->{$exporterip}->{flow} = {
				'flows' => $flows,
				'bytes' => $bytes,
				'pkts' => $pkts,
				'startime' => $startime,
				'endtime' => $endtime,
			};
		}
		elsif (($direction == $DIR_RX) || ($direction == $DIR_TX)) {
			$exporters->{$exporterip}->{interfaces}->{$if}->{$direction} = {
				'flows' => $flows,
				'bytes' => $bytes,
				'pkts' => $pkts,
			}
		}
	}
	close(IN);
	print "$count flow stat lines\n", br if ($DEBUG);
}

sub loadInterfaces
{
	my $exporters = shift;
	my $stateDir = "/tmp";
	my $ifCacheDir;

	# FUTURE WORK: should add recursion here

	open(IN, $configFile);
	while ( <IN> ) {
		chop;
		next if (/^\s*\#/);	# skip comment-only lines

		s/\s*[\#\;].*//;	# get rid of comments
		s/^\s+//;		# get rid of leading whitespace
		s/\s+$//;		# get rid of trailing whitespace
		s/\s+/ /g;		# make sure all whitespace is realy a single space
					#  (increases readability of the regexps below)

		if (/^directory (temp|state) (.*)/) {
			$stateDir = $2;
		}
		elsif (/^directory cache (.*)/) {
			$ifCacheDir = $1;
		}
	}
	close(IN);

	$ifCacheDir = $stateDir if (! defined $ifCacheDir);

	opendir(DIR, $ifCacheDir) || print "$!<br>\n";
	my(@ifDataFiles) = grep (/^ifData/, readdir(DIR));
	closedir(DIR);

	my $count = 0;
	foreach (@ifDataFiles) {
		next if (! /^ifData\.(\d+\.\d+\.\d+\.\d+)$/);
		$count++;
		my $ip = $1;

		my $cacheFile = "$ifCacheDir/$_";
		open(IN, $cacheFile);

		$exporters->{$ip}->{cacheFileName} = $cacheFile;
		$exporters->{$ip}->{cacheFileTime} = (stat($cacheFile))[9];

		chomp($_ = <IN>); $exporters->{$ip}->{sysUpTime} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{ifTableLastChanged} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{lastPollTime} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{lastMinorPollTime} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{snmpHost} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{sysName} = $_;
		chomp($_ = <IN>); $exporters->{$ip}->{name} = $_;

		delete $exporters->{$ip}->{snmpHost} if (! $exporters->{$ip}->{sysName});

		while ( <IN> ) {
			chomp;
			next if (! /\t/);
			my ($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);

# 8       Serial1/0       0905,3945(10.250.251.193)       45000000

			$exporters->{$ip}->{interfaces}->{$ifIndex} = {
				'ifDescr' => $ifDescr,
				'ifAlias' => $ifAlias,
				'ifSpeed' => $ifSpeed
			};
		}
		close(IN);
	}
	print "read $count cache files<br>\n" if ($DEBUG);
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

sub commafy
{
	local $_ = $_[0];
	return $_ if (! /^\d+\.?\d*$/);
	$_ = sprintf("%.02f", $_) if (/\./);
	while (s/^(\d+)(\d{3})/$1,$2/) {}
	return $_;
}

