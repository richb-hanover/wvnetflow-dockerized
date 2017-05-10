#!/usr/bin/perl

use strict;
use CGI qw/:standard/;
use CGI::Carp qw( fatalsToBrowser );

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $SHOW_PACKETS = 0;
our $SHOW_FLOWS = 1;
our $SHOW_RESETS = 0;
our $SHOW_LOST = 0;
our $SHOW_LOSTPERC = 1;

our $colspan = ($SHOW_PACKETS ? 1 : 0) + ($SHOW_FLOWS ? 1 : 0) + ($SHOW_RESETS ? 1 : 0) + ($SHOW_LOST ? 1 : 0) + ($SHOW_LOSTPERC ? 1 : 0);

our $debug = 0;

$| = 1;

print header(),
	start_html('NetFlow collection stats'),
	h1('NetFlow collection stats'), "\n";

my (%dhash, %dates, @dates, %exporters, %chash, %cexporters);

my $exporterNames = &loadExporterNames;

my @files;
push(@files,
	(reverse sort split(/\s+/, `find /var/log/ -name messages.* -mtime -14`)),
	'/var/log/messages'
);

my $count = 0;

print "processing " . (scalar @files) . " log files...<br>\n" if ($debug);

foreach (@files) {
	open(IN, (($_ =~ /\.bz2$/) ? "bzcat $_ |" : ($_ =~ /\.gz$/) ? "gunzip -c $_ |" : $_)) || do {
		print "could not read $_ -- is it set to permissions 0644?<br>\n";
		next;
	};

	while ( <IN> ) {
		$count++;

		# flow-capture[17304]: STAT: now=1179783900
		next if (! /flow-capture\[(\d+)\]\: STAT/);

		my $pid = $1;

		next if (!/^(\S+\s+\d+) (\d+\:\d+)\:\d+.*src_ip=(\S+).*d_ver=(\d+).*pkts=(\d+).*flows=(\d+) lost=(\d+) reset=(\d+)/);

		my($date, $time, $src, $ver, $pkts, $flows, $lost, $reset) = ($1, $2, $3, $4, $5, $6, $7, $8);

		if (! exists $dates{$date}) {
			push(@dates, $date);
			$dates{$date}->{'first'} = $time;
		}
		$dates{$date}->{'last'} = $time;

		my $exp = "$src:$ver";

		$exporters{$pid,$exp} = 1;

		if (! exists $dhash{$date}->{$pid,$exp}) {
			$dhash{$date}->{$pid,$exp}->{'first'} = {
				'pkts' => $pkts,
				'flows' => $flows,
				'lost' => $lost,
				'reset' => $reset
			};
		}

		if ($pkts < $dhash{$date}->{$pid,$exp}->{first}->{pkts}) {
			print "reset $exp at $date $time<br>\n"  if ($debug);

			$dhash{$date}->{$pid,$exp}->{'first'} = {
				'pkts' => $pkts,
				'flows' => $flows,
				'lost' => $lost,
				'reset' => $reset
			};
		}

		$dhash{$date}->{$pid,$exp}->{'last'} = {
			'pkts' => $pkts,
			'flows' => $flows,
			'lost' => $lost,
			'reset' => $reset
		};
	}
}

if (! @dates) {
	print h2("No netflow collection data found...");
	exit 0;
}

my @colstyle = (
	"'background: #e0e0ff'",
	"'background: #ffe0e0'",
);

print "read $count lines\n" if ($debug);

print "<table style='font-family:sans-serif; font-size: 8pt;' border=1 rules=groups cellpadding=3>",
	"<thead>",
	"<colgroup span=1>",
	map { "<colgroup span=$colspan>" } @dates;

# pkts flows lost lost%

print "<tr>";
print "<th rowspan=2 valign=bottom>Exporter";
print "<th rowspan=2 valign=bottom>IP:version";

my $col = 0;
foreach my $date (@dates) {
	print "<th colspan=$colspan align=center valign=bottom style=" . $colstyle[$col++ % 2] . ">$date";

	if ( ($dates{$date}->{'first'} ge '00:30') || ($dates{$date}->{'last'} le '23:30') ) {
		print "<sup>*</sup>";
	}
}

my $col = 0;
print "\n<tr>";
foreach my $date (@dates) {
	my @cols;
	push(@cols, 'Packets') if ($SHOW_PACKETS);
	push(@cols, 'Flows') if ($SHOW_FLOWS);
	push(@cols, 'Resets') if ($SHOW_RESETS);
	push(@cols, 'Lost') if ($SHOW_LOST);
	push(@cols, 'Lost%') if ($SHOW_LOSTPERC);

	print map { "<th align=center style=" . $colstyle[$col % 2] . ">$_" } @cols;
	$col++;
}

print "\n</thead><tbody align=right>";

foreach my $exp (sort byPaddedNum keys %exporters) {
	my($pid, $exporter) = split(/$;/, $exp);

	foreach my $date (@dates) {
		my $hp = $dhash{$date}->{$exp};

		my $pkts = $hp->{'last'}->{'pkts'} - $hp->{'first'}->{'pkts'};
		my $flows = $hp->{'last'}->{'flows'} - $hp->{'first'}->{'flows'};
		my $lost = $hp->{'last'}->{'lost'} - $hp->{'first'}->{'lost'};
		my $reset = $hp->{'last'}->{'reset'} - $hp->{'first'}->{'reset'};

		# handle wrap -- this is flawed if multiple wraps occur in a 24-hour period.

		$flows += 2**32 if ($flows < 0);
		$pkts += 2**32 if ($pkts < 0);
		$lost += 2**32 if ($lost < 0);
		$reset += 2**32 if ($reset < 0);

		if ($pkts > 0) {
			$chash{$date}->{$exporter}->{pkts} += $pkts;
			$chash{$date}->{$exporter}->{flows} += $flows;
			$chash{$date}->{$exporter}->{lost} += $lost;
			$chash{$date}->{$exporter}->{reset} += $reset;

			$exporter =~ /([\d\.]+)\:/;
			$cexporters{$exporter} = $exporterNames->{$1} || "unknown";
		}
	}
}

foreach my $exp (sort { lc($cexporters{$a}) cmp lc($cexporters{$b}) } keys %cexporters) {

	print "\n<tr>";
	print "<td>" . $cexporters{$exp};
	print "<td>" . $exp;

	my $col = 0;
	foreach my $date (@dates) {
		my $hp = $chash{$date}->{$exp};

		my $pkts = $hp->{pkts};
		my $flows = $hp->{flows};
		my $lost = $hp->{lost};
		my $reset = $hp->{reset};
		my $lostp = sprintf("%.2f%%", ($flows+$lost) ? (100 * $lost / ($flows+$lost)) : 0);

		my @cols;
		push(@cols, &commafy($pkts))if ($SHOW_PACKETS);
		push(@cols, &commafy($flows)) if ($SHOW_FLOWS);
		push(@cols, &commafy($reset)) if ($SHOW_RESETS);
		push(@cols, &commafy($lost)) if ($SHOW_LOST);
		push(@cols, sprintf("%.2f%%", ($flows) ? (100 * $lost / $flows) : 0)) if ($SHOW_LOSTPERC);

		print map { "<td style=" . $colstyle[$col % 2] . ">$_" } @cols;

		$col++;
	}
}
print "</table>\n";
print end_html;

sub commafy
{
	local $_ = $_[0];

	return $_ if (! /^\d+\.?\d*$/);
	$_ = sprintf("%.02f", $_) if (/\./);
	while (s/^(\d+)(\d{3})/$1,$2/) {}
	return $_;
}

sub byPaddedNum{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

# Apr 29 09:00:00 ustca137 flow-capture[26959]: STAT: now=1083247200 startup=1083166953 src_ip=172.16.0.113 dst_ip=165.28.97.137 d_ver=5 pkts=3721 flows=8666 lost=947 reset=0 filter_drops=0

sub loadExporterNames
{
	my $stateDir = "/tmp";
	my $ifCacheDir;
	my $exporters = {};

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

	opendir(DIR, $ifCacheDir);
	foreach ( grep (/^ifData/, readdir(DIR)) ) {
		if (/ifData\.([\d\.]+)$/) {
			my $ip = $1;
			my $name;

			open(IN, "$ifCacheDir/$_");
			<IN>; <IN>; <IN>; <IN>; <IN>; <IN>;
			chomp( $name = <IN> );

			$exporters->{$ip} = $name;
	}
	closedir(DIR);

	return $exporters;

}

