#!/usr/bin/perl

use Cflow qw(:flowvars find);   # for reading Cflowd data files
use POSIX;                      # for strftime
use Time::Local;                # need the timelocal function

use strict;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our @files;

foreach (@ARGV) {
	push(@files, $_) if (-f $_);
}

our $exporters = {};

Cflow::find(\&wanted, \&perfile, @files);

&loadInterfaces;

print join("\t", qw/Exporter-IP Exporter-Name Flows Time-Range First-Time Last-Time Rx-Only-Interfaces Tx-Only-Interfaces/) . "\n";

foreach (sort byPaddedNum keys %$exporters) {
	my $exp = $exporters->{$_};
	my (@rxonly, @txonly);

	foreach (keys %{$exp->{interfaces}}) {
		my $if = $exp->{interfaces}->{$_};
		push(@rxonly, $_) if (($if->{rx} > 0) && ($if->{tx} == 0));
		push(@txonly, $_) if (($if->{tx} > 0) && ($if->{rx} == 0));
	}

	my $sec = ($exp->{endtime} + $exp->{end_msecs} / 1000) - ($exp->{startime} + $exp->{start_msecs} / 1000);

	print join("\t",
		$_, $exp->{name}, $exp->{count},
		sprintf("%d:%02d:%02d.%03d", int($sec / 3600), int((int($sec) % 3600) / 60), int($sec) % 60, 1000 * ($sec - int($sec))),
		&datefmt($exp->{startime}, $exp->{start_msecs}),
		&datefmt($exp->{endtime}, $exp->{end_msecs}),
		join(', ', map { $exp->{interfaces}->{$_}->{ifDescr} } @rxonly),
		join(', ', map { $exp->{interfaces}->{$_}->{ifDescr} } @txonly),
	) . "\n";
}

exit;

sub wanted
{
	if (! exists $exporters->{$exporterip}) {
		$exporters->{$exporterip} = {
			'count' => 1,
			'startime' => $startime,
			'start_msecs' => $start_msecs,
			'endtime' => $endtime,
			'end_msecs' => $end_msecs,
			'interfaces' => {
				$input_if => { 'rx' => 1 },
				$output_if => { 'tx' => 1 },
			}
		}
	}
	else {
		my $exp = $exporters->{$exporterip};

		if ( ($startime < $exp->{startime}) || ( ($startime == $exp->{startime}) && ($start_msecs < $exp->{start_msecs})) ) {
			$exp->{startime} = $startime;
			$exp->{start_msecs} = $start_msecs;
		}
		if ( ($endtime > $exp->{endtime}) || ( ($endtime == $exp->{endtime}) && ($end_msecs > $exp->{end_msecs})) ) {
			$exp->{endtime} = $endtime;
			$exp->{end_msecs} = $end_msecs;
		}
		$exp->{interfaces}->{$input_if}->{rx}++;
		$exp->{interfaces}->{$output_if}->{tx}++;
		$exp->{count}++;
	}
}

sub perfile
{
	print "reading " . (shift @_) . "\n";
}

sub datefmt
{
	my($secs,$msecs) = @_;
	return POSIX::strftime("%Y-%m-%d %H:%M:%S", localtime($secs)) . sprintf(".%03d", $msecs);
}

sub loadInterfaces
{
	my %exporter;
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

	foreach (@ifDataFiles) {
		next if (! /^ifData\.(\d+\.\d+\.\d+\.\d+)$/);
		my $ip = $1;
		my $name;

		next if (! exists $exporters->{$ip});

		open(IN, "$ifCacheDir/$_");

		<IN>; <IN>; <IN>; <IN>; <IN>; <IN>;
		chomp( $name = <IN> );
		$exporters->{$ip}->{name} = $name;

		while ( <IN> ) {
			chomp;
			next if (! /\t/);
			my ($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);
			$exporters->{$ip}->{interfaces}->{$ifIndex}->{ifAlias} = $ifAlias;
			$exporters->{$ip}->{interfaces}->{$ifIndex}->{ifDescr} = $ifDescr;
		}
		close(IN);
	}
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

