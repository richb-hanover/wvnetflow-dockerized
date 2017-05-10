#!/usr/bin/perl

# wvFlowCheck.pl  - this is an exporter-centric reporter

#  v1.0   2012-03-19   initial version

use strict;
use Cflow qw(:flowvars find);   # for reading Cflowd data files
use POSIX;                      # for strftime
use Time::Local;                # need the timelocal function

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $D_FLOWS = 0;
our $D_PKTS = 1;
our $D_BYTES = 2;
our $D_STARTIME = 3;
our $D_ENDTIME = 4;
our $D_INTERFACE = 5;

our $DIR_RX = 0;
our $DIR_TX = 1;
our $DIR_EX = 2;

our $exp;			# global for speed
our $flows;			# 1 for Cflow, set elsewhere
our $direction;			# undef for Cflow, DIR_EX, DIR_RX, or DIR_TX otherwise

select STDERR;
$| = 1;
select STDOUT;

# process arguments

our @files;
our $sortBy;
our $simple = 1;
our $pipe = 0;

foreach (@ARGV) {
	if (-f $_) {
		push(@files, $_);
	}
	elsif ( /^-$/ ) {
		$pipe = 1;
	}
	elsif (/^--sort=(flows|packets|octets|bytes)$/) {
		if (($1 eq 'octets') || ($1 eq 'bytes')) { $sortBy = $D_BYTES; }
		elsif ($1 eq 'flows') { $sortBy = $D_FLOWS; }
		elsif ($1 eq 'packets') { $sortBy = $D_PKTS; }
	}
	elsif (/^--full$/) {
		$simple = 0;
	}
}

our $exporters = {};

if (@files) {
	our @cacheFiles;
	foreach (@files) { push(@cacheFiles, &doFile($_)); }

	$exporters = {};
	&globCacheFiles(@cacheFiles);
}

if ($pipe) {
	Cflow::find(\&wanted, \&perfile, "-");
}

&dump(*STDOUT, $simple);

exit;

sub dump
{
	my $fh = shift;
	my $simple = shift;			# simple output

	if ($simple) {
		print $fh "# recn: exaddr,flows,octets,packets,first,last,timespan,rx-only,tx-only\n";
	}
	else {
		print $fh "# recn: exaddr,interface,direction,flows,octets,packets,first,last\n";
	}

	my @keys;
	if (defined $sortBy) {	@keys = sort { $exporters->{$b}->[$sortBy] <=> $exporters->{$a}->[$sortBy] } keys %$exporters;	}
	else {			@keys = sort byPaddedNum keys %$exporters;							}

	foreach (@keys) {
		my $exp = $exporters->{$_};

		if ($simple) {
			my (@rxonly, @txonly);

			foreach my $ifIndex (sort {$a <=> $b} keys %{$exp->[$D_INTERFACE]}) {
				my $if = $exp->[$D_INTERFACE]->{$ifIndex};
				push(@rxonly, $ifIndex) if (ref($if->[$DIR_TX]) ne "ARRAY");
				push(@txonly, $ifIndex) if (ref($if->[$DIR_RX]) ne "ARRAY");
			}

			print $fh join(",",
				$_, $exp->[$D_FLOWS], $exp->[$D_BYTES], $exp->[$D_PKTS],
				$exp->[$D_STARTIME], $exp->[$D_ENDTIME], $exp->[$D_ENDTIME] - $exp->[$D_STARTIME],
				join(' ', @rxonly),
				join(' ', @txonly)
			) . "\n";
		}
		else {
			print $fh join(",",
				$_, undef, $DIR_EX, $exp->[$D_FLOWS], $exp->[$D_BYTES], $exp->[$D_PKTS],
				$exp->[$D_STARTIME], $exp->[$D_ENDTIME]) . "\n";

			foreach my $ifIndex (keys %{$exp->[$D_INTERFACE]}) {
				my $if = $exp->[$D_INTERFACE]->{$ifIndex};

				my $ifx = $if->[$DIR_TX];
				if (ref($ifx) eq "ARRAY") {
					print $fh join(",",
						$_, $ifIndex, $DIR_TX, $ifx->[$D_FLOWS], $ifx->[$D_BYTES], $ifx->[$D_PKTS],
						undef, undef) . "\n";
				}
				my $ifx = $if->[$DIR_RX];
				if (ref($ifx) eq "ARRAY") {
					print $fh join(",",
						$_, $ifIndex, $DIR_RX, $ifx->[$D_FLOWS], $ifx->[$D_BYTES], $ifx->[$D_PKTS],
						undef, undef) . "\n";
				}
			}
		}
	}
}

sub globCacheFiles
{
	my $if;

	foreach (@_) {
		open(IN, $_);
		while ( <IN> ) {
			chomp;
			next if (/^#/);
			my ($exporterip,$if,$direction,$flows,$bytes,$pkts,$startime,$endtime) = split(/,/);

			if (! ($exp = $exporters->{$exporterip}) ) {
				$exp = $exporters->{$exporterip} = [];
				$exp->[$D_STARTIME] = $startime;
				$exp->[$D_ENDTIME] = $endtime;
				$exp->[$D_INTERFACE] = {};
			}

			if ($direction == $DIR_EX) {
				$exp->[$D_STARTIME] = $startime if ($startime < $exp->[$D_STARTIME]);
				$exp->[$D_ENDTIME]= $endtime if ($endtime > $exp->[$D_ENDTIME]);
				$exp->[$D_FLOWS] += $flows;
				$exp->[$D_BYTES] += $bytes;
				$exp->[$D_PKTS] += $pkts;
			}
			elsif (($direction == $DIR_TX) || ($direction == $DIR_RX)) {
				$exp->[$D_INTERFACE]->{$if}->[$direction]->[$D_FLOWS] += $flows;
				$exp->[$D_INTERFACE]->{$if}->[$direction]->[$D_BYTES] += $bytes;
				$exp->[$D_INTERFACE]->{$if}->[$direction]->[$D_PKTS] += $pkts;
			}
		}
	}
}

sub doFile
{
	my $file = shift;

	return if ($file !~ /^(.*?\/?)(ft|tmp)([^\/]+)$/);
	my $cacheFile = "$1summary-ft$3";

	print STDERR "working file=$file   cacheFile=$cacheFile\n";

	if (! -f $cacheFile) {
		$exporters = {};
		Cflow::find(\&wanted, \&perfile, $file);
		open(OUT, ">$cacheFile");
		&dump(*OUT);
		close(OUT);
	}
	return $cacheFile;
}

sub wanted
{
	if (! ($exp = $exporters->{$exporterip}) ) {
		$exp = $exporters->{$exporterip} = [];
		$exp->[$D_STARTIME] = $startime;
		$exp->[$D_ENDTIME] = $endtime;
		$exp->[$D_INTERFACE] = {};
	}
	else {
		$exp->[$D_STARTIME] = $startime if ($startime < $exp->[$D_STARTIME]);
		$exp->[$D_ENDTIME]= $endtime if ($endtime > $exp->[$D_ENDTIME]);
	}

	$exp->[$D_FLOWS] ++;
	$exp->[$D_BYTES] += $bytes;
	$exp->[$D_PKTS] += $pkts;
	$exp->[$D_INTERFACE]->{$input_if}->[$DIR_RX]->[$D_FLOWS] ++;
	$exp->[$D_INTERFACE]->{$input_if}->[$DIR_RX]->[$D_BYTES] += $bytes;
	$exp->[$D_INTERFACE]->{$input_if}->[$DIR_RX]->[$D_PKTS] += $pkts;
	$exp->[$D_INTERFACE]->{$output_if}->[$DIR_TX]->[$D_FLOWS] ++;
	$exp->[$D_INTERFACE]->{$output_if}->[$DIR_TX]->[$D_BYTES] += $bytes;
	$exp->[$D_INTERFACE]->{$output_if}->[$DIR_TX]->[$D_PKTS] += $pkts;
}

sub perfile
{
#	print STDERR "$0 reading " . (shift @_) . "\n";
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

