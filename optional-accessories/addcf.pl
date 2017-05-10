#!/usr/bin/perl

# takes an RRD file and adds an 'AVERAGE' CF for every 'MAX' CF that
# exists, complete with NaN data.

# if migrating from webview v1.02 to later, you should convert all your
# rrd data files using a command like this:
#
# find /var/log/webview/flows/data -name '*.rrd' -exec ./addcf.pl {} \;

use strict;

my $fname = shift @ARGV;
my $tmp = "/tmp/cf-$$.tmp";
my ($tab, $acc);

open(OUT, ">$tmp") || die "err $!";
open(IN, "rrdtool dump $fname |") || die "err $!";

while ( <IN> ) {
	print OUT $_;
	$acc .= $_ if ($tab);

	if ( /<rra>/ ) {
		$tab = 1;
		$acc .= $_;
	}
	elsif (/<\/rra>/) {
		$tab = 0;

		if ($acc =~ / AVERAGE /) {
			print "skipped : $fname\n";
			exit 1;
		}

		$acc =~ s/ MAX / AVERAGE /;
		$acc =~ s/(<value>)\s*\S+\s*(<\/value>)/$1 NaN $2/g;
		$acc =~ s/(<unknown_datapoints>)\s*\S+\s*(<\/unknown_datapoints>)/$1 0 $2/g;
		$acc =~ s/(<v>)\s*\S+\s*(<\/v>)/$1 NaN $2/g;
		print OUT $acc;

		undef $acc;
	}
}
close(IN);
close(OUT);

`mv $fname $fname.bak`;

# unlink($fname);
`rrdtool restore $tmp $fname`;

unlink($tmp) || die "unlink $tmp failed: $!";

print "complete: $fname\n";
exit 0;

