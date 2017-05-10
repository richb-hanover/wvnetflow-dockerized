#!/usr/bin/perl

# ---------------------------------------------------------
# Using Webview with ASN labels ...
#
# This script serves three roles:
#
# 1) it composes a config snippet so that flowage.pl can track
#    individual ASNs of interest and summaries (by registrar) of the rest.
#    See the example asn.cfg to see how this snippet can be used.
#
# 2) it creates ./asn-descriptions.txt with ASN descriptions for the
#    config snippet.
#
# 3) it creates /tmp/asns.txt with labels for every ASN. These
#    labels are used by the ad hoc query tool when running ASN reports.
#
# Use this script by following these steps:
#
# 1. Get a copy of http://www.cidr-report.org/as2.0/reserved-ases.html
#    into the current working directory. wget or curl is a handy way to get
#    that file.
#
# 2. Define interesting ASNs in the $asns{$_} hash below.
#
# 3. Define the really interesting ASNs in the $local{$_} hash
#    below. These are treated the same as other ASNs except that they
#    will be displayed first in the graphing engine.
# 
# 4. Run the script   ./asnbuild.pl
#
# 5. Take the output from the line "as-matrix ASN" to the end and embed
#    it into your flowage config file. asn.cfg has an example.
#
# 6. Optionally add an xform statement for your local ASN (which is otherwise
#    reported as 0). See asn.cfg for an example.
#
# You can repeat these steps every time an ASN becomes interesting (and worthy
# of its own graph).
#
# You may also want to edit the www/flow/adhocForm.cgi file and change the
# line "our $SHOW_ASN = 0" to "our $SHOW_ASN = 1". This will enable ASN
# reports in the ad hoc query tool.
#

our $infile = "reserved-ases.html";
our $outfile1 = "asn-descriptions.txt";
our $outfile2 = "/tmp/asns.txt";

our $asns;
our $regs;

# wget http://www.cidr-report.org/as2.0/reserved-ases.html

# DEFINE INTERESTING ASNS HERE:

map { $asns{$_} = 1 } qw/
	174 209 577 701 812 1239 1299 1668 2119 2140 2381 2386 2856
	2914 3215 3269 3301 3352 3356 3491 3549 3561 3599 4134 4181
	4264 4323 4764 4835 4837 5089 5462 5615 5668 5779 6128 6327
	6432 6453 6848 6939 6967 7018 7132 7260 7725 7757 7973 8075
	8151 9038 10796 10879 10912 10994 11139 11260 11393 11426 11427
	11449 11643 11662 11697 11796 12271 13367 13768 14173 14703 14776
	14779 14780 14912 15100 15169 15267 15557 16086 19108 19166 19262
	20094 20115 20214 22384 22773 22822 23352 23393 23430 26910 29748
	31898 32746 32968 33287 33491 33651 33739 33970 36561 36727 36839
	38930 30361 36472 21844 20473 30094 27524 12182 16265 40027 32934
	20940 14960 25973
/;

# DEFINE LOCAL ASNS HERE:

map { $locals{$_} = 1 } qw/
	11796
	14703
	23430
	22066
	20094
/;

# STOP MAKING CHANGES HERE!



open(IN, $infile) || die $!;
open(OUT1, ">$outfile1") || die $!;
open(OUT2, ">$outfile2") || die $!;

print "writing $outfile1 and $outfile2\n";

while ( <IN> ) {
	chomp;
	my ($start, $end, $key);

	if (/^AS(\d+)\s+(.*)/) {
		if (exists $locals{$1}) {
			print OUT1 "$1\t' Local AS$1 $2'\n";
		}
		elsif (exists $asns{$1}) {
			print OUT1 "$1\t'AS$1 $2'\n";
		}
		print OUT2 "$1\t'AS$1 $2'\n";
	}

	elsif (/^(\d+)\-*(\d*)\s+Allocated by (\S+)/) {
		($start, $end, $key) = ($1, $2, $3);
	}
	elsif (/^(\d+)\-*(\d*)\s+(Reserved|AS_TRANS|Designated|Unallocated)/) {
		($start, $end, $key) = ($1, $2, 'Reserved');
	}
	else {
		next;
	}

	if ($end) { 
		print "$start-$end = $key\n";
		map { $regs[$_] = $key; } ($start .. $end);
	}
	else {
		$regs[$start] = $key;
	}
}

foreach (keys %asns) { $regs[$_] = 'skip'; }		 # punch holes for our well-known ASN's

my $start;
my $reg;

$as[65536] = 'hack';
for (my $as = 1; $as <= 65536; $as++ ) {
	if ($as == 64512) {
		for ($as .. $as + (scalar keys %ranges) - 2) { $regs[$_] = 'skip'; }
	}

	next if ($regs[$as] eq $reg);		# still adding to current one

	if ($as > 1) {
		if ($start == ($as - 1)) {
			push( @{$ranges{$reg || 'Reserved'}}, $start );
		}
		else {
			push( @{$ranges{$reg || 'Reserved'}}, $start . '-' . ($as - 1) );
		}
	}

	$reg = $regs[$as];
	$start = $as;
}

print <<EOT;
as-matrix ASN
	#
	# Descriptions of ASN's
	#
	descriptions=asn-descriptions.txt
	aliases=simple
	#
	# List of ASN's we are interested in
	#
EOT
	print "\t" . join(' ', sort {$a <=> $b} keys %asns) . "\n";

print <<EOT;
	#
	# Transformations of other ASN ranges
	#
EOT

my $privas = 64512;
foreach my $reg (sort { @{$ranges{$b}} <=> @{$ranges{$a}} } keys %ranges) {
	next if ($reg eq 'skip');
	print "\t# $reg\n";
	print "\txform=$privas:" . join(',', @{$ranges{$reg}}) . "\n";
	print OUT1 "$privas\t'Summary - $reg'\n";
	$privas++;
}

