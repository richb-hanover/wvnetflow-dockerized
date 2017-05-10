#!/usr/bin/perl

# looks through a few random flow files from the previous 24 hour period, collecting subnet info
# these subnets are written to the 'subnets' table of MySQL.
# run this once a day.

use DBI;
use Cflow qw(:flowvars find);
use strict;

$| = 1;

my $flowDir = "/var/log/webview/flows/capture";
my $flowCounter = 0;
my $start = time;
my $randCutoff = 0.25;

my $dbh = DBI->connect("DBI:mysql:database=netflow:host=localhost")
        || die "DBI->connect: " . $DBI::errstr;

my (%subnetHash, @subnetMasks, @flowFiles);

for (my $mask=0; $mask<=32; $mask++) {
	$subnetMasks[$mask] = ( ($mask) ? (0xffffffff << (32-$mask)) : 0 );
}

my $cutoff = time - 86400 * 8;

opendir(DIR, $flowDir);
while ($_ = readdir(DIR)) {
	next if (! /^ft-/);
	push(@flowFiles, "$flowDir/$_") if ( ((stat("$flowDir/$_"))[9] >= $cutoff) && ((rand() < $randCutoff) || ! @flowFiles) );
}
closedir(DIR);

die "No recent files in $flowDir" if (! @flowFiles);


Cflow::find(\&wanted, \&perfile, @flowFiles);

&dbSubnets;

my $dur = (time - $start) || 1;
my $fps = int($flowCounter / $dur);

print "$flowCounter flows read in $dur seconds ($fps fps)\n";

$dbh->disconnect();

exit 0;

# -----------------------------------------------------------------

sub dbSubnets
{
	my(@db_update);

	foreach my $exporter (sort keys %subnetHash) {
		foreach my $ifIndex (sort { $a <=> $b } keys %{$subnetHash{$exporter}}) {
			my $hp = $subnetHash{$exporter}->{$ifIndex};

			foreach (sort { $hp->{$b} <=> $hp->{$a} } keys %$hp) {
				my($subnet, $mask) = split(/$;/);
				push(@db_update, "(" . join(",", $exporter, $ifIndex, $dbh->quote(&IP($subnet) . "/" . $mask), 
					$hp->{$_}) . ")");
			}
		}
	}

	$dbh->do("DELETE FROM subnets") || die "DBI->do(DELETE): " . $DBI::errstr;

	$dbh->do("REPLACE INTO subnets VALUES " . join(", ", @db_update)) ||
		die "DBI->do(REPLACE): " . $DBI::errstr;

	print scalar @db_update, " updates sent to database\n";
}

sub wanted
{
	$flowCounter++;
	$subnetHash{$exporter}->{$output_if}->{$dstaddr & $subnetMasks[$dst_mask],$dst_mask} += $bytes;
}

sub perfile
{
	if (! -f $_[0]) { print "unable to read: ", $_[0], "\n"; }
	else { print "reading: ", $_[0], "\n"; }
}

sub IP
{
	sprintf("%d.%d.%d.%d", $_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
}

