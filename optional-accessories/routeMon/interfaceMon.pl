#!/usr/bin/perl

# copies flowage-learned interface data into the 'interfaces' MySQL table
# run this once a day

use DBI;
use strict;

$| = 1;

my (%exporterName, %ifDescr, %ifAlias, %subnetHash, %subnet2if, @subnetMasks);
my $ifDataDir = '/var/log/webview/flows/tmp';
my $flowCounter = 0;
my $start = time;

my $dbh = DBI->connect("DBI:mysql:database=netflow:host=localhost")
        || die "DBI->connect: " . $DBI::errstr;

&loadIfData;

$dbh->disconnect();

exit 0;

# -----------------------------------------------------------------

sub loadIfData
{
	$dbh->do("DELETE FROM interfaces") ||
	        die "Error deleting existing database: " . $DBI::errstr;

	opendir(DIR, $ifDataDir);
	while ($_ = readdir(DIR)) {
		my($exporter, $exporterName);
		my(@db_update);

		# ifData.172.25.127.33[PECACR1]
		next if (! /^ifData.(\d+)\.(\d+)\.(\d+)\.(\d+)\[([^\]]+)\]$/);

		$exporter = ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;

		open(IN, "$ifDataDir/$_");
		<IN>; <IN>; <IN>;			# timestamps
		chomp($exporterName = <IN>);

		# create 'Local' interface
		push(@db_update, "(" . join(",", $exporter, $dbh->quote($exporterName), 0,
			$dbh->quote("Local"), $dbh->quote(""), 0) . ")");

		my $count = 0;
		while ( <IN> ) {
			chomp;
			my($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);

			push(@db_update, "(" .
				join(",", $exporter, $dbh->quote($exporterName), $ifIndex,
					$dbh->quote($ifDescr), $dbh->quote($ifAlias), $ifSpeed)
				. ")");
			$count++;
		}
		close(IN);

		print "device ", $exporterName, " (", &IP($exporter), ") has $count interfaces\n";

#		print "REPLACE INTO interfaces VALUES " . join(", ", @db_update) . "\n";

		$dbh->do("REPLACE INTO interfaces VALUES " . join(", ", @db_update)) ||
			die "DBI->do: " . $DBI::errstr;
	}
	closedir(DIR);
}

sub IP
{
	sprintf("%d.%d.%d.%d", $_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
}

