#!/usr/bin/perl

use CGI qw(:standard :html3 -nosticky);
use DBI;
use strict;

$| = 1;

my $title = 'NetFlow-derived Route Info';

my %queries = (
	'All routes' => 'all',
	'WAN routes' => 'wan',
	'Duplicate routes' => 'dup'
);

my $debug = 0;
my $LOG_DEBUG = 0;
my $LOG_ERROR = 1;

my %subnet_query = (
	'dup' => <<EOT,
SELECT subnet
	FROM subnets LEFT JOIN interfaces USING (exporter, ifIndex)
	WHERE (ifDescr LIKE 'HSSI%' OR ifDescr LIKE 'Serial%' OR ifDescr LIKE 'ATM%') AND (ifAlias NOT LIKE 'MAN subnet%') AND (subnet <> '0.0.0.0/0')
	GROUP BY subnet
	HAVING count(*) > 1
EOT
);

my $total_query = 
	'SELECT subnet, SUM(bytes) AS bytes FROM subnets GROUP BY subnet;';

my %data_query = (
	'all' => <<EOT,
  SELECT subnet, exporterName, ifDescr, ifAlias, ifSpeed, bytes
	FROM subnets LEFT JOIN interfaces USING (exporter, ifIndex)
	ORDER by subnet, bytes DESC
EOT

	'wan' => <<EOT,
  SELECT subnet, exporterName, ifDescr, ifAlias, ifSpeed, bytes
	FROM subnets LEFT JOIN interfaces USING (exporter, ifIndex)
	WHERE (ifDescr LIKE 'HSSI%' OR ifDescr LIKE 'Serial%' OR ifDescr LIKE 'ATM%') AND (ifAlias NOT LIKE 'MAN subnet%')
	ORDER by subnet, bytes DESC
EOT

	'dup' => <<EOT,
  SELECT subnet, exporterName, ifDescr, ifAlias, ifSpeed, bytes
	FROM subnets LEFT JOIN interfaces USING (exporter, ifIndex)
	WHERE (ifDescr LIKE 'HSSI%' OR ifDescr LIKE 'Serial%' OR ifDescr LIKE 'ATM%') AND (ifAlias NOT LIKE 'MAN subnet%')
	AND (%SUBNET%)
	ORDER by subnet, bytes DESC
EOT
);

&main;
exit 0;

sub main
{
	print header(), start_html(-title=>$title),
		h2($title),
		start_form(),
		(map { submit(-name=>'go', -value=>$_) } keys %queries),
		end_form(),
		br;

	my $go = $queries{param('go')} || return;

	my $dbh = DBI->connect("DBI:mysql:database=netflow:host=localhost", 'root')
		|| do {
		print b("DBI->connect: " . $DBI::errstr);
		exit 0;
	};

	my ($sq, $dq) = ($subnet_query{$go}, $data_query{$go});

	if (! $dq) {
		&logit($LOG_ERROR, "No query defined for '$go'");
		return;
	}

	my %byteTotals;

	foreach (&dbSimpleQuery($dbh, $total_query)) {
		$byteTotals{$_->[0]} = $_->[1];
	}

	my @subnets = &dbSimpleQuery($dbh, $sq) if ($sq);
	$dq =~ s/%SUBNET%/"(" . join(" || ", map { 'subnet=' . $dbh->quote($_) } @subnets) . ")"/e;

	my $sth = $dbh->prepare($dq) || &logit($LOG_ERROR, "DBI prepare cmd '$dq': " . $dbh->errstr);
	$sth->execute || &logit($LOG_ERROR, "DBI execute cmd '$dq': " . $dbh->errstr);

	print "<table border=1 style='font-size: 10; font-family: sans-serif'><tr>", (map { th($_) } @{$sth->{NAME}}), "\n";

	my $lastSubnet;
	my $subnetCount = 0;

	my $COL_BYTES = 5;
	my $COL_SUBNET = 0;

	while (my $ref = $sth->fetchrow_arrayref) {

		my $total = $byteTotals{$ref->[$COL_SUBNET]};

		if ($total) {
			my $perc = 100 * $ref->[$COL_BYTES] / $byteTotals{$ref->[$COL_SUBNET]};
			$ref->[$COL_BYTES] = (($perc >= 0.01) ?  sprintf("%.02f%%", $perc) : "trace");
		}
		else {
			$ref->[$COL_BYTES] = "Unknown";
		}

		$subnetCount++ if ($lastSubnet ne $ref->[0]);
		$lastSubnet = $ref->[0];
		print "<tr", (($subnetCount % 2) ? "" : " bgcolor='#E0E0E0'"), ">", (map { td($_) } @$ref), "\n";
	}
	print "</table>";

	$dbh->disconnect();
}

# -----------------------------------------------------------------

sub IP
{
	sprintf("%d.%d.%d.%d", $_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
}

sub logit
{
	print h2($_[1]), "\n";
}

# -----------------------------------------------
# Perform a simple DB query.

sub dbSimpleQuery
{
	my($DBH, $cmd) = @_;
	my @rows;

	my $sth = $DBH->prepare($cmd) || do {
		&logit($LOG_ERROR, "dbSimpleQuery prepare cmd '$cmd': " . $DBH->errstr);
		return undef;
	};

	$sth->execute() or do {
		&logit($LOG_ERROR, "dbSimpleQuery execute cmd '$cmd': " . $DBH->errstr);
		return undef;
	};

	while (my @row = $sth->fetchrow_array) {
		if (@row == 1) { push(@rows, $row[0]); }		# only one column, return it
		else { push(@rows, \@row); }					# multiple columns, return pointer to array
	}

	$sth->finish || do {
		&logit($LOG_ERROR, "dbSimpleQuery finish cmd '$cmd': " . $DBH->errstr);
	};

	if (wantarray) {			# return all rows
		&logit($LOG_DEBUG, "dbSimpleQuery cmd '$cmd' returned " . (scalar @rows) . " rows")
			if ($debug);

		return @rows;
	}
	else {					  # else return the first element of the first row
		my $v = ( (ref($rows[0])) ? $rows[0]->[0] : $rows[0] );

		&logit($LOG_DEBUG, "dbSimpleQuery cmd '$cmd' returned value '" . $v . "'")
			if ($debug);

		return $v;
	}
}

