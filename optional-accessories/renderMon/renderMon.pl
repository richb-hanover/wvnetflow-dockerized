#!/usr/bin/perl

# version history
#
# v1.0            initial version
# v1.01 06-24-03  fixed order of avg/max
# v1.02 07-18-03  changed INSERT to REPLACE
# v1.03 09-23-03  strip whitespace on returned fields
# v1.04 10-03-03  added support for goofy 'Aggregate' category
# v1.05 10-13-03  now updates the 'aliases' table
# v1.06 10-24-03  added 'core' variable in updates, changed table to 'netusage'
# v1.07 10-27-03  perform site updates only by office number, not site name
# v1.08 11-24-03  added %OPT_core_sources differentiation
# v1.09 01-19-04  added transport/corp config files and fixed timezone calculations

our $pkgName = 'renderMon';
our $pkgVer = '1.07';

use POSIX;
use DBI;
use LWP::UserAgent;
use HTTP::Request::Common;
use Time::Local;

# ---------------------------------------------------------------
# defined constants

our $debug = 0;

our $baseDbiConnector = "DBI:mysql:database=netflow:host=localhost";
our $baseDbiTable = "netusage";
our $baseDbiUsername = "root";
our $baseDbiPassword = undef;
our $baseDbiRowsAtOnce = 1000;		# do 1000 datapoint insertions at a time

# load config files
our (@configTransports, @configCores);
our $core_file = "/usr/local/webview/flowage/renderMon/render-core.txt";
our $transport_file = "/usr/local/webview/flowage/renderMon/render-transport.txt";

push(@configTransports, &readSubFile($transport_file));
push(@configCores, &readSubFile($core_file));

# generate time zone info
our $localStart = 7;
our $localTimeZone = 'ET';
our %startTimeByTimeZone;

&loadTimeZones;

my %fileVars = (
	'Apps' => 'Applications',
	'Aggregate' => 'Aggregate'
);

my $keyVariable = 'Interfaces';
my %vars;

my %months = (
	'Jan' => '01',  'Feb' => '02',  'Mar' => '03',  'Apr' => '04',
	'May' => '05',  'Jun' => '06',  'Jul' => '07',  'Aug' => '08',
	'Sep' => '09',  'Oct' => '10',  'Nov' => '11',  'Dec' => '12'
);

# ---------------------------------------------------------------
# process command-line arguments

my $OPT_file = shift @ARGV;
my $OPT_dp = shift @ARGV;

my $hostname;
if ($ARGV[0] =~ /[a-z]/) { $hostname = shift @ARGV; }
else { chomp( $hostname = `hostname`); }

my $OPT_iterations = shift @ARGV || 1;

my $OPT_start_time = 7;			# unused
my $OPT_duration = '9-Hour';
my $OPT_period = 'Days';
my $OPT_round = 86400;
my $OPT_aggregate = ($OPT_file =~ /aggregate/i);
my ($OPT_core, $OPT_transport, $OPT_url, %OPT_core_sources);

my $logFile = "/logs/webview/rrds/renderMon-" . $OPT_file . "-" . $hostname . ".log";

if (
	(! defined $fileVars{$OPT_file}) ||				# file
	($OPT_dp !~ /^(Bits|Packets|Flows)$/) ||			# datapoint
	(! $OPT_iterations) ||						# iteration
	($OPT_duration !~ /^(\d+\-Hour|Day|Week|Month|Year)$/) ||	# duration
	($OPT_period !~ /^(Hours|Days|Weeks)$/)				# period
) {
	print <<EOT;
$pkgName $pkgVer

The script makes automated queries to the Berbee WebView Render front
end and populates the tabular results in a mysql database.

usage:  $pkgName <file> <datapoint> [hostname] [iterations]

 <file>	       'Summary' or 'Detail'
 <datapoint>   'Bits', 'Packets', or 'Flows'
 [hostname]    hostname of this server; controls data source and tagging (default is '$hostname')
 [iterations]  number of days (default is '1')

All values must be specified. Case is probably important.
EOT
	exit 0;
}


if ($hostname =~ /nsx401l6460/) { 		# webview
	$OPT_url = "http://netview.bcbsm.com/netflow/render.cgi";
}
else {
	print <<EOT;
$pkgName $pkgVer

Error: hostname '$hostname' is not recognized in this code. Please edit
the script file ($0) and define contents for this hostname.

EOT
	exit 0;
}

# ------------------------------------------------------------
# do main processing

my $DBH = DBI->connect($baseDbiConnector, $baseDbiUsername);	# , $baseDbiPassword);

if (! $DBH) {
	&logit("DBI->connect: " . $DBI::errstr);
	exit 1;
}

&logit("DBI->connect: okay");

&gatherKeyVariables(\%vars);
&updateAliasesTable($DBH, \%vars);

foreach (keys %vars) {
	&runCoreTransportReports($DBH, $vars{$_}, $_);
}

&logit("Disconnecting from database");
if (! $DBH->disconnect()) {
	&logit("DBI->disconnect: " . $DBI::errstr);
	exit 1;
}
else {
	&logit("DBI->disconnect: okay");
}

exit 0;


sub logit
{

	if (-s $logFile > 100_000_000) {		# rotate log file
		`mv $logFile $logFile.bak`;
	}

	open(LOG, ">>" . $logFile);
	print LOG scalar localtime(), " ", $_[0], "\n";
	close(LOG);
}

# ------------------------------------------------------------
sub updateAliasesTable
{
	my ($DBH, $vars) = @_;
	my (@db_update);

	foreach (keys %$vars) {
		my $alias = $vars{$_};
		s/^\+//;
		s/\+$//;
		$alias =~ s/^\s+//;
		$alias =~ s/\s+$//;

		foreach (split(/,/)) {
			my ($rtr, $if) = split(/#/);
			my (@answer) = &dbSimpleQuery($DBH, "SELECT exporter,ifIndex FROM interfaces WHERE exporterName='$rtr' AND ifDescr='$if';");
			my $exporter = $answer[0]->[0];
			my $ifIndex = $answer[0]->[1];

			push(@db_update, "(" . join(",", $DBH->quote($alias), $exporter, $ifIndex) . ")") if ($exporter);
		}
	}

	if (@db_update) {
		if (! $DBH->do("DELETE FROM aliases")) {
			&logit($logmsg . $DBI::errstr);
			return;
		}

		if (! $DBH->do("REPLACE INTO aliases VALUES " . join(", ", @db_update))) {
			&logit($logmsg . $DBI::errstr);
			return;
		}
	}

# +0055-WRTR-09#Hssi8/0/0.318+ ->  WAN Newark, DE (318)
# +0055-WRTR-13#Hssi1/0.260+ ->  WAN Happy Valley, OR (DC1D)
# +0055-WRTR-05#Serial3/0:0,0055-WRTR-17#Serial3/0:0+ ->  WAN Unionville, ON (776)
}

# ------------------------------------------------------------
sub runCoreTransportReports
{
	my($DBH, $alias, $item) = @_;
	my(%icore);

	$alias =~ s/^\s+//;
	$alias =~ s/\s+$//;

	my(@items) = split(/\s*,\s*/, $1) if ($item =~ /^\+(.*)\+/);

	# given an alias, break it up into the various defined core sources. We will generate
	# these separately.

	foreach my $i (@items) {
		my $core = &hackConfig($i, \@configCores);
		my $transport = &hackConfig($i, \@configTransports);

		push(@{$icore{$core,$transport}}, $i);
	}

	foreach (keys %icore) {
		($OPT_core, $OPT_transport) = split(/$;/);
		$item = '+' . join(',', @{$icore{$_}}) . '+';

		&runReport($DBH, $alias, $item);
	}
}

sub runReport
{
	my($DBH, $alias, $item) = @_;
	my $office;

	$office = $alias;

#	if ($alias =~ /\((\w{2,4})\)/) {
#		$office = uc(substr("0000" . $1, -4));
#	}
#	elsif ($alias =~ /LAN core/i) {
#		$office = 'LANC';
#	}
#	else {
#		if (! $skipped{$alias}++) {
#			&logit("Skipping alias $alias (no office ID)");
#		}
#		return;
#	}

	my $ua = LWP::UserAgent->new;
	my $localWhen = $startTimeByTimeZone{&hackTZ($DBH, $office) || $localTimeZone};

	my $OPT_date = strftime("%m-%d-%Y", localtime($localWhen));
	my $OPT_time = strftime("%I%p", localtime($localWhen));

	&logit("office=$office, item=$item, core=$OPT_core, transport=$OPT_transport");
	&logit(join(" ", $OPT_date, $OPT_time, scalar localtime($localWhen), $vars{$item}));

# +085A-WRTR-13#Hssi3/0.87+

	my $res = $ua->request(
		POST $OPT_url,
		[
			'file' => $OPT_file,
			'go' => 'Table',

			'date' => $OPT_date,
			'time' => $OPT_time,
			'trimEmpty' => 'off',
			'io' => 'distinct',
			'style' => 'stack',

			'output' => 'simple',

			'dp' => $OPT_dp,
			'dur' => $OPT_duration,
			'iterations' => $OPT_iterations,
			'period' => $OPT_period,

			'v' . $keyVariable => (($OPT_aggregate) ? 'graph' : 'separate'),
			's' . $keyVariable => $item,

			# the following are unused for aggregate data

			'v' . $fileVars{$OPT_file} => 'graph',
			's' . $fileVars{$OPT_file} => 'all'
		]
	);

	my $table = $res->as_string;

#	&logit($table);

	$table =~ s/^.*?\<table[^\>]*\>//is;		# trim before table
	$table =~ s/\<\/table[^\>]*\>.*//is;		# trim after table
	$table =~ s/[\n\r]//gs;				# trim newlines

	my @db_update;

	foreach (split(/\<tr[^\>]*\>/i, $table)) {
		my @fields = split(/\s*<td[^\>]*\>\s*/i);		# get rid of trailing/leading space, too
		# including spaces in the variables, if they exist

		if ((@fields != 16) || ($fields[1] !~ /\d{4}$/)) {		# fields[2] is the date field -- ensure it ends in a year
			next;
		}

		my($date, $site, $bw, $app, $maxin, $maxout, $avgin, $avgout) =
			($fields[1], $fields[3], $fields[5], $fields[7], $fields[9], $fields[11], $fields[13], $fields[15]);

		if ($OPT_aggregate) {
			$site = $app;
			$app = $OPT_file;
		}

		# note that the order of max/avg values is switched when going from render to the database...

		push(@db_update, "(" . join(",",
			$DBH->quote($OPT_core),				# core variable
			$DBH->quote($OPT_transport),			# transport variable
			$DBH->quote($OPT_file),				# file
			$DBH->quote($office),				# office number (from $alias)
			$bw,						# bandwidth
			$DBH->quote(&hackDate($date)),			# date
			$DBH->quote($app),				# app
			$avgin,						# avg in
			$avgout,					# avg out
			$maxin,						# max in
			$maxout) . ")");				# max out
	}

	my $logmsg = "DBI->do REPLACE " . (scalar @db_update) . " rows: ";

	while (@db_update) {
		my @localUpdate = splice(@db_update, 0, $baseDbiRowsAtOnce);

		foreach (@localUpdate) { &logit($_); }

		if (! $DBH->do("REPLACE INTO $baseDbiTable VALUES " . join(", ", @localUpdate) ) ) {
			&logit($logmsg . $DBI::errstr);
			return;
		}
	}

	&logit($logmsg . "okay");
}

sub hackDate
{
	# Tue Apr 15 20:16:46 2003  ->  2003-04-15 20:16:46

	if ($_[0] =~ /^\S+ (\S+)\s+(\d+)\s+([\d\:]+)\s+(\d+)/) {
		return sprintf("%04d-%02d-%02d %s", $4, $months{$1}, $2, $3);
	}
}

sub hackConfig
{
	my($thing, $arrayp) = @_;
	my $result = 'Unknown';

LOOP:	foreach my $descx (@$arrayp) {
		my ($target, @exps) = split(/\t/, $descx);

		foreach (@exps) {
			if ($thing =~ /$_/) {
				$result = $target;
				last LOOP;
			}
		}
	}

	return $result;
}

# ------------------------------------------------------------
sub gatherKeyVariables
{
	my ($vars) = @_;

	my %categories;
	my $ua = LWP::UserAgent->new;

	# --- first, grab the main index
	my $res = $ua->request(
		POST $OPT_url,
		[ 'go' => 'select', 'file' => $OPT_file ]
	);

	if (! &hackSelect('cat' . $keyVariable, \$res->as_string, \%categories)) {
		&logit("file $OPT_file: no options for cat" . $keyVariable . "!\n");
		return;
	}
 
	# --- second, for each 'Aliases' item, repost and grab the keyed variable
	&logit("read " . (scalar keys %categories) . " categories");

	foreach my $cat (keys %categories) {
		next if ($cat !~ /^Aliases/);

		&logit("reading category $cat... ");

		my $res = $ua->request(
			POST $OPT_url,
			[ 'go' => 'select', 'file' => $OPT_file, 'cat' . $keyVariable => $cat ]
		);

		my $count=&hackSelect('s' . $keyVariable, \$res->as_string, $vars);

		&logit("received " . $count . " s" . $keyVariable);
	}
}

# ------------------------------------------------------------
# given a select name, a pointer to an html string, and a pointer to a new hash, fills
# the hash with values;
sub hackSelect
{
	my($selVar, $html, $hash) = @_;

	if ($$html =~ /\<select name=[\"\']?$selVar[^\>]*\>(.*?)\<\/select\>/s) {
		my $opts = $1;
		my $count = 0;

		while ($opts =~ s/\<option\s+value=[\"\']?(.*?)[\"\']?\>(.*?)\<\/option\>(.*)/$3/) {
			$hash->{$1} = $2;
			$count++;
		}
		return $count;
	}

	return undef;
}

sub hackTZ
{
	my($DBH, $office) = @_;

	my $tz = 'ET';
#	my $tz = $DBH->selectrow_array("SELECT timezone FROM offices WHERE office='$office';");
	return $tz;
}

sub loadTimeZones
{
	# convert from database timezone field to something that Linux recognizes
	# (see /usr/share/zoneinfo files and /etc/sysconfig/clock)

	my %TZ_Map = (
		'GMT' => 'GMT',
		'AT' => 'Canada/Atlantic',
		'ET' => 'US/Eastern',
		'CT' => 'US/Central',
		'MT' => 'US/Mountain',
		'PT' => 'US/Pacific',
		'AKT' => 'US/Alaska',

		# funny areas that don't observe daylight savings time
		'EST' => 'US/East-Indiana',
		'MST' => 'US/Arizona',
		'HST' => 'US/Hawaii',

		# if these are used, map them to their DST-observing neighbors
		'CST' => 'US/Central',
		'AKST' => 'US/Alaska',
	);

	# save local timezone
	my $saveTZ = $ENV{'TZ'};

	# compute $delta between localtime and GMT
	my($mday, $mon, $year);
	(undef, undef, undef, $mday, $mon, $year, undef) = localtime(time - 86400);

	# compute Start Time in localtimezone for every timezone's work day
	foreach my $tz (keys %TZ_Map) {
		$ENV{'TZ'} = $TZ_Map{$tz};
		$startTimeByTimeZone{$tz} = timelocal(0,0,$localStart,$mday,$mon,$year);
	}

	# restore local timezone
	if (! defined $saveTZ) { delete $ENV{'TZ'}; }
	else { $ENV{'TZ'} = $saveTZ; }
}

# -----------------------------------------------
# Perform a simple DB query.

sub dbSimpleQuery
{
	my ($DBH, $cmd) = @_;
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

# -----------------------------------------------

$DBINFO = <<EOT;

Allow anonymous access to the netflow table from any host:

  grant select on netflow.* to ''@'%';
  flush privileges;

EOT

# --------------------------------------------------------------------------------
# read in a description/alias file

#	s/%([0-9a-f][0-9a-f])/chr(hex "0x$1")/eg;
#	$foo =~ s/[^A-Z^a-z^0-9^\-^\#]/sprintf("%%%2x",ord($&))/ge;

sub readSubFile
{
	sub q {
		my($foo) = $_[0];
		$foo =~ s/[^A-Z^a-z^0-9^\-^\#]/sprintf("%%%2x",ord($&))/ge;
		return $foo;
	}
	sub uq {
		my($foo) = $_[0];
		$foo =~ s/%([0-9a-f][0-9a-f])/chr(hex "0x$1")/eg;
		return $foo;
	}

	my($fName, $section) = @_;
	my($target, $lastTarget, @stuff);
	my(@targets, %targetCache);

	print "reading $fName\n" if ($debug);
	open(INSUB, $fName);
	while ( <INSUB> ) {
		my($continue, @parts);

		chomp;			# newline
		$continue = (/^\s+/);	# 1=leading spaces, 0=something in column 0

		s/^\s+//;		# leading spaces
		s/\s+$//;		# trailing spaces
		next if (/^[\#\;]/);	# ignore comment lines
		next if (/^$/);		# ignore blank lines

		s/\'([^\']*)\'/&q($1)/ge;		# escape out all single-quote items
		s/\"([^\"]*)\"/&q($1)/ge;		# escape out all double-quote items

		s/\s+[\#\;].*//;	# ignore comments at end of line

		$splitChar = ((/\t/) ? '\t' : '[\s,]');
		foreach (split(/$splitChar+/)) {
			push(@parts, &uq($_));
		}

		# typically files are in TARGET VALUE VALUE VALUE form
		# but some are in VALUE TARGET form
		#	(e.g., a hosts file or an interface description list)

		if ($continue) {			# continue from previous line
			unshift(@parts, $lastTarget);
		}
		elsif (($parts[0] =~ /^[\d\.\/]+$/) || ($parts[0] =~ /#/)) {	# inverted
			@parts = reverse @parts;
		}

		$target = shift @parts;
		foreach (@parts) { push(@{$targetCache{$target}}, $_); }
		push(@targets, $target) if (! $continue);
		$lastTarget = $target;
	}
	close(INSUB);

	foreach $target (@targets) {
		push(@stuff, join("\t",
			$target,
			@{$targetCache{$target}})
		);

		print "target=$target<br>values=" . join(" ", @{$targetCache{$target}}) . "<br>\n" if ($debug);
	}

	return @stuff;
}

