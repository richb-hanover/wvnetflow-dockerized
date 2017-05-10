#!/usr/bin/perl

# ipslaMon.cgi
#
# Craig Weinhold (weinhold@berbee.com)
# Berbee Information Networks Corp.
#
# version history
#  v1.0  2003-11-05
#  v1.1  2003-11-11  added text tables and graph grouping
#  v1.11 2003-11-19  added separate graphing/merged tables and fixed site sort
#  v1.12 2003-12-16  added separate packet loss graph
#  v1.20 2004-08-30  significant rewrite and improvement
#  v1.21 2004-11-15  fixed bug in rrd creation
#  v1.22 2005-01-24  tweaked router display to exclude non-echo and jitter probes
#  v1.23 2005-03-10  made a few improvements for releasability
#  v1.24 2005-05-27  streamlined RRDs and incorporated UI improvements from Bob Brunette
#  v1.24a 2005-12-01 patched with sdev debug info
#  v1.24b 2005-12-02 patched with improved snmpCollect diagnostics
#  v1.24c 2005-12-02 bug in snmpCollect
#  v1.25  2005-12-12 previous changes formalized into v1.25
#  v1.26  2006-02-06 code clean-up, tag parts break-out
#  v1.27  2006-11-02 minor posix, css, and terminology cleanup, umask fix
#  v1.28  2008-04-22 renamed saaMon to ipslaMon
#
# This script both collects IP SLA echo and jitter data from routers (defined below) and
# generates a CGI interface to the results in graphic and tabular format.

use CGI qw/:standard delete_all unescape/;
use RRDs;
use SNMP_util;
use Storable;
use POSIX;
use Time::Local;
use Cwd;
use strict;

our $VERSION = 'saMon.cgi 1.27';
our $DEBUG = 0;
our ($LOG_ERROR, $LOG_INFO, $LOG_DEBUG) = (1, 2, 3);

# ----------------------------------------------------------
# DEFAULT VALUES FOR ALL CONFIG VARIABLES
# please don't change these here -- use ipsla.conf

sub defaultConfig
{
	return {
		'directory' => {
			'data' => '/var/ipsla',
			'graph_absolute' => '/var/www/html/graphs',
			'graph_relative' => '/graphs',
			'warnings' => 'on',
		},

		'rrd' => {
			'period' => 60,
			'heartbeat' => 930,
			'fudge' => 10,
			'xff' => 0.5,
			'rows_period' => 2016,
			'rows_hour' => 720,
			'rows_day' => 380,
		},

		'graph' => {
			'data_invalid' => '5000',
			'jitter_combined' => 'yes',
			'jitter_separate' => 'yes',
			'jitter_minmax' => 'no',
			'default_range' => 9 * 3600,
			'tiny_height' => 100,
			'tiny_width' => 320,
			'small_height' => 160,
			'small_width' => 480,
			'medium_height' => 200,
			'medium_width' => 700,
			'large_height' => 400,
			'large_width' => 700,
			'huge_height' => 600,
			'huge_width' => 1000,
			'format' => 'png',
		},

		'color' => {
			'background' => '#ffffff',
			'baseline' => '#ffc040',
			'min' => 'auto',
			'max' => 'auto',
			1 => '#c00000',
			2 => '#f07000',
			3 => '#ffff00',
			4 => '#50a000',
			5 => '#60e0e0',
			6 => '#60a0e0',
			7 => '#0000f0',
			8 => '#f000f0',
		},

		'snmp' => {
			'community' => 'public',
			'timeout' => 3,
			'retries' => 2,
			'backoff' => 1,
			'port' => 161,
			'version' => '2c',
		},

		'timer' => {
			'cache' => 3600,
			'cleanup' => 600,
		},

		'misc' => {
			'cachefile' => 'ipsla.cache',
			'logfile' => 'ipsla.log',
			'loglevel' => $LOG_INFO,
			'logsize' => 1_000_000,
			'loglines' => 1_000,
			'password' => undef,
			'linkname' => 'Webview%20Home',
			'linkurl' => '/',
			'tagregexp' => '^([^\(]*)',
			'tagpartregexp' => '\((.*)\)',
		},

		'router' => {
		},
	};
}

our $config = &defaultConfig;

# ------------------------------------------------------------
# DEFINE GLOBAL CONSTANTS

our @configOrder = ('router', 'directory', 'snmp', 'rrd', 'graph', 'misc', 'timer', 'color' );

our $defaultConfigFileName = 'ipsla.conf';
our $defaultConfigDirectory = '/etc';

# rtt types. All unknown types are ignored

our %rttTypes = (
	1 => 'echo',
	9 => 'jitter'
);

# graph titles (also hardcoded later on, yeech)

our %rttGraphs = (
	'echo' => [
		'Round-Trip time (RTT)'
	],

	'jitter' => [
		'Round-Trip time (RTT)',
		'One-Way Times',
		'Combined Jitter',
		'Source-to-destination Jitter',
		'Destination-to-source Jitter',
		'Packet Loss'
	]
);

# a list of millisecond values used for upper/lower bounding

our @boundValues = ( '10ms', '20ms', '30ms', '40ms', '50ms', '60ms', '70ms', '80ms', '90ms', '100ms',
	'125ms', '150ms', '175ms', '200ms', '250ms', '300ms', '400ms', '500ms', '750ms', '1000ms', '1500ms',
	'2000ms', '2500ms', '3000ms', '4000ms', '5000ms' );

# selectable date ranges for graphing

our %dateRange = (
	3600 * 1 => '1 hour',
	3600 * 4 => '4 hours',
	3600 * 9 => '9 hours',
	86400 => 'day',
	86400 * 7 => 'week',
	86400 * 31 => 'month',
	86400 * 365 => 'year',
);

# color definitions

our $cmajor = '#808080';
our $cminor = '#a0a0a0';
our $ccell = '#c0c0c0';

our $dummyRouter = 'hunkahunka';

# ensure SNMP collected timeticks are integers

$BER::pretty_print_timeticks = 0;

# fill in SNMP OID->name mappings from SAA MIB

&snmpmapOID(qw/
	rttMonCtrlAdminTag			1.3.6.1.4.1.9.9.42.1.2.1.1.3
	rttMonCtrlAdminRttType			1.3.6.1.4.1.9.9.42.1.2.1.1.4
	rttMonCtrlAdminFrequency		1.3.6.1.4.1.9.9.42.1.2.1.1.6
	rttMonCtrlAdminStatus			1.3.6.1.4.1.9.9.42.1.2.1.1.9

	rttMonlatestRttOperCompletionTime	1.3.6.1.4.1.9.9.42.1.2.10.1.1
	rttMonLatestRttOperTime			1.3.6.1.4.1.9.9.42.1.2.10.1.5

	rttMonLatestJitterOperNumOfRTT		1.3.6.1.4.1.9.9.42.1.5.2.1.1 
	rttMonLatestJitterOperRTTSum		1.3.6.1.4.1.9.9.42.1.5.2.1.2 
	rttMonLatestJitterOperRTTSum2		1.3.6.1.4.1.9.9.42.1.5.2.1.3 
	rttMonLatestJitterOperRTTMin		1.3.6.1.4.1.9.9.42.1.5.2.1.4 
	rttMonLatestJitterOperRTTMax		1.3.6.1.4.1.9.9.42.1.5.2.1.5 
	rttMonLatestJitterOperMinOfPositivesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.6 
	rttMonLatestJitterOperMaxOfPositivesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.7 
	rttMonLatestJitterOperNumOfPositivesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.8 
	rttMonLatestJitterOperSumOfPositivesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.9 
	rttMonLatestJitterOperSum2PositivesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.10 
	rttMonLatestJitterOperMinOfNegativesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.11 
	rttMonLatestJitterOperMaxOfNegativesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.12 
	rttMonLatestJitterOperNumOfNegativesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.13 
	rttMonLatestJitterOperSumOfNegativesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.14 
	rttMonLatestJitterOperSum2NegativesSD	1.3.6.1.4.1.9.9.42.1.5.2.1.15 
	rttMonLatestJitterOperMinOfPositivesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.16 
	rttMonLatestJitterOperMaxOfPositivesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.17 
	rttMonLatestJitterOperNumOfPositivesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.18 
	rttMonLatestJitterOperSumOfPositivesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.19 
	rttMonLatestJitterOperSum2PositivesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.20 
	rttMonLatestJitterOperMinOfNegativesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.21 
	rttMonLatestJitterOperMaxOfNegativesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.22 
	rttMonLatestJitterOperNumOfNegativesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.23 
	rttMonLatestJitterOperSumOfNegativesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.24 
	rttMonLatestJitterOperSum2NegativesDS	1.3.6.1.4.1.9.9.42.1.5.2.1.25 
	rttMonLatestJitterOperPacketLossSD	1.3.6.1.4.1.9.9.42.1.5.2.1.26 
	rttMonLatestJitterOperPacketLossDS	1.3.6.1.4.1.9.9.42.1.5.2.1.27 
	rttMonLatestJitterOperPacketOutOfSequence	1.3.6.1.4.1.9.9.42.1.5.2.1.28 
	rttMonLatestJitterOperPacketMIA		1.3.6.1.4.1.9.9.42.1.5.2.1.29 
	rttMonLatestJitterOperPacketLateArrival	1.3.6.1.4.1.9.9.42.1.5.2.1.30 
	rttMonLatestJitterOperSense		1.3.6.1.4.1.9.9.42.1.5.2.1.31 
	rttMonLatestJitterErrorSenseDescription	1.3.6.1.4.1.9.9.42.1.5.2.1.32 
	rttMonLatestJitterOperOWSumSD		1.3.6.1.4.1.9.9.42.1.5.2.1.33 
	rttMonLatestJitterOperOWSum2SD		1.3.6.1.4.1.9.9.42.1.5.2.1.34 
	rttMonLatestJitterOperOWMinSD		1.3.6.1.4.1.9.9.42.1.5.2.1.35 
	rttMonLatestJitterOperOWMaxSD		1.3.6.1.4.1.9.9.42.1.5.2.1.36 
	rttMonLatestJitterOperOWSumDS		1.3.6.1.4.1.9.9.42.1.5.2.1.37 
	rttMonLatestJitterOperOWSum2DS		1.3.6.1.4.1.9.9.42.1.5.2.1.38 
	rttMonLatestJitterOperOWMinDS		1.3.6.1.4.1.9.9.42.1.5.2.1.39 
	rttMonLatestJitterOperOWMaxDS		1.3.6.1.4.1.9.9.42.1.5.2.1.40 
	rttMonLatestJitterOperNumOfOW		1.3.6.1.4.1.9.9.42.1.5.2.1.41 
	rttMonLatestJitterOperMOS		1.3.6.1.4.1.9.9.42.1.5.2.1.42
	rttMonLatestJitterOperICPIF		1.3.6.1.4.1.9.9.42.1.5.2.1.43
	rttMonLatestJitterOperIAJOut		1.3.6.1.4.1.9.9.42.1.5.2.1.44
	rttMonLatestJitterOperIAJIn		1.3.6.1.4.1.9.9.42.1.5.2.1.45
	rttMonLatestJitterOperAvgJitter		1.3.6.1.4.1.9.9.42.1.5.2.1.46
	rttMonLatestJitterOperAvgSDJ		1.3.6.1.4.1.9.9.42.1.5.2.1.47
	rttMonLatestJitterOperAvgDSJ		1.3.6.1.4.1.9.9.42.1.5.2.1.48
	rttMonLatestJitterOperOWAvgSD		1.3.6.1.4.1.9.9.42.1.5.2.1.49
	rttMonLatestJitterOperOWAvgDS		1.3.6.1.4.1.9.9.42.1.5.2.1.50
	rttMonLatestJitterOperNTPState		1.3.6.1.4.1.9.9.42.1.5.2.1.51
	rttMonLatestJitterOperUnSyncRTs		1.3.6.1.4.1.9.9.42.1.5.2.1.52
/);

$SIG{__WARN__} = \&trapper;
$SIG{__DIE__} = \&trapper;

umask 0;					# allow full file permissions for files created by script

# --------------------------------------------------------------
# GLOBAL VARIABLES
# --------------------------------------------------------------
our %counters;
our %routers;

our $configFile;				# actual location of file
our $configUser;				# username to give control to
our $CONFIG_OKAY = 0;				# set to 1 when config file has been loaded
our $MODE = 0;					# set to 'setup', 'daemon', 'poll', or undef
our $WEBUSER = (exists $ENV{'REMOTE_ADDR'});	# 1 if web user, 0 if shell
our $ALTDATA = 0;				# 1 if user has overridden default data/config location
our ($dataDir, $graphDir, $graphDirURL);
our @routers;

# ------------------------------------------------------------
# LOCATE THE CONFIG FILE
# --------------------------------------------------------------

# preprocess command-line

while (@ARGV) {
	$_ = shift @ARGV;

	if (/^--datadir=?(.*)$/) { $config->{'directory'}->{'data'} = $1 || shift @ARGV; $ALTDATA = 1; }
	elsif (/^--graphdir=?(.*)$/) { $config->{'directory'}->{'graph_absolute'} = $1 || shift @ARGV; }
	elsif (/^--graphurl=?(.*)$/) { $config->{'directory'}->{'graph_relative'} = $1 || shift @ARGV; }
	elsif (/^--user=?(.*)$/) { $configUser = $1 || shift @ARGV; }
	elsif (/^--(setup|daemon|poll)$/) { $MODE = $1; }
	elsif ((/^--help$/) || (/^-\?/)) { &helpScreen; exit 0; }
	else { print "Invalid command-line: $_\n"; exit 1; }
}

$configFile = &findConfig($MODE) if (! defined $configFile);

if ( (defined $configFile) && (&loadConfig($config, $configFile)) ) {
	$CONFIG_OKAY = 1;
}

# assign a few global variables from config variables, for convenience

&setGlobals;

sub setGlobals
{
	$dataDir = &config('directory', 'data');
	$graphDir = &config('directory', 'graph_absolute');
	$graphDirURL = &config('directory', 'graph_relative');
	@routers = grep (! /$dummyRouter/, &config('router'));
}

# --------------------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------------------


if ($MODE eq "setup") {		# perform some basic install
	if (! defined $configUser) {
		print <<EOT;
You must set '--user=<username>' to determine file ownership when running
setup. The user will be responsible for background processing (using
cron or daemon mode). You can use the 'root' user, but it is not advised.
EOT
		exit;
	}

	print "config file found at $configFile (using its settings)\n\n" if (defined $configFile);

	$configFile = &config('directory', 'data') . '/' . $defaultConfigFileName;
	&setup($configUser);

	my $whoami = &absolutelyme;

	print <<EOT;
---------------------------
Now add a scheduled job to run 'ipslaMon.cgi --poll' every minute. On un*x,
edit the crontab...
	crontab -u $configUser -e

  and add the line...
	*/1 * * * * $whoami --poll

It is also okay to run ipslaMon in daemon mode. On un*x,
	su - $configUser -c '$whoami --daemon &'

However, it's important that the daemon process be protected from
interruption and that it is started automatically if the server reboots.
EOT

	exit 0;
}

exit 1 if ((! $CONFIG_OKAY) || (! &sanityChecks));

if ($WEBUSER) {			# running from web
	if ( &testWebWrite ) {
		if ( &loadSAAinfo(0) ) {
			&mainCGI;
			&houseKeeping($graphDir);
		}
	}
}
elsif ($MODE eq "poll") {
	if ( &loadSAAinfo(1) ) {
		&pollSAAinfo;
	}
}
elsif ($MODE eq "daemon") {
	my $period = &config('rrd', 'period');
	my $lastConfigTime = (stat($configFile))[9];

	&logit($LOG_INFO, "Daemonic mode started with period $period");

	while ( 1 ) {
		my $now = time;

		# this config loader may need to become a bit smarter (e.g., init with defaults)

		if (! -f $configFile) {
			&logit($LOG_ERROR, "Config file is missing. Continuing to use the \"in-memory\" config.");
		}
		elsif ((stat($configFile))[9] != $lastConfigTime) {
			$lastConfigTime = (stat($configFile))[9];
			&logit($LOG_INFO, "Config file change detected. Reloading...");

			my $newconfig = &defaultConfig;

			if (&loadConfig($newconfig, $configFile)) {
				$config = $newconfig;
				&setGlobals;
			}
			else {
				&logit($LOG_ERROR, "New config contains errors. Continuing to use the \"in-memory\" config.");
			}
		}

		if ( &loadSAAinfo(1) ) {
			&pollSAAinfo;
		}

		my $x = $now + $period - time;
		if ($x < 0) {
			&logit($LOG_ERROR, "'rrd' period ($period secs) is less than the poll time (" . (time - $now) . " sec).");
		}
		else {
			sleep($x);
		}
	}
}
else {
	print "Use '$0 --help' for help\n";
}

exit 0;


# --------------------------------------------------------------

sub setup
{
	my($username) = shift;
	my ($err, $uid, $gid);

	if (defined $username) {
		my @foo = getpwnam($username);
		if (! @foo) {
			print "User '$username' does not exist.\n";
			exit 1;
		}
		$uid = $foo[2];
		$gid = $foo[3];
	}

	print <<EOT;
ipslaMon.cgi setup

          directory data: $dataDir
directory graph_absolute: $graphDir
             config file: $configFile
EOT
	print <<EOT if ($uid);
               ownership: $username (uid $uid, gid $gid)
EOT

	print "\nOkay to initialize? [N]";
	$_ = <STDIN>;
	return if (! /^y/i);

	# --- Create/verify dataDirectory existence

	&createDirectory($dataDir);
	&setOwnership($uid, $gid, $username, $dataDir) if ($uid);
	&setMode(0755, $dataDir);

	# --- Create/verify graphDirectory existence

	&createDirectory($graphDir);
	&setOwnership($uid, $gid, $username, $graphDir) if ($uid);
	&setMode(0777, $graphDir);

	# --- Create/verify config

	if (! $CONFIG_OKAY) {
		# --- Save a default config file
		if (! &saveConfig($config, $configFile)) {
			print "$configFile ... could not be written: $^E\n"; exit 1;
		}
		print "$configFile ... created from scratch with default values\n";
	}
	else {
		print "$configFile ... exists\n";
	}

	&setOwnership($uid, $gid, $username, $configFile) if ($uid);
	&setMode(0666, $configFile);

	# --- Create/verify logfile

	my $logFile = $dataDir . '/' . &config('misc', 'logfile');
	if (! &logit($LOG_ERROR, "setup run from command-line")) {
		print "$logFile ... could not be written: $^E"; exit 1;
	}

	&setOwnership($uid, $gid, $username, $logFile) if ($uid);
	&setMode(0666, $logFile);

	if ($ALTDATA) {
		print <<EOT;

IMPORTANT: You have overridden the default data directory location. For
ipslaMon.cgi to find its config file, you will need to take one of two
steps:

  1) create a symbolic link (un*x machines)
       ln -s $configFile $defaultConfigDirectory/$defaultConfigFileName

  2) edit the script $0 and find the line
        \$defaultConfigDirectory = '$defaultConfigDirectory';

     and change it to
        \$defaultConfigDirectory = '$dataDir';

Once one of these changes have been made, the web interface should be
able to find the config file and run properly.

EOT
	}
}

sub createDirectory
{
	my $dir = shift;

	if (-d $dir) {
		if (-w $dir) { print "$dir ... exists and is writeable.\n"; }
		else { print "$dir ... exists but is unwriteable\n"; exit 1; }
	}
	elsif (! mkdir $dir) { print "$dir ... failed to create: $!\n"; exit 1; }
	else { print "$dir ... created.\n"; }
}

sub setOwnership
{
	my($uid, $gid, $username, $file) = @_;
	my @stat = stat($file);

	if (($uid == $stat[4]) && ($gid == $stat[5])) {
		print "$file ... has proper ownership\n";
	}
	elsif (! chown ($uid, $gid, $file) ) {
		print "$file ... unable to set ownership to $username: $!\n"; exit 1;
	}
	else {
		print "$file ... ownership set to $username (uid $uid)\n";
	}
}

sub setMode
{
	my($mode, $file) = @_;
	my @stat = stat($file);
	my $cmode = $stat[2] & 0777;

	if ($mode == $cmode) {
		printf ("$file ... has proper mode (0%03o)\n", $mode);
	}
	elsif ( ! chmod ($mode, $file) ) {
		printf ("$file ... unable to set mode to 0%03o: $!\n", $mode); exit 1;
	}
	else {
		printf ("$file ... mode set to 0%03o\n", $mode);
	}
}

# --------------------------------------------------------------

sub title
{
	return <<EOT;
$VERSION
Berbee Information Networks Corp, http://www.berbee.com
Q&A to Craig Weinhold, weinhold\@berbee.com

EOT
}

sub helpScreen
{
	print &title,
		<<EOT;

ipslaMon.cgi [OPTION] [COMMAND]...

Options:

 --datadir=DIRECTORY   Absolute path of data directory (chmod 664). Used for
                       rrd, log, and config files.

 --graphdir=DIRECTORY  Absolute path of graph work directory (chmod 666).
                       Should be underneath web server's DocumentRoot.

 --graphurl=RELATIVE   Relative path to graph work directory, for composing
                       URIs.

 --user=USER           Set file ownership to USER.

Commands:

 --poll                Collect IP SLA data once. Use this from a scheduler like
                       cron. The cron frequency should match the 'rrd period'
                       config setting.

                       # crontab entry for ipslaMon with 'rrd period 60'
                       * * * * * /var/www/cgi-bin/ipslaMon.cgi --poll

 --daemon              Collect IP SLA data continuously. The collection interval
                       is determined by 'rrd period' config setting.

 --setup               Attempt to set up ipslaMon.cgi directories and create a
                       default config file.

ipslaMon.cgi is a script used for both backend collection of IP SLA (formerly
SAA or RTR) data from Cisco routers and for frontend viewing of this data from
a web browser. IP SLA is a router technology that measures the response time of
probe traffic across arbitrary network paths. It is good to have a basic idea
of how to configure IP SLA probes before implementing this script. Refer to
http://www.cisco.com/go/ipsla for more information.

Basic script installation steps:
  1. Begin with a machine with a web server and all dependencies (see below)
  2. Copy ipslaMon.cgi to a cgi directory (e.g., /var/www/cgi-bin).
  3. Choose or create a user to run the backend collection.
  4. As root, run 'ipslaMon.cgi --user=<username> --setup' to create directories.
  5. Configure the user with a cron job to run 'ipslaMon.cgi -poll' every minute.
  6. View the script in a browser (e.g., http://myserver/cgi-bin/ipslaMon.cgi)
  7. Use the web interface to configure a few IP SLA source routers.

The web interface is populated from the information learned from the IP SLA
config on the routers. Here is a sample IP SLA probe:

  ip sla 50
   type jitter dest-ipaddr 10.110.248.98 num-packets 5
   tos 0x2E
   tag 0234-Providence, RI (Frame-relay)
   frequency 300
   request-data-size 100

Guidelines for configuring IP SLA for use with ipslaMon.cgi:

  - only echo and jitter probes are supported (at this time).

  - udp jitter probes may collect one-way times, but these are only
    accurate if both devices involved in the probe have local NTP servers
    (e.g., GPS clocks). If NTP is run across a WAN, the one-way times
    will be blank and/or incorrect.

  - rtr 'frequency' should be >= the 'rrd period' of ipslaMon.cgi or else some
    data samples will be missed.

  - the rtr index is persistent. If an index number is reused for a different
    target, the new tag will be used, but the graph will contain old data.

  - 'tag' is used for labeling and grouping sites within the web interface.
    Each tag should be made of a general target name followed by specific
    probe attributes in parenthesis. For example,

      ip sla 50
        tag Madison, WI (via Frame Relay)

      ip sla 51
        tag Madison, WI (via VPN Tunnel)

    The web interface will show a menu with 'Madison, WI', from which a graph
    will show 'via Frame Relay' and 'via VPN Tunnel' as two different colors.

    By creating multiple probes with different attributes and tags, it's easy
    to group the probe results on the same graph (e.g., for different network
    paths, QoS settings, packet sizes, etc).

Dependencies:
  Perl 5.6+  http://www.perl.org or http://activestate.com
  CGI.pm     http://stein.cshl.org/WWW/software/CGI/
  SNMP_util  http://www.switch.ch/misc/leinen/snmp/perl/
  RRDTOOL    http://people.ee.ethz.ch/~oetiker/webtools/rrdtool/
    (be sure to do a 'make site-perl-install')
EOT
}


# --------------------------------------------------------------
# SNMP POLLING ROUTINES
# --------------------------------------------------------------

sub pollSAAinfo
{
	my $now = time;

	if (&config('rrd', 'reset') eq 'yes') {
		&rrdPurge;
		delete $config->{'rrd'}->{'reset'};
		&saveConfig($config, $configFile);
	}

	foreach my $router (@routers) {
		&pollSAArouter($router);
	}

	&logit($LOG_INFO, "Poll took " . (time - $now) . " seconds for routers @routers");
}

sub snmpHost
{
	my($router) = shift;

	my $community = &subconfig('router', $router, 'snmp') || &config('snmp', 'community');
	my $host = &subconfig('router', $router, 'host') || $router;

	my $x = join(":", 
		$community . '@' . $host,
		&config('snmp', 'port', 'timeout', 'retries', 'backoff', 'version')
	);

	return $x;
}

sub logit
{
	my $level = shift;

	return 1 if ($level > &config('misc', 'loglevel'));

	my $fn = $dataDir . '/' . &config('misc', 'logfile');
	open(OUT, ">>$fn") || return 0;
	foreach (@_) {
		print OUT (scalar localtime()) . "  ", $_ . "\n";
	}
	close(OUT);

	if (-s $fn > &config('misc', 'logsize')) {		# rotate log when it gets to a certain point
		open(IN, $fn);
		open(OUT, ">$fn.bak");
		while ( <IN> ) { print OUT $_; }
		close(IN);
		close(OUT);
		unlink($fn);
	}

	return 1;
}

sub trapper
{
	&logit($LOG_ERROR, @_)
}


sub pollSAArouter
{
	my($router) = shift;

	my $snmpHost = &snmpHost($router);

	# --- first, figure out which entries are active

	my $hp = &snmpCollect($snmpHost, 'rttMonCtrlAdminStatus');
	&logit($LOG_DEBUG, "Fetched " . (scalar keys %$hp) . " rttMonCtrlAdminStatus entries from router $router");

	foreach (keys %$hp) {
		if ($routers{$router}->{$_}->{status} != $hp->{$_}) {
			&logit($LOG_INFO, "forcing reload of cache for router $router\n");
			delete $routers{$router};
			&loadSAAinfo(2);
			last;
		}
	}

	# --- second, get the current sysUpTime and the times the SAA probes last finished
	my ($sysUpTime) = &snmpget($snmpHost, "sysUpTime");		# needs to be an array lval

	$hp = &snmpCollect($snmpHost, 'rttMonLatestRttOperTime');
	foreach (keys %$hp) {
		# calculate the real time of the last probe operation
		$routers{$router}->{$_}->{operTime} = int(time - ($sysUpTime - $hp->{$_}) / 100);
	}

	# --- third, figure out how many probes of each type there are
	my %typeHash;
	foreach (keys %$hp) {
		$typeHash{$routers{$router}->{$_}->{type}}++;
	}

	if ($typeHash{1}) {		# we have at least one echo probe

		# --- next, poll the most recent echo response times (rttType == 1)
		my $hp = &snmpCollect($snmpHost,
			'rttMonlatestRttOperCompletionTime'
		);

		foreach (keys %$hp) {
			next if (! $routers{$router}->{$_}->{status});

			if ($routers{$router}->{$_}->{type} == 1) {
				&rrdEchoUp($router, 1, $_, $routers{$router}->{$_}->{operTime}, $hp->{$_});
			}
		}
	}

	if ($typeHash{9}) {		# we have at least one jitter probe

		my $hp = &snmpCollect($snmpHost, qw/
			rttMonLatestJitterOperNumOfRTT
			rttMonLatestJitterOperNumOfOW

			rttMonLatestJitterOperRTTSum
			rttMonLatestJitterOperRTTSum2
			rttMonLatestJitterOperRTTMin
			rttMonLatestJitterOperRTTMax

			rttMonLatestJitterOperOWSumSD
			rttMonLatestJitterOperOWSum2SD
			rttMonLatestJitterOperOWMinSD
			rttMonLatestJitterOperOWMaxSD
			rttMonLatestJitterOperPacketLossSD 

			rttMonLatestJitterOperOWSumDS
			rttMonLatestJitterOperOWSum2DS
			rttMonLatestJitterOperOWMinDS
			rttMonLatestJitterOperOWMaxDS
			rttMonLatestJitterOperPacketLossDS

			rttMonLatestJitterOperNumOfPositivesSD
			rttMonLatestJitterOperSumOfPositivesSD
			rttMonLatestJitterOperSum2PositivesSD

			rttMonLatestJitterOperNumOfNegativesSD
			rttMonLatestJitterOperSumOfNegativesSD
			rttMonLatestJitterOperSum2NegativesSD

			rttMonLatestJitterOperNumOfPositivesDS
			rttMonLatestJitterOperSumOfPositivesDS
			rttMonLatestJitterOperSum2PositivesDS

			rttMonLatestJitterOperNumOfNegativesDS
			rttMonLatestJitterOperSumOfNegativesDS
			rttMonLatestJitterOperSum2NegativesDS
		/ );

		foreach (keys %$hp) {
			next if (! $routers{$router}->{$_}->{status});

			if ($routers{$router}->{$_}->{type} == 9) {
				&rrdJitterUp($router, 9, $_, $routers{$router}->{$_}->{operTime}, @{$hp->{$_}});
			}
		}
	}
}

sub testWebWrite
{
	my $fn = $dataDir . '/' . &config('misc', 'logfile');
	if ( open(OUT, ">>$fn") ) {
		close(OUT);

		if (open(OUT, ">>$configFile")) {
			close(OUT);
			return 1;
		}
	}

	my $err = <<EOT;
Unable to write to config/log files.

This is probably because ipslaMon.cgi was not setup with the --setup option.

To fix, make the log and config files universally writeable:
    chmod 666 $fn
    chmod 666 $configFile
EOT

	&dumperrors( $err);
	return 0;
}

sub loadSAAinfo
{
	my $updateCache = shift;
	my $loadedSomething;

	my $cacheTime = &config('timer', 'cache');
	my $rtrCache = &config('misc', 'cachefile');
	$rtrCache = $dataDir . '/' . $rtrCache if ($rtrCache!~ /^\//);

	if (! $updateCache) {
		my $err;

		if ( ! -f $rtrCache ) {
			$err = <<EOT;
Cache file $rtrCache is missing.

Check that backend polling or daemon mode is set up properly.
EOT
		}
		elsif ( ! -r $rtrCache ) {
			$err = <<EOT;
Cache file $rtrCache is unreadable.

Check that its file permissions are set properly ('chmod 664 $rtrCache').
EOT
		}
		else {
			%routers = %{retrieve($rtrCache)};			# read cache
			return 1;						# return okay (even if empty)
		}

		&dumperrors( $err);
		return 0;
	}

	if ($updateCache != 2) {
		if ( (-r $rtrCache) && ((stat($rtrCache))[9] > time - $cacheTime) ) {	# load cached copy
			%routers = %{retrieve($rtrCache)};
		}
	}

	foreach my $router (@routers) {
		if (! exists $routers{$router}) {
			my $snmpHost = &snmpHost($router);

			my $hp = &snmpCollect($snmpHost,
				'rttMonCtrlAdminStatus',
				'rttMonCtrlAdminTag',
				'rttMonCtrlAdminRttType',
				'rttMonCtrlAdminFrequency'
			);

			foreach (keys %$hp) {
				$routers{$router}->{$_}->{status} =	$hp->{$_}->[0];
				$routers{$router}->{$_}->{tag} =	$hp->{$_}->[1];
				$routers{$router}->{$_}->{type} =	$hp->{$_}->[2];
				$routers{$router}->{$_}->{freq} =	$hp->{$_}->[3];
				&logit($LOG_DEBUG, "router $router, rtr $_, old status " . $routers{$router}->{$_}->{status});
			}

			$routers{$router}->{0} = 1;			# dummy

			&logit($LOG_INFO, "Loaded " . (scalar keys %$hp) . " RTR entries from router $router");
			$loadedSomething = 1;
		}
	}

	if (! @routers) {				# no routers? store some dummyd data so we know the cache works
		$routers{$dummyRouter} = 1;
		$loadedSomething = 1;
		&logit($LOG_DEBUG, "Storing dummy data");
	}

	if (($loadedSomething) && ($updateCache)) {
		if (! store \%routers, $rtrCache) {
			&logit($LOG_ERROR, "Unable to write $rtrCache", $!);
			return 0;
		}
	}

	return 1;
}

sub snmpCollect
{
	my ($snmpHost, @variables) = @_;
	my %results;

	print strftime('%x %X',localtime(time)) . " getting @variables from $snmpHost\n" if ($DEBUG);

	foreach my $v (@variables) {
		foreach ( &snmpwalk($snmpHost, $v) ) {
			next if (! /(.*?)(\d+)\s*\:\s*(.*)/);
			my ($oid, $instance, $desc) = ($1, $2, $3);
			$results{$instance}->{$v} = $desc;
		}
	}

	&logit($LOG_DEBUG, "Results of SNMP collection from '$snmpHost':");

	my @keys = keys %results;
	return undef if (@keys == 0);					# no results

	my %response;

	&logit($LOG_DEBUG, join(",", 'instance', @variables) );

	foreach my $instance (@keys) {

		$response{$instance} = [
			map {
				(exists $results{$instance}->{$_}) ? $results{$instance}->{$_} :
					do { &logit($LOG_ERROR, "$_.$instance not returned by $snmpHost"); undef; }
			} @variables
		];

		&logit($LOG_DEBUG, join(",", $instance, map { (defined $_) ? $_ : '<undef>' } @{$response{$instance}} )  );

		if (@variables == 1) {
			$response{$instance} = $response{$instance}->[0];
		}
	}

	return \%response;
}

# pass this routine a filename and a bunch of DS's .. it takes care of the rest.

sub rrdVerify
{
	my($fName, $tStamp, @ds) = @_;

	if (! -f $fName) {
		my ($xff, $heartbeat, $period) = &config('rrd', 'xff', 'heartbeat', 'period');

		my @rrdcmd = (
			$fName,
			"--start", $tStamp - $heartbeat,
			"--step", $period
		);

		if (my $rows = &config('rrd', 'rows_period')) {
			push(@rrdcmd, "RRA:MIN:$xff:1:$rows");
			push(@rrdcmd, "RRA:AVERAGE:$xff:1:$rows");
			push(@rrdcmd, "RRA:MAX:$xff:1:$rows");
		}

		if (my $rows = &config('rrd', 'rows_hour')) {
			my $steps = int(3600 / $period);
			push(@rrdcmd, "RRA:MIN:$xff:$steps:$rows");
			push(@rrdcmd, "RRA:AVERAGE:$xff:$steps:$rows");
			push(@rrdcmd, "RRA:MAX:$xff:$steps:$rows");
		}

		if (my $rows = &config('rrd', 'rows_day')) {
			my $steps = int(3600 / $period);
			push(@rrdcmd, "RRA:MIN:$xff:$steps:$rows");
			push(@rrdcmd, "RRA:AVERAGE:$xff:$steps:$rows");
			push(@rrdcmd, "RRA:MAX:$xff:$steps:$rows");
		}

		foreach (@ds) {
			s/HEARTBEAT/$heartbeat/;		# replace heartbeat
			push(@rrdcmd, $_);
		}

		&logit($LOG_INFO, "rrdcmd=@rrdcmd") if ($DEBUG);
		RRDs::create(@rrdcmd);

		my $err=RRDs::error;
		if ($err) {
			&logit($LOG_ERROR, $err, "RRDS::create(", (map { "\t$_" } @rrdcmd), ")");
			return 0;
		}
		else {
			&logit($LOG_INFO, "RRDs::create($fName) ... okay");
		}
	}
	else {			# make sure that time has marched forward...
		my $fudge = &config('rrd', 'fudge');
		return 0 if (($tStamp - $fudge) <= RRDs::last($fName));
	}

	return 1;
}

sub rrdPurge
{
	opendir(DIR, $dataDir);
	my @files = grep (/^.+\#.+\-.+.rrd$/, readdir(DIR));
	closedir(DIR);

	if (! @files) {
		&logit($LOG_ERROR, "RRD purge: no files to delete");
		return;
	}

	my $count = 0;

	foreach (@files) {
		if (unlink("$dataDir/$_")) {
			$count++;
		}
		else {
			print "$^E", br;
			&logit($LOG_ERROR, $^E, "while unlinking $dataDir/$_");
		}
	}

	closedir(DIR);

	&logit($LOG_ERROR, "RRD purge: deleted " . (($count != @files) ? "$count of " . (scalar @files) : "all $count") . " RRD files");
}

sub rrdUpdate
{
	my($fName, $tStamp, @v) = @_;

	my $update = join(":", $tStamp, @v);
	&logit($LOG_INFO, "rrdcmd=$fName $update") if ($DEBUG);
	RRDs::update($fName, $update);

	my $err=RRDs::error;
	if ($err) {
		&logit($LOG_ERROR, $err, "RRDS::update(\"$fName\", \"$update\") ... failed");
		return 0;
	}
	else {
		&logit($LOG_DEBUG, "RRDS::update(\"$fName\", \"$update\") ... okay");
		return 1;
	}
}

sub rrdEchoUp
{
	my($router, $type, $rtr, $tStamp, @v) = @_;

	$tStamp = time if (! $tStamp);
	my $fName = "$dataDir/$router\#$rtr-$type.rrd";

	return 0 if (! &rrdVerify($fName, $tStamp, "DS:Milliseconds:GAUGE:HEARTBEAT:U:U") );

	return &rrdUpdate($fName, $tStamp, @v);
}

sub rrdJitterUp
{
	my($router, $type, $rtr, $tStamp, @v) = @_;
	$tStamp = time if (! $tStamp);

	my $fName = "$dataDir/$router\#$rtr-$type.rrd";

	return 0 if (! &rrdVerify($fName, $tStamp,
		"DS:Avg:GAUGE:HEARTBEAT:U:U",		# Avg
		"DS:SDev:GAUGE:HEARTBEAT:U:U",		# SDev
		"DS:Min:GAUGE:HEARTBEAT:U:U",		# Min
		"DS:Max:GAUGE:HEARTBEAT:U:U",		# Max

		"DS:AvgSD:GAUGE:HEARTBEAT:U:U",		# Avg SD
		"DS:SDevSD:GAUGE:HEARTBEAT:U:U",	# SDev SD
		"DS:MinSD:GAUGE:HEARTBEAT:U:U",		# Min SD
		"DS:MaxSD:GAUGE:HEARTBEAT:U:U",		# Max SD
		"DS:LossSD:GAUGE:HEARTBEAT:U:U",	# Loss SD

		"DS:AvgDS:GAUGE:HEARTBEAT:U:U",		# Avg DS
		"DS:SDevDS:GAUGE:HEARTBEAT:U:U",	# SDev DS
		"DS:MinDS:GAUGE:HEARTBEAT:U:U",		# Min DS
		"DS:MaxDS:GAUGE:HEARTBEAT:U:U",		# Max DS
		"DS:LossDS:GAUGE:HEARTBEAT:U:U",	# Loss DS

		"DS:AvgJSD:GAUGE:HEARTBEAT:U:U",	# Avg J combined SD
		"DS:SDevJSD:GAUGE:HEARTBEAT:U:U",	# SDev J combined SD

		"DS:AvgJDS:GAUGE:HEARTBEAT:U:U",	# Avg J combined DS
		"DS:SDevJDS:GAUGE:HEARTBEAT:U:U",	# SDev J combined DS

		"DS:AvgPSD:GAUGE:HEARTBEAT:U:U",	# Avg J positive SD
		"DS:SDevPSD:GAUGE:HEARTBEAT:U:U",	# SDev J positive SD

		"DS:AvgNSD:GAUGE:HEARTBEAT:U:U",	# Avg J negative SD
		"DS:SDevNSD:GAUGE:HEARTBEAT:U:U",	# SDev J negative SD

		"DS:AvgPDS:GAUGE:HEARTBEAT:U:U",	# Avg J negative DS
		"DS:SDevPDS:GAUGE:HEARTBEAT:U:U",	# SDev J negative DS

		"DS:AvgNDS:GAUGE:HEARTBEAT:U:U",	# Avg J negative DS
		"DS:SDevNDS:GAUGE:HEARTBEAT:U:U",	# SDev J negative DS
	) );

	my (
		$countRTT, $countOW,
		$sum_ALL, $sum2_ALL, $min_ALL, $max_ALL,
		$sum_SD, $sum2_SD, $min_SD, $max_SD, $loss_SD,
		$sum_DS, $sum2_DS, $min_DS, $max_DS, $loss_DS,

		$count_PSD, $sum_PSD, $sum2_PSD,
		$count_NSD, $sum_NSD, $sum2_NSD,
		$count_PDS, $sum_PDS, $sum2_PDS,
		$count_NDS, $sum_NDS, $sum2_NDS,

	) = @v;

	sub sdev {
		my ($router, $rtr, $label, $count, $sum, $sum2) = @_;

		if ($count) {
			my $q = ($count * $sum2 - ($sum * $sum)) / ($count * $count);
			return sqrt($q) if ($q >= 0);
			&logit($LOG_ERROR, "Invalid data, router $router, rtr $rtr, tag '" .
				$routers{$router}->{$rtr}->{tag} .
				"', '$label' STDEV: count $count, sum $sum, sum2 $sum2, q $q");
		}
		return 'NaN';
	}
	sub avg {
		my ($count, $sum) = @_;
		return $count ? ($sum / $count) : 'NaN';
	}

	my @nv = (
		avg($countRTT, $sum_ALL),						# AVERAGE
		sdev($router, $rtr, 'RTT', $countRTT, $sum_ALL, $sum2_ALL),		# STDEV
		$min_ALL,								# MIN
		$max_ALL,								# MAX

		avg($countOW, $sum_SD),							# AVERAGE SD
		sdev($router, $rtr, 'OWSD', $countOW, $sum_SD, $sum2_SD),		# STDEV SD
		$min_SD,								# MIN SD
		$max_SD,								# MAX SD
		$loss_SD,								# LOSS SD

		avg($sum_DS, $countOW),							# AVERAGE DS
		sdev($router, $rtr, 'OWDS', $countOW, $sum_DS, $sum2_DS),		# STDEV DS
		$min_DS,								# MIN DS
		$max_DS,								# MAX DS
		$loss_DS,								# LOSS DS

		avg($count_PSD+$count_NSD, $sum_PSD+$sum_NSD),				# AVERAGE COMBINED J SD
		sdev($router, $rtr, 'CSD', $count_PSD+$count_NSD, $sum_PSD+$sum_NSD, $sum2_PSD+$sum2_NSD),	# STDEV COMBINED J SD

		avg($count_PDS+$count_NDS, $sum_PDS+$sum_NDS),				# AVERAGE COMBINED J DS
		sdev($router, $rtr, 'CDS', $count_PDS+$count_NDS, $sum_PDS+$sum_NDS, $sum2_PDS+$sum2_NDS),	# STDEV COMBINED J DS
	
		avg($count_PSD, $sum_PSD),						# AVERAGE POSITIVE J SD
		sdev($router, $rtr, 'PSD', $count_PSD, $sum_PSD, $sum2_PSD),					# STDEV POSITIVE J SD

		avg($count_NSD, $sum_NSD),						# AVERAGE NEGATIVE J SD
		sdev($router, $rtr, 'NSD', $count_NSD, $sum_NSD, $sum2_NSD),					# STDEV NEGATIVE J SD
	
		avg($count_PDS, $sum_PDS),						# AVERAGE POSITIVE J DS
		sdev($router, $rtr, 'PDS', $count_PDS, $sum_PDS, $sum2_PDS),					# STDEV POSITIVE J DS

		avg($count_NDS, $sum_NDS),						# AVERAGE NEGATIVE J DS
		sdev($router, $rtr, 'NDS', $count_NDS, $sum_NDS, $sum2_NDS),					# STDEV NEGATIVE J DS
	);

	my $bogus = &config('graph', 'data_invalid');		# at what point are values considered invalid
	foreach (@nv) {
		if ($_ >= $bogus) {
			&logit($LOG_ERROR, "Invalid sample (>=$bogus): router $router, rtr $rtr, tag '" .
				$routers{$router}->{$rtr}->{tag} .
				"', \@nv=(" .
				join(', ', @nv) . "). Skipped.");
			return;
		}
	}

	return &rrdUpdate($fName, $tStamp, @nv);
}


# --------------------------------------------------------------
# CGI ROUTINES (WEB INTERFACE)
# --------------------------------------------------------------

sub calcGraphs
{
	my $routerHash = \%routers;
	my (%tagTypes, %graphTypes);
	my @graphTypes;

	# compute Tag -> router data
	foreach my $router (@routers) { 				# keys %$routerHash) {
		foreach my $rtr (keys %{$routerHash->{$router}}) {
			next if (! $rtr);
			$tagTypes{$rttTypes{$routerHash->{$router}->{$rtr}->{type}}} = 1;
		}
	}

	foreach (keys %tagTypes) {
		foreach (@{$rttGraphs{$_}}) {
			next if (exists $graphTypes{$_});
			push(@graphTypes, $_);
			$graphTypes{$_} = 1;
		}
	}

	return @graphTypes;
}

sub calcTags
{
	my $routerHash = \%routers;
	my %tags;

	# compute Tag -> router data
	foreach my $router (@routers) { 				# (keys %$routerHash) {
		foreach my $rtr (keys %{$routerHash->{$router}}) {
			next if (! $rtr);

			my $tag = &breakOutTagTitle($router, $rtr) . ' (' . $rttTypes{$routerHash->{$router}->{$rtr}->{type}} . ')';
			push(@{$tags{$tag}}, "$router,$rtr");
		}
	}

	return \%tags;
}

sub calcTagsInverted
{
	my $tags = &calcTags;
	my %rtr;

	foreach my $tag (keys %$tags) {
		foreach (@{$tags->{$tag}}) {
			$rtr{$_} = $tag;
		}
	}

	return \%rtr;
}

sub breakOutTagTitle
{
	my ($router, $rtr) = @_;
	my $re = &config('misc', 'tagregexp');		# || '^([^\(]*)';
	if ($routers{$router}->{$rtr}->{tag} =~ /$re/o) {
		my $title = $1;
		$title =~ s/\s*$//;
		$title =~ s/^\s*//;
		return $title;
	}
}

sub breakOutTagParts
{
	my ($router, $rtr) = @_;
	my $re = &config('misc', 'tagpartregexp');	# || '^([^\(]*)';

	if ($routers{$router}->{$rtr}->{tag} =~ /$re/o) {
		return split(/\s*\;\s*/, $1);
	}
}

sub mainCGI
{
	my $routerHash = \%routers;
	my $title = 'IP Service Level Agreement (IP SLA) Reporter';
	my $tags = &calcTags;

	my $style = <<EOT;
.dinky {
	font-family: sans-serif;
	font-size: 8pt;
}

.nav {
	font-family: sans-serif;
	font-size: 8pt;
	background-color: #f0f0f0;
}

.config {
	font-family: monospace;
	font-size: 10pt;
}
EOT
	print header(), start_html({-style=>{-code=>$style}, -title=>$title}),
		"<span class=dinky>",
		font({-size=>'+2'}, $title), p;

	if (param('edit')) {
		if (my $pwcheck = &config('misc', 'password')) {
			if (crypt(param('password'), $pwcheck) ne $pwcheck) {
				print font({-color=>'red'},
					font({-size=>4}, b('Invalid password')),
					br,
					"If you have forgotten it, you will need to delete the password from $configFile"
				), p;
				Delete('edit');
			}
		}
	}

	if (@routers == 0) {			# new install -- go directly to edit
		print font({-color=>'red', -size=>'+1'}, 'No IP SLA routers have yet been added.'), p;
		&configCGI;
	}
	elsif (param('edit') =~ /Admin|Setup/) {
		&configCGI;
	}
	elsif (param('edit') =~ /Log/) {
		&logCGI;
	}
	elsif (param('edit') =~ /Info/) {
		print pre(&title);
		&navBar("editvar");
	}
	elsif (param('router') && param('rtr')) {	# looking at a specific router/tag combo
		param('go','Graph+Table');
		&graphIt($routerHash, param('router') . "," . param('rtr'));
	}
	elsif (defined param('tag')) {				# looking at a specific tag
		my @parts = param('parts');
		my $partregexp = grep(/^All$/, @parts) ? '' : '^(' . join('|', @parts) . ')$';

		my @tagnums = sort byPaddedNum keys %$tags;
		my @pairs;
		foreach my $pair ( map { @{$tags->{$tagnums[$_]}} } param('tag') ) {
			my ($router, $rtr) = split(/,/, $pair);

			foreach ( &breakOutTagParts($router, $rtr) ) {
				if (/$partregexp/io) { push(@pairs, $pair); last; }
			}
		}

		&graphIt($routerHash, @pairs);
#		&graphIt($routerHash, map { @{$tags->{$tagnums[$_]}} } param('tag'));
	}
	elsif (param('router')) {			# looking at a router, display all probes
		my $router = param('router');
		&navBar("router");

		print font({-size=>5}, $router), p, "<ul>";

		my $count = 0;
		param('router', $router);
		foreach my $rtr (sort {$a <=> $b} keys %{$routerHash->{$router}}) {
			next if ((! $rtr) || ($rtr > 150_000_000) || (! exists $rttTypes{$routerHash->{$router}->{$rtr}->{type}}));

			$count++;
			param('rtr', $rtr);
			param('llimit', '0ms');
			param('size', 'medium');

			print "<li>",
				"rtr: ", b($rtr),
				", type: ", $rttTypes{$routerHash->{$router}->{$rtr}->{type}},
				", frequency: ", $routerHash->{$router}->{$rtr}->{freq},
				", tag: ", b($routerHash->{$router}->{$rtr}->{tag}),
 				"<br>\n",
				"graph period: &nbsp; ";

			foreach (sort {$a <=> $b} keys %dateRange) {
				next if ($_ < 8 * 3600);
				param('range', $_);
				my $link = url(-query=>1, -relative=>1);

				print a({-href=>$link}, $dateRange{$_}), " &nbsp; ";
			}
			print "<p>\n";
		}

		print "</ul>\n";

		if (! $count) {
			print font({-color=>'red', size=>'+1'}, "No IP SLA probes found on this router"), p;
		}
	}
	else {						# display main screen
		my ($sepDefault, @sepValues, %sepLabels);
		$sepDefault = 'sep_target';

		if (@routers == 1) {		# only one source router -- reduce menu complexity
			if (scalar keys %$tags == 1) {
				@sepValues = ('sep_target', 'sep_all');
			}
			else {
				@sepValues = ('sep_none', 'sep_target', 'sep_all');
			}

			%sepLabels = (
					'sep_target' => 'each destination target',
					'sep_all' => 'each destination/probe combination',
					'sep_none' => 'everything',
			);
		}
		else {						# multiple source routers -- increase menu complexity
			@sepValues = ('sep_none', 'sep_target', 'sep_source', 'sep_dp', 'sep_all');

			%sepLabels = (
					'sep_target' => 'each destination target',
					'sep_source' => 'each source router',
					'sep_dp' => 'each source/destination combination',
					'sep_all' => 'each source/destination/probe combination',
					'sep_none' => 'everything',
			);

			$sepDefault = 'sep_target';
		}

		my %sourceRefs;
		foreach (sort @routers) { 			# keys %$routerHash) {
			param('router', $_);
			$sourceRefs{$_} = url(-query=>1, -relative=>1);
		}

		&graphSanityCheck;

		my $bg = '#e0e0e0';

		my $tagCount = 0;
		my %tagLabels = map { $tagCount++, $_ } sort byPaddedNum keys %$tags;

		my @availableGraphTypes = &calcGraphs;

		# ---------------------------
		my (%tagFreq);

		foreach my $router (@routers) {
			foreach my $rtr (keys %{$routerHash->{$router}}) {
				next if (! $rtr);
				foreach (&breakOutTagParts($router, $rtr)) { $tagFreq{uc($_)}++; }
			}
		}
		# ---------------------------

		print start_form(-method=>'GET'), 

#			"<table border=1 cellspacing=0 style='border-style:none' bgcolor='#8080a0'>",

			"<table border=1 cellspacing=0 bgcolor='#d0d0f0'>",

			Tr( td( {-colspan=>2, -align=>'center'},
#					-style=>"border-style: solid; border-width: thick; border-color:$bg"},

				font( {-size=>3}, 
					b('Select data by'),
				)
			) ),

			Tr( td( { -valign=>'top' },
#					-style=>"border-style: solid; border-width: thick; border-color:$bg"},

				table( { -border=>0 },
				Tr(
					td( font( {-size=>3}, b( 'Destination:' ) ) ),
					td( font( {-size=>3}, b( 'Probe:' ) ) ),
				),
				Tr(
					td( scrolling_list(-name=>'tag',
						-values=>[sort {$a <=> $b} keys %tagLabels],
						-labels=>\%tagLabels,
						-default=> ( (scalar keys %tagLabels > 1) ? [] : [ keys %tagLabels ]),
						-size=>10, -multiple=>'true', -class=>'dinky')
					),

					td( scrolling_list(-name=>'parts',
						-values=>['All', sort { $tagFreq{$b} <=> $tagFreq{$a} }  keys %tagFreq],
						-default=>['All'],
						-size=>10, -multiple=>'true', -class=>'dinky')
					)
				)
				)
			),
			td( {-valign=>'top'},
				font( {-size=>3}, 
					b( 'Source router:' ),
				),

				&grid( 9,
					map { a( {-href=>$sourceRefs{$_}}, $_) } sort keys %sourceRefs
				),

#				ul(
#					(map { li( a( {-href=>$sourceRefs{$_}}, $_) ) } sort keys %sourceRefs),
#				)
				
			)  ),

			Tr( td( {-valign=>'top'},
				b('Display one set of graphs/tables for:'), p

				radio_group(-name=>'separate',
					-values=>\@sepValues,
					-labels=>\%sepLabels,
					-default=>$sepDefault,
					-linebreak=>'true'
					),
			),
			td( {-valign=>'top'},
				# if more than one graph is available, let the user select which to see

				(@availableGraphTypes <= 1) ?

					hidden(-name=>'graphs', -default=>'All') :

					b('Which graph(s) to display:'), p,

					scrolling_list(-name=>'graphs',
						-values=>[ 'All', @availableGraphTypes ],
						-multiple=>'true',
						-default=>'All', -class=>'dinky')
			) ),

			Tr( td( {-colspan=>2},
				font( {-size=>3},
					b('Options:'),
				), br,

				"<table>",
				&graphForm,
				"</table>",
#			) ),

#			Tr( td( {-colspan=>2, -align=>'center'},
				"<center>",
				submit(-name=>'go', -value=>'Graph', -class=>'dinky'),
				"&nbsp; &nbsp; ",
				submit(-name=>'go', -value=>'Table', -class=>'dinky'),
				"&nbsp; &nbsp; ",
				submit(-name=>'go', -value=>'Graph & Table', -class=>'dinky'),
				"</center>",
			) ),

			end_form(),
			"</table>",
			"</td></tr></table>";

		&navBar("main");
	}

	print end_html();
}

sub grid
{
	my ($maxrows, @vals) = @_;
	my @rows;
	my $row=0;

	while ($_ = shift @vals) {
		push(@{$rows[$row]}, td($_));
		$row = ($row + 1) % $maxrows;
	}

	return
		"<table border=0 cellspacing=0 cellpadding=1>",
		(map { Tr( @$_ ) } @rows),
		"</table>"
	;
}


sub graphIt
{
	my($routerHash) = shift;
	my(@pairs) = @_;

	my $do_graph = (param('go') =~ /graph/i);
	my $do_table = (param('go') =~ /table/i);
	my $separate = (param('separate'));
	my $range = param('range') || &config('graph', 'default_range');
	my $ulimit = $1 if (param('ulimit') =~ /(\d+)/);
	my $llimit = $1 if (param('llimit') =~ /(\d+)/);
	my $start;
	my %graphEnable;

	# if only a subset of graphs have been selected...

	if (param('graphs') !~ /^(All|)$/) {
		map { $graphEnable{$_} = 1; } param('graphs');
	}

	if (param('date') =~ /(\d+)-(\d+)-(\d+)/) {
		my($yy,$mm,$dd) = ($1, $2, $3);

		if (param('hour') =~ /(\d+)\:(\d+)/) {
			my ($h, $m) = ($1 % 12, $2);
			$h += 12 if (param('hour') =~ /pm/i);
			$start = timelocal(0, $m, $h, $dd, $mm - 1, $yy);
		}
	}

	my $maxStart = time - ($range + &config('rrd', 'period'));
	$start = $maxStart if ((! defined $start) || ($start > $maxStart));

	my @colors;
	foreach my $index ( sort {$a <=> $b} &config('color') ) {
		push(@colors, &config('color', $index)) if ($index > 0);
	}

	my $color_background	= &config('color', 'background');
	my $color_baseline	= &config('color', 'baseline');
	my $color_min		= $1 if ( &config('color', 'min') =~ /^\s*(#[0-9a-f]{6})\s*$/ );
	my $color_max		= $1 if ( &config('color', 'max') =~ /^\s*(#[0-9a-f]{6})\s*$/ );

	my $LINE = (($range <= 3600) ? "LINE3" : (($range < 86400) ? "LINE2" : "LINE1"));
	my $LLINE = ($LINE eq "LINE3") ? "LINE2" : "LINE1";

	my $height = &config('graph', param('size') . '_height') || 400;
	my $width = &config('graph', param('size') . '_width') || 700;

	# arrange @pairs to be compatible with $separate

	my $dp2tag = &calcTagsInverted;			# hash of 'router,rtr' => 'tag (protocol)'

	if ($separate eq "sep_target") {		# separate by target
		@pairs = sort { $dp2tag->{$a} cmp $dp2tag->{$b} } @pairs;
	}
	elsif ($separate eq "sep_source") {		# separate by router
		@pairs = sort @pairs;
	}

	# come up with a title suffix (e.g., 'For APLTN_RTR01SP' or 'From GBSC-RTR03WAN')
	# and individual labels (e.g., 'from GBSC-RTR03WAN' or 'APLTN_RTR01SP')

	my (@tagParts, %uglyRouterHash);

	foreach (@pairs) {
		my ($router, $rtr) = split(/,/);
		$uglyRouterHash{$router}++;
		my $count = 0;

		foreach (&breakOutTagParts($router, $rtr)) { $tagParts[$count++]->{$_}++; }
	}

	my (@titles, @tagTitles, @labels, @tagLabels);

	# handle display of source router
	if (@routers > 1) {
		if ((scalar keys %uglyRouterHash == 1) || ($separate eq "sep_source"))  {
			push(@titles, 'from %r');		#  . (keys %uglyRouterHash)[0]);
		}
		elsif ($separate eq "sep_target") {
			push(@labels, 'from %r');
		}
		else {
			push(@labels, '%r');
		}
	}

	# handle tag
	my $count = 0;

	foreach (@tagParts) {
		if ((scalar keys %$_ == 1) || ($separate eq "sep_all")) {		# was sep_target
			push(@tagTitles, '%' . $count);
		}
		else {
			push(@tagLabels, '%' . $count);
		}

		$count++;
	}

	if (($separate eq "sep_target") || ($separate eq "sep_dp") || ($separate eq "sep_all")) {	# target goes in title
		push(@titles, 'for %t');
		push(@titles, join('/', @tagTitles) ) if (@tagTitles);
		push(@labels, join(', ', @tagLabels) ) if (@tagLabels);
	}
	else {												# target goes in label
		push(@labels, '%t');
		push(@labels, '(' . join('; ', @tagLabels) . ')') if (@tagLabels);
		push(@titles, 'tags (' . join('; ', @tagTitles) . ')') if (@tagTitles);
	}

	# handle start date
	push(@titles, strftime( (($range < 8 * 3600) ? 'on %a %b %d %H:%M' : 'on %a %b %d'), localtime($start)));

	my $titleInfo = join(" ", undef, @titles);
	my $labelInfo = join(", ", @labels);

	my (@bounds1, @bounds2);
	if (defined $ulimit) {
		if ($llimit) {
			push(@bounds1, "-l$llimit", "-u$ulimit", "--rigid");
		}
		else {
			push(@bounds1, "-l0", "-u$ulimit", "--rigid");
		}
		push(@bounds2, "-l-$ulimit", "-u$ulimit", "--rigid");
	}
	elsif (defined $llimit) {
		push(@bounds1, "-l$llimit", "--rigid");
	}

	my $re = &config('misc', 'tagregexp');			# grab the location
	my $counter = 0;					# int(rand(100));
	my %graphs;
	my @graphOrder;
	my(%table);

	while (my $dp = shift @pairs) {
		my ($router, $rtr) = split(/,/, $dp);

		my $title;
		my $subTitleInfo;
		my $color = $colors[$counter++ % @colors];		# main line color
		my $scolor = $color;					# stdev color
		my ($llcolor, $ulcolor);

		if ($color =~ /#(..)(..)(..)/) {
			my($r,$g,$b) = (hex($1), hex($2), hex($3));

			my $r_up = $r * 4/3;
			my $g_up = $g * 4/3;
			my $b_up = $b * 4/3;
			my $r_down = $r * 1/3;
			my $g_down = $g * 1/3;
			my $b_down = $b * 1/3;
			$r_up = 255 if ($r_up > 255);
			$g_up = 255 if ($g_up > 255);
			$b_up = 255 if ($b_up > 255);

			$scolor = sprintf("#%02x%02x%02x", $r, $g_up, $b);			# more green

			$llcolor = (defined $color_min) ? $color_min :
				sprintf("#%02x%02x%02x", $r_down, $g_up, $b_down);

			$ulcolor = (defined $color_max) ? $color_max :
				sprintf("#%02x%02x%02x", $r_up, $g_down, $b_down);
		}

		# figure out target
		my $target = &breakOutTagTitle($router, $rtr);

		# figure out tags
		my @tagParts = &breakOutTagParts($router, $rtr);

		my $myTitleInfo = $titleInfo;
		$myTitleInfo =~ s/\%r/$router/;
		$myTitleInfo =~ s/\%t/$target/;
		$myTitleInfo =~ s/\%(\d+)/$tagParts[$1]/ge;

		my $label = $labelInfo;
		$label =~ s/\%r/$router/;
		$label =~ s/\%t/$target/;
		$label =~ s/\%(\d+)/$tagParts[$1]/ge;

		my $type = $routerHash->{$router}->{$rtr}->{type};
		my $p = &counter('p');
		my $rrdName = "$dataDir/$router\#$rtr-$type.rrd";

		if ($type == 1) {				# ECHO GRAPH
			$title = $rttGraphs{$rttTypes{$type}}[0];		# RTT

			if (! defined $graphs{$title}->{header}) {
				push(@graphOrder, $title);

				@{$graphs{$title}->{header}} = (
					'--start', $start,
					'--end', $start + $range,
					'--height', $height,
					'--width', $width,
					'-vmilliseconds',
					@bounds1,
					'--title', $title . $myTitleInfo,
				);
			}

			push(@{$graphs{$title}->{defs}},
				"DEF:ms$p=$rrdName:Milliseconds:MAX"
			);

			push(@{$graphs{$title}->{lines}},
				"LINE2:ms$p$color:$label"
			);

			push(@{$graphs{$title}->{legend}},
				"PRINT:ms$p:MIN:$label~ min = %.0lf",
				"PRINT:ms$p:AVERAGE:$label~ avg = %.0lf",
				"PRINT:ms$p:MAX:$label~ max = %.0lf"
			);
		}
		elsif ($type == 9) {				# JITTER GRAPH

			my $minmax = &boolean(&config('graph', 'jitter_minmax'));

		# Jitter Graph #1 - RTT

			$title = $rttGraphs{$rttTypes{$type}}[0];

			if (! defined $graphs{$title}->{header}) {
				push(@graphOrder, $title);

				@{$graphs{$title}->{header}} = (
					'--start', $start,
					'--end', $start + $range,
					'--height', $height,
					'--width', $width,
					'-vmilliseconds',
					'--units-exponent', '0',
					@bounds1,
					'--title', $title . $myTitleInfo
				);

			}

			push(@{$graphs{$title}->{defs}},
				"DEF:Avg$p=$rrdName:Avg:AVERAGE",
				"DEF:SDev$p=$rrdName:SDev:AVERAGE",
				"DEF:Min$p=$rrdName:Min:AVERAGE",
				"DEF:Max$p=$rrdName:Max:AVERAGE",
				"CDEF:Avg1$p=Avg$p,SDev$p,2,/,-"
			);

			push(@{$graphs{$title}->{lines}},
				&shaded("Avg1$p", "SDev$p", 5, $color_background, $scolor),
				"$LINE:Avg$p$color:$label"
			);

			push(@{$graphs{$title}->{lines}},
				"$LLINE:Max$p$ulcolor",
				"$LLINE:Min$p$llcolor",
			) if ($minmax);

			push(@{$graphs{$title}->{legend}},
				"PRINT:Min$p:MIN:$label~ ms~ min = %.0lf",
				"PRINT:Avg$p:AVERAGE:$label~ ms~ avg = %.0lf",
				"PRINT:Max$p:MAX:$label~ ms~ max = %.0lf",
				"PRINT:SDev$p:MIN:$label~ stddev~ min = %.0lf",
				"PRINT:SDev$p:AVERAGE:$label~ stddev~ avg = %.0lf",
				"PRINT:SDev$p:MAX:$label~ stddev~ max = %.0lf",
			);

		# Jitter Graph #2 - One-way times

			$title = $rttGraphs{$rttTypes{$type}}[1];

			if (! defined $graphs{$title}->{header}) {
				push(@graphOrder, $title);

				@{$graphs{$title}->{header}} = (
					'--start', $start,
					'--end', $start + $range,
					'--height', $height,
					'--width', $width,
					'-vmilliseconds',
					@bounds2,
					'--units-exponent', '0',
					'--title', $title . $myTitleInfo,
					"HRULE:0$color_baseline",
					"COMMENT:src-to-dst times are above axis and " .
						"dst-to-src times are below.\\c",
					"COMMENT:Note: one-way measurements are often unreliable.\\c",
				);
			}

			push(@{$graphs{$title}->{defs}},
				"DEF:AvgSD$p=$rrdName:AvgSD:AVERAGE",
				"DEF:SDevSD$p=$rrdName:SDevSD:AVERAGE",
				"DEF:MinSD$p=$rrdName:MinSD:AVERAGE",
				"DEF:MaxSD$p=$rrdName:MaxSD:AVERAGE",

				"DEF:AvgDS$p=$rrdName:AvgDS:AVERAGE",
				"DEF:SDevDS$p=$rrdName:SDevDS:AVERAGE",
				"DEF:MinDS$p=$rrdName:MinDS:AVERAGE",
				"DEF:MaxDS$p=$rrdName:MaxDS:AVERAGE",

				# compute start/end of Avgs, based on STDDEV
				"CDEF:AvgSD1$p=AvgSD$p,SDevSD$p,2,/,-",
				"CDEF:AvgDS1$p=AvgDS$p,SDevDS$p,2,/,-",

				# create negative values for DS
				"CDEF:iAvgDS$p=0,AvgDS$p,-",
				"CDEF:iAvgSD$p=0,AvgSD$p,-",
				"CDEF:iAvgDS1$p=0,AvgDS1$p,-",
				"CDEF:iSDevDS$p=0,SDevDS$p,-",
				"CDEF:iMinDS$p=0,MinDS$p,-",
				"CDEF:iMaxDS$p=0,MaxDS$p,-"
			);

			push(@{$graphs{$title}->{lines}},
				# plot out SD numbers
				&shaded("AvgSD1$p", "SDevSD$p", 5, $color_background, $scolor),
				"$LINE:AvgSD$p$color:$label",

				# plot out DS numbers
				&shaded("iAvgDS1$p", "iSDevDS$p", 5, $color_background, $scolor),
				"$LINE:iAvgDS$p$color",

				# ensure graph is +/- equal bounds
				"LINE1:iAvgSD$p",				# positive max
				"LINE1:AvgDS$p",				# negative max
			);

			push(@{$graphs{$title}->{lines}},
				"$LLINE:MaxSD$p$ulcolor",
				"$LLINE:MinSD$p$llcolor",
				"$LLINE:iMinDS$p$llcolor",
				"$LLINE:iMaxDS$p$ulcolor",
			) if ($minmax);

			push(@{$graphs{$title}->{legend}},
				"PRINT:MinSD$p:MIN:$label~ src-to-dst~ ms~ min = %.0lf",
				"PRINT:AvgSD$p:AVERAGE:$label~ src-to-dst~ ms~ avg = %.0lf",
				"PRINT:MaxSD$p:MAX:$label~ src-to-dst~ ms~ max = %.0lf",
				"PRINT:SDevSD$p:MIN:$label~ src-to-dst~ stddev~ min = %.0lf",
				"PRINT:SDevSD$p:AVERAGE:$label~ src-to-dst~ stddev~ avg = %.0lf",
				"PRINT:SDevSD$p:MAX:$label~ src-to-dst~ stddev~ max = %.0lf",

				"PRINT:MinDS$p:MIN:$label~ dst-to-src~ ms~ min = %.0lf",
				"PRINT:AvgDS$p:AVERAGE:$label~ dst-to-src~ ms~ avg = %.0lf",
				"PRINT:MaxDS$p:MAX:$label~ dst-to-src~ ms~ max = %.0lf",
				"PRINT:SDevDS$p:MIN:$label~ dst-to-src~ stddev~ min = %.0lf",
				"PRINT:SDevDS$p:AVERAGE:$label~ dst-to-src~ stddev~ avg = %.0lf",
				"PRINT:SDevDS$p:MAX:$label~ dst-to-src~ stddev~ max = %.0lf",
			);

		# Jitter Graph #3 - Combined Jitter

			if (&boolean(&config('graph', 'jitter_combined'))) {

				$title = $rttGraphs{$rttTypes{$type}}[2];

				if (! defined $graphs{$title}->{header}) {
					push(@graphOrder, $title);

					@{$graphs{$title}->{header}} = (
						'--start', $start,
						'--end', $start + $range,
						'--height', $height,
						'--width', $width,
						'-vmilliseconds',
						'--units-exponent', '0',
						@bounds2,
						'--title', $title . $myTitleInfo,
						"HRULE:0$color_baseline",
						"COMMENT:src-to-dst jitter is above axis and " .
							"dst-to-src jitter is below.\\c"
					);
				}

				push(@{$graphs{$title}->{defs}},
					"DEF:AvgSD$p=$rrdName:AvgJSD:AVERAGE",
					"DEF:SDevSD$p=$rrdName:SDevJSD:AVERAGE",

					"DEF:AvgDS$p=$rrdName:AvgJDS:AVERAGE",
					"DEF:SDevDS$p=$rrdName:SDevJDS:AVERAGE",

					# compute start/end of Avgs, based on STDDEV
					"CDEF:AvgSD1$p=AvgSD$p,SDevSD$p,2,/,-",
					"CDEF:AvgDS1$p=AvgDS$p,SDevDS$p,2,/,-",

					# create negative values for DS
					"CDEF:iAvgDS$p=0,AvgDS$p,-",
					"CDEF:iAvgSD$p=0,AvgSD$p,-",
					"CDEF:iAvgDS1$p=0,AvgDS1$p,-",
					"CDEF:iSDevDS$p=0,SDevDS$p,-"
				);

				push(@{$graphs{$title}->{lines}},
					# plot out SD numbers
					&shaded("AvgSD1$p", "SDevSD$p", 5, $color_background, $scolor),
					"$LINE:AvgSD$p$color:$label",

					# plot out DS numbers
					&shaded("iAvgDS1$p", "iSDevDS$p", 5, $color_background, $scolor),
					"$LINE:iAvgDS$p$color",

					# ensure graph is +/- equal bounds
					"LINE1:AvgDS$p",				# positive max
					"LINE1:iAvgSD$p",				# negative max
				);

				push(@{$graphs{$title}->{legend}},
					"PRINT:AvgSD$p:MIN:$label~ src-to-dst~ ms~ min = %.0lf",
					"PRINT:AvgSD$p:AVERAGE:$label~ src-to-dst~ ms~ avg = %.0lf",
					"PRINT:AvgSD$p:MAX:$label~ src-to-dst~ ms~ max = %.0lf",
					"PRINT:SDevSD$p:MIN:$label~ src-to-dst~ stddev~ min = %.0lf",
					"PRINT:SDevSD$p:AVERAGE:$label~ src-to-dst~ stddev~ avg = %.0lf",
					"PRINT:SDevSD$p:MAX:$label~ src-to-dst~ stddev~ max = %.0lf",

					"PRINT:AvgDS$p:MIN:$label~ dst-to-src~ ms~ min = %.0lf",
					"PRINT:AvgDS$p:AVERAGE:$label~ dst-to-src~ ms~ avg = %.0lf",
					"PRINT:AvgDS$p:MAX:$label~ dst-to-src~ ms~ max = %.0lf",
					"PRINT:SDevDS$p:MIN:$label~ dst-to-src~ stddev~ min= %.0lf",
					"PRINT:SDevDS$p:AVERAGE:$label~ dst-to-src~ stddev~ avg = %.0lf",
					"PRINT:SDevDS$p:MAX:$label~ dst-to-src~ stddev~ max = %.0lf",
				);
			}

			if (&boolean(&config('graph', 'jitter_separate'))) {
				foreach ('SD', 'DS') {

		# Jitter Graph #4 and #5 - Jitter broken out by SD and DS

					$title = $rttGraphs{$rttTypes{$type}}[($_ eq "SD") ? 3 : 4];

					if (! defined $graphs{$title}->{header}) {
						push(@graphOrder, $title);

						@{$graphs{$title}->{header}} = (
							'--start', $start,
							'--end', $start + $range,
							'--height', $height,
							'--width', $width,
							'-vmilliseconds',
							'--units-exponent', '0',
							@bounds2,
							'--title', $title . $myTitleInfo,
							"HRULE:0$color_baseline",
							"COMMENT:positive jitter is above axis and " .
								"negative jitter is below.\\c"
						);
					}

					push(@{$graphs{$title}->{defs}},
						"DEF:AvgP$p=$rrdName:AvgP$_:AVERAGE",
						"DEF:SDevP$p=$rrdName:SDevP$_:AVERAGE",
						"DEF:AvgN$p=$rrdName:AvgN$_:AVERAGE",
						"DEF:SDevN$p=$rrdName:SDevN$_:AVERAGE",

						# compute start/end of Avgs, based on STDDEV
						"CDEF:AvgP1$p=AvgP$p,SDevP$p,2,/,-",
						"CDEF:AvgN1$p=AvgN$p,SDevN$p,2,/,-",

						# create negative values for DS
						"CDEF:iAvgN$p=0,AvgN$p,-",
						"CDEF:iAvgP$p=0,AvgP$p,-",
						"CDEF:iAvgN1$p=0,AvgN1$p,-",
						"CDEF:iSDevN$p=0,SDevN$p,-"
					);

					push(@{$graphs{$title}->{lines}},
						# plot out P numbers
						&shaded("AvgP1$p", "SDevP$p", 5, $color_background, $scolor),
						"$LINE:AvgP$p$color:$label",

						# plot out N numbers
						&shaded("iAvgN1$p", "iSDevN$p", 5, $color_background, $scolor),
						"$LINE:iAvgN$p$color",

						# ensure graph is +/- equal bounds
						"LINE1:AvgN$p",					# positive max
						"LINE1:iAvgP$p",				# negative max
					);

					push(@{$graphs{$title}->{legend}},
						"PRINT:AvgP$p:MIN:$label~ positive jitter~ ms~ min = %.0lf",
						"PRINT:AvgP$p:AVERAGE:$label~ positive jitter~ ms~ avg = %.0lf",
						"PRINT:AvgP$p:MAX:$label~ positive jitter~ ms~ max = %.0lf",
						"PRINT:SDevP$p:MIN:$label~ positive jitter~ stddev~ min = %.0lf",
						"PRINT:SDevP$p:AVERAGE:$label~ positive jitter~ stddev~ avg = %.0lf",
						"PRINT:SDevP$p:MAX:$label~ positive jitter~ stddev~ max = %.0lf",

						"PRINT:AvgN$p:MIN:$label~ negative jitter~ ms~ min = %.0lf",
						"PRINT:AvgN$p:AVERAGE:$label~ negative jitter~ ms~ avg = %.0lf",
						"PRINT:AvgN$p:MAX:$label~ negative jitter~ ms~ max = %.0lf",
						"PRINT:SDevN$p:MIN:$label~ negative jitter~ stddev~ min = %.0lf",
						"PRINT:SDevN$p:AVERAGE:$label~ negative jitter~ stddev~ avg = %.0lf",
						"PRINT:SDevN$p:MAX:$label~ negative jitter~ stddev~ max = %.0lf"
					);
				}
			}

		# Jitter Graph #6 - Packet Loss

			$title = $rttGraphs{$rttTypes{$type}}[5];

			if (! defined $graphs{$title}->{header}) {
				push(@graphOrder, $title);

				@{$graphs{$title}->{header}} = (
					'--start', $start,
					'--end', $start + $range,
					'--height', $height,
					'--width', $width,
					'-vpacket loss',
					'--units-exponent', '0',
					'--title', $title . $myTitleInfo,
					"HRULE:0$color_baseline",
					"COMMENT:dst-to-src loss is above axis and " .
						"src-to-dst loss is below axis.\\c"
				);
			}

			push(@{$graphs{$title}->{defs}},
				"DEF:LAvgSD$p=$rrdName:LossSD:AVERAGE",
				"DEF:LAvgDS$p=$rrdName:LossDS:AVERAGE",
				"DEF:LMinSD$p=$rrdName:LossSD:MIN",
				"DEF:LMinDS$p=$rrdName:LossDS:MIN",
				"DEF:LMaxSD$p=$rrdName:LossSD:MAX",
				"DEF:LMaxDS$p=$rrdName:LossDS:MAX",

				# create negative values for DS
				"CDEF:iLAvgDS$p=0,LAvgDS$p,-",
				"CDEF:iLMinDS$p=0,LMinDS$p,-",
				"CDEF:iLMaxDS$p=0,LMaxDS$p,-",
				"CDEF:iLMaxSD$p=0,LMaxDS$p,-",
			);

			push(@{$graphs{$title}->{lines}},
				"$LINE:LAvgSD$p$color:$label",
				"$LINE:iLAvgDS$p$color",

				# ensure graph is +/- equal bounds
				"LINE1:LMaxDS$p",				# positive max
				"LINE1:iLMaxSD$p",				# negative max
			);

			push(@{$graphs{$title}->{lines}},
				"$LLINE:LMinSD$p$llcolor",
				"$LLINE:LMaxSD$p$ulcolor",
				"$LLINE:iLMinDS$p$llcolor",
				"$LLINE:iLMaxDS$p$ulcolor",
			) if ($minmax);

			push(@{$graphs{$title}->{legend}},
				"PRINT:LMinSD$p:MIN:$label~ src-to-dst~ min = %.0lf",
				"PRINT:LAvgSD$p:AVERAGE:$label~ src-to-dst~ avg = %.0lf",
				"PRINT:LMaxSD$p:MAX:$label~ src-to-dst~ max = %.0lf",

				"PRINT:LMinDS$p:MIN:$label~ dst-to-src~ min = %.0lf",
				"PRINT:LAvgDS$p:AVERAGE:$label~ dst-to-src~ avg = %.0lf",
				"PRINT:LMaxDS$p:MAX:$label~ dst-to-src~ max = %.0lf"
			);
		}

		if (@pairs) {
			my $nextdp = $pairs[0];
			my ($nextrouter, $nextrtr) = split(/,/, $nextdp);

			if ($separate eq "sep_target") {		# separate by target
				next if ($dp2tag->{$dp} eq $dp2tag->{$nextdp});
			}
			elsif ($separate eq "sep_source") {		# separate by router
				next if ($router eq $nextrouter);
			}
			elsif ($separate eq "sep_dp") {			# separate for every router,target combo
				next if (
					($router eq $nextrouter) &&
					($dp2tag->{$dp} eq $dp2tag->{$nextdp})
				);
			}
			elsif ($separate eq "sep_none") {		# no separation
				next;
			}
		}

		foreach my $title (@graphOrder) {
			if ((%graphEnable) && (! $graphEnable{$title})) {
#				print "skipping $title<br>\n";
				next;
			}

			my $fmt = &config('graph', 'format');
			my $img = &counter("image-$$-") . ".$fmt";

			my @rrd = (
				$graphDir . '/' . $img,
				'-a', uc($fmt),
				@{$graphs{$title}->{header}},
				@{$graphs{$title}->{defs}}
			);

			push(@rrd, @{$graphs{$title}->{lines}}) if ($do_graph);
			push(@rrd, @{$graphs{$title}->{legend}}) if ($do_table);

			my($print, @crap) = RRDs::graph(@rrd);

			my $err=RRDs::error;
			if ($err) {
				print "RRDs GRAPH: ", b($err), br, "\n";
				foreach (@rrd) {
					print $_, br, "\n";
				}
			}
			else {
				print "<center>",
					img( { -src=>$graphDirURL . '/' . $img,
						-alt=>$title . $myTitleInfo}),
					"</center>", br
					if ($do_graph);

				# create data transform

				my %itemOrder;
				foreach (@$print) {
					next if (! /^([^~]*)~(.*?)\s*=\s*(.*)$/);
					my($item, $label, $value) = ($1, $2, $3);
				
					$value = '-' if (lc($value) eq "nan");
					push(@{$table{$title}->{'tableOrder'}}, $label) if (! exists $table{$title}->{$label});
					push(@{$table{$title}->{'itemOrder'}}, $item) if (! exists $itemOrder{$item});
					$itemOrder{$item} = 1;
					$table{$title}->{$label}->{$item} = $value;
				}
			}

			if (($do_table) && ($do_graph)) {
				&dumpTable(\%table, undef, $title);
				undef %table;
			}
		}

		if ((! $do_graph) && ($do_table)) {
			&dumpTable(\%table, $myTitleInfo, @graphOrder);
		}

		undef %table;
		undef %graphs;
		undef @graphOrder;
	}							# end of foreach @pairs

#	print p, "\n";

# -----------------------------------------------------------

#	return if ($range > 86400);			# no changes for week/yearly views

	# present a date change form
	print 
		start_form(-method=>'GET'),
		hidden(-name=>'router', -default=>param('router')),
		hidden(-name=>'rtr', -default=>param('rtr')),
		hidden(-name=>'tag', -default=>param('tag')),
		hidden(-name=>'parts', -default=>param('parts')),
		hidden(-name=>'go', -default=>param('go')),
		hidden(-name=>'separate', -default=>param('separate')),
		hidden(-name=>'graphs', -default=>param('graphs')),

		"<table border=0 cellspacing=0 bgcolor='#d0d0f0'>",
		&graphForm(! $do_graph),

		Tr( td( {-colspan=>2, -align=>'center'},
			submit(-value=>'Set', -class=>'dinky'),
		) ),

		"</table>",

		end_form();

	&navBar("router");
}

sub graphForm
{
	my $table = shift;

	# for the past two weeks
	my (@dates, @hours);

	for (my $tt = time-(14*86400); $tt <= time; $tt += 86400) {
		push(@dates, POSIX::strftime("%Y-%m-%d %a", localtime($tt)));
	}

	for (my $hh = 0; $hh < 24; $hh++) {
		push(@hours, POSIX::strftime("%l:00 %p", 0, 0, $hh, 0, 0, 0));
	}

	my($ddate, $dhour) = split(/\|/, POSIX::strftime("%Y-%m-%d %a|%l:00 %p", localtime()) );

	my @stuff;

	push(@stuff,
		Tr( td( 'Starting date: ',
			popup_menu(-name=>'date', -values=>\@dates, -default=>$ddate, -class=>'dinky'),
			popup_menu(-name=>'hour', -values=>\@hours, -default=>$dhour, -class=>'dinky'),
		),

		td( 'Duration: ',
			popup_menu(-name=>'range',
				-values=>[sort {$a <=> $b} keys %dateRange],
				-labels=>\%dateRange,
				-default=>&config('graph', 'default_range'),
				-class=>'dinky'),
		) )
	);

	push(@stuff,
		Tr(
			td('Graph bounds: ',
				'Lower ',
				popup_menu(-name=>'llimit',
					-values=>[ 'Auto', '0ms', @boundValues ],
					-default=>'0ms',
					-class=>'dinky'),
				'Upper ',
				popup_menu(-name=>'ulimit',
					-values=>[ 'Auto', @boundValues ],
					-default=>'Auto',
					-class=>'dinky'),
			),

			td( 'Graph size: ',
				popup_menu(-name=>'size',
					-values=>['tiny', 'small', 'medium', 'large', 'huge'],
					-default=>'medium',
					-class=>'dinky')
		) ),

	) if (! $table);

	return @stuff;
}

sub dumpTable
{
	my($table, $label, @titles) = @_;

	foreach my $title (@titles) {
		next if (! exists $table->{$title});

		print "<center>";
		print "<h4>$title$label</h4>" if ($label);
		my @itemOrder = @{$table->{$title}->{'itemOrder'}};
		my @tableOrder = @{$table->{$title}->{'tableOrder'}};

		my (@header, @headers);
		foreach (@tableOrder) {
			my @parts = split(/\s*~\s*/);
			for (my $count=0; $count < @parts; $count++) {
				push(@{$header[$count]}, $parts[$count]);
			}
		}
		my $noItem = ((@itemOrder == 1) && ($itemOrder[0] =~ /^\s*$/));

		foreach (@header) {
			my ($last, $count, @cols);

			# this loop generates one <td> spacer at the beginning
			foreach (@$_) {
				if ($_ eq $last) {
					$count++;
				}
				else {
					push(@cols, (($count > 1) ? "<td colspan=$count align=center>" : "<td align=center>")
						. $last . "</td>");
					$count = 1;
					$last = $_;
				}
			}
			push(@cols, (($count > 1) ? "<td colspan=$count align=center>" : "<td align=center>") . $last . "</td>");
			shift @cols if ($noItem);
			push(@headers, join("", @cols));
		}

		# display table
		print "<table border=2 rules=groups cellspacing=0 style='font-size: 10; font-family: sans-serif'>\n";

		if (@headers > 1) {					# other colgroups as well
			my $x = $headers[$#headers - 1];
			while ($x =~ s/\<td\s*([^\>]*)\>//) {
				printf ("<colgroup span=%d>", ($1 =~ /colspan=(\d+)/i) ? $1 : 1);
			}
		}

		print "<thead>\n";
		foreach (@headers) {
			print Tr({-style=>'font-size: 12; font-weight: bold'}, $_), "\n";
		}
		print "</thead>";

		foreach my $item (@itemOrder) {
			print "<tr>";
			print "<td align=right>$item</td>" if (! $noItem);
			print map { td({-align=>'center', -width=>50}, $_) } ( map { $table->{$title}->{$_}->{$item} } @tableOrder );
			print "\n</tr>";
		}
		print "</table></center><p><hr>";
	}
}

sub shaded
{
	my($startDEF, $shadeDEF, $intervals, $color1, $color2) = @_;
	my(@results);
	
	return if (($intervals < 1) || ($intervals > 16));
	$intervals = int($intervals);

	push(@results, "AREA:" . $startDEF);				# get cursor to right starting spot

# 1 : 0 changes in color (use color1 for the whole thing
# 2 : 1 change in color (half color1, half something between color1 and color 2
# 3 : 2 changes in color ...

	my @colors = &colorSpectrum($intervals, $color1, $color2);

	push(@results, "CDEF:" . $shadeDEF . "_Interval=" . $shadeDEF . ",2,/,$intervals,/");	# divide the length in half

	foreach (@colors) {
		push(@results, "STACK:" . $shadeDEF . "_Interval" . $_);
	}

	foreach (reverse @colors) {
		push(@results, "STACK:" . $shadeDEF . "_Interval" . $_);
	}

	return @results;
}

sub colorSpectrum
{
	my($steps, $c1, $c2) = @_;

	return undef if ($c1 !~ /#(..)(..)(..)/);
	my ($r1, $g1, $b1) = (hex($1), hex($2), hex($3));
	return undef if ($c2 !~ /#(..)(..)(..)/);
	my ($r2, $g2, $b2) = (hex($1), hex($2), hex($3));

	my $rd = ($r2 - $r1) / $steps;
	my $gd = ($g2 - $g1) / $steps;
	my $bd = ($b2 - $b1) / $steps;
	my @colors;

	for (1 .. $steps) {
		push(@colors, sprintf("#%02x%02x%02x", $r1, $g1, $b1));
		$r1 += $rd; $g1 += $gd; $b1 += $bd;
	}
	return @colors;
}

sub counter
{
	my($var) = $_[0];
	return sprintf("$var%04d", ++$counters{"Counter_$var"});
}

sub houseKeeping
{
	my($dir) = $_[0] || ".";
	my(@files);

	my $cleanupTime = &config('timer', 'cleanup');
	my $cutoff = time - $cleanupTime;

	my $fmt = &config('graph', 'format');
	opendir(DIR, $dir);
	@files = grep (/^image-\d+-\d+.$fmt/, readdir(DIR));
	closedir(DIR);

	foreach (@files) {
		unlink("$dir/$_") if ( (stat("$dir/$_"))[9] < $cutoff);
	}
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

sub absolutelyme
{
	my $pathonly = shift;

	return ($0 =~ /(.*)[\/\\]([^\/^\\]+)$/) ?
		Cwd::abs_path($1) . (($pathonly) ? '' : '/' . $2) :
		Cwd::cwd . (($pathonly) ? '' : '/' . $0);
}

sub findConfig
{
	my $mode = shift;
	my $fn;
	my @configSearchPath;

	my $whoami = &absolutelyme;

	push(@configSearchPath, &absolutelyme(1));			# check same dir as script
	push(@configSearchPath, cwd);					# check current working directory
	push(@configSearchPath, $defaultConfigDirectory);		# then check /etc
	push(@configSearchPath, &config('directory', 'data'));		# then check default data directory

	foreach (@configSearchPath) {
		$fn = $_ . '/' . $defaultConfigFileName;
		return $fn if (-f $fn);
	}

	return undef if ($mode eq "setup");

	my $err = <<EOT;
Config file '$defaultConfigFileName' not found in search path (@configSearchPath)
EOT

	$err .= <<EOT if ($WEBUSER);

Use '$0 --setup' from the command-line to
set up default directories and config file.
EOT

	&dumperrors( $err );
	return undef;
}

sub loadConfig
{
	my ($config, $cfgFile) = @_;

	open(IN, $cfgFile) || do {
		&logit($LOG_ERROR, "$cfgFile could not be opened", $!);
		return 0;
	};

	while ( <IN> ) {
		chomp;
		next if (/^\s*\#/);	# skip comment-only lines
		s/^\s+//;		# get rid of leading whitespace
		s/\s+$//;		# get rid of trailing whitespace
		s/\s+/ /g;		# make sure all whitespace is realy a single space
		next if (! $_);		# skip all blank lines

		if (/^(\S+) (\S+) (\S+\s.+)$/) {		# router foo snmp public
			$config->{$1}->{$2} = { split(/\s+/, $3) };
		}
		elsif (/^(\S+) (\S+) (\S+)$/) {			# directory foo /bar
			$config->{$1}->{$2} = $3;
		}
		elsif (/^(\S+) (\S+)$/) {				# misc password <undef>
			$config->{$1}->{$2} = undef;
		}
		else {
			&logit($LOG_ERROR, "line $. unparsable: $_");
		}
	}

	return 1;
}

sub saveConfig
{
	my($config, $cfgFile) = @_;

	open(OUT, ">$cfgFile") || return 0;

	foreach my $major (keys %$config) {
		foreach my $minor (keys %{$config->{$major}}) {

			if (&majorVars($major)) {
				print OUT "$major $minor";
				foreach my $key (&majorVars($major)) {
					next if (! $config->{$major}->{$minor}->{$key});
					print OUT " $key ", $config->{$major}->{$minor}->{$key};
				}
				print OUT "\n";
			}
			else {
				print OUT "$major $minor ", $config->{$major}->{$minor}, "\n";
			}
		}
	}

	close(OUT);
	return 1;
}


# --------------------------------------------------------------
# ensure some basic system things

sub sanityChecks
{
	my(@errors);

#	push(@errors, "No routers defined.") if (@routers == 0);

	foreach ( $dataDir, $graphDir) {
		if (! -d $_) {
			push(@errors, "directory $_ does not exist.");
		}
	}

	foreach ($configFile, "$graphDir/testfile") {
		my $purge = (! -f $_);
		if (open(OUT, ">>$_")) { close(OUT); unlink($_) if ($purge); }
		else { push(@errors, "file $_ could not be written: $!"); }
	}

	return 1 if (! @errors);
	&dumperrors( @errors );
	return 0;
}

sub graphSanityCheck
{
	if ( ($WEBUSER) && (&boolean(&config('directory', 'warnings'))) ) {
		if (my $docRoot = $ENV{"DOCUMENT_ROOT"}) {
			if ($graphDir ne $docRoot . $graphDirURL) {

				my $err = <<EOT;
The graph_absolute and graph_relative directories do not appear to point to
the same location. If you are sure that they do, this check can be suppressed
by setting 'directory warnings' to 'off'.

              DOCUMENT_ROOT $docRoot
   directory graph_absolute $graphDir
   directory graph_relative $graphDirURL
EOT
				my $x = $graphDir;
				if ($x =~ s/^$docRoot//) {		# we have a suggestion
					$err .= <<EOT;

A suggestion is to change 'directory graph_relative' to '$x'.
EOT
				}
				print "<pre>$err</pre>\n";
				return 0;
			}
		}
	}
	return 1;
}

sub config
{
	my($major, @minors) = @_;

	if (wantarray()) {
		return (sort keys %{$config->{$major}}) if (! @minors);
		return ( map { $config->{$major}->{$_} } @minors );
	}

	return $config->{$major}->{$minors[0]};
}

sub subconfig
{
	my($major, $minor, $key) = @_;
	return $config->{$major}->{$minor}->{$key};
}


sub boolean
{
	my $x = shift;
	return 1 if ($x > 0);
	return ($x =~ /yes|true|on/i);
}

sub dumperrors
{
	print header('text/plain') if ($WEBUSER);
	print join("\n\n", $VERSION . " error:", map { s/\n/\n  /gm; "- $_"; } @_) , "\n";
}

# --------------------------------------------------------------
# CGI log viewer
# --------------------------------------------------------------

sub logCGI
{
	&navBar("log");
	my $lines = &config('misc', 'loglines');
	my $fn = $dataDir . '/' . &config('misc', 'logfile');
	my @lines;

	print font({-size=>'+2'}, "Last $lines lines of log file (reverse order)"), p;
	open(IN, $fn);
	while ( <IN> ) { push(@lines, $_); }
	close(IN);

	print "<pre>\n";
	@lines = splice(@lines, -$lines) if (@lines > $lines);
	foreach ( reverse @lines ) { print $_; } 
	print "</pre>\n";

	print hr, font({-size=>'+2'}, "directory of $dataDir"), p;

	print "<pre>\n";
	opendir(DIR, $dataDir);
	while ($_ = readdir(DIR)) {
		my @s = stat($dataDir . '/' . $_);
		printf ("%20.20s %10.10s %s\n", scalar localtime($s[9]), $s[7], $_);
	}
	closedir(DIR);
	print "</pre>\n";
}

# --------------------------------------------------------------
# CGI config editor - operates on global $config hash
# --------------------------------------------------------------

sub configCGI
{
	my $major = param('major');
	my $minor = param('newminor') || param('minor');
	my $action = param('action');

	if (($major) && ($minor)) {
		if ($action eq "save") {

			if (! &kosher($minor)) {
				print h4("Invalid character in $major name: ", b($minor));
				&configEditVar($major, param('minor'));
				return;
			}
			else {
				foreach (grep /^val/, param()) {
					my $v = $1 || 'value';
					my $val = param($_);

					if (! &kosher($val)) {
						print h4('Invalid character in ', b($v), ': ', $val);

						&configEditVar($major, param('minor'));
						return;
					}
				}
			}

			if (&majorVars($major)) {
				map { $config->{$major}->{$minor}->{$_} = param("val$_") } &majorVars($major);
			}
			elsif (&ispw($major,$minor)) {
				$config->{$major}->{$minor} = 
					crypt(param('val'),
						join '', ('.', '/', 0..9, 'A'..'Z', 'a'..'z')[rand 64, rand 64]
					);

				param('password', param('val'));		# transfer password to form for continued use
				print "password set to ", param('val'), p;
			}
			elsif (&isreset($major,$minor)) {
				if (param('val') =~ /^\s*yes\s*/i) {
					$config->{$major}->{$minor} = 'yes';
					&saveConfig($config, $configFile);

					&logit($LOG_INFO, $ENV{'REMOTE_ADDR'} . " resets rrd files");
					&configEditMain;
					return;
				}
				else {
					&configEditVar($major, $minor);
					return;
				}
			}
			else {
				$config->{$major}->{$minor} = param('val');
			}

			&logit($LOG_INFO, $ENV{'REMOTE_ADDR'} . " adds/edits $major $minor");
			&saveConfig($config, $configFile);
		}
		elsif ($action eq "delete") {
			delete $config->{$major}->{$minor};

			&logit($LOG_INFO, $ENV{'REMOTE_ADDR'} . " deletes $major $minor");
			&saveConfig($config, $configFile);
		}
		elsif ($action ne "cancel") {
			&configEditVar($major, $minor);
			return;
		}
	}

	&configEditMain;
}

sub kosher
{
	return ($_[0] !~ /[\x00-\x20]/);
}

sub configEditVar
{
	my($major, $minor) = @_;
	my $cp;
	
	&navBar('editvar');

	print start_form(-method=>'POST'),
		hidden(-name=>'edit'),
		hidden(-name=>'password'),
		hidden(-name=>'major', -value=>$major),
		"<table border=1 cellspacing=0 cellpadding=4>";

	if (&majorVars($major)) {
		map { $cp->{$_} = $config->{$major}->{$minor}->{$_} } &majorVars($major);
	}
	else {
		$cp = $config->{$major}->{$minor};
	}

	if ($minor eq "new") {
		print Tr(
			td( {-bgcolor=>$cmajor, -align=>'right'}, b( "New $major" ) ),
			td( {-bgcolor=>$ccell}, textfield(-name=>'newminor', -size=>60, -maxlength=>120),
				hidden(-name=>'minor', -value=>$minor) )
		);
	}
	else {
		print Tr(
			td( {-bgcolor=>$cminor, -colspan=>2}, font( {-size=>'+1'}, "$major $minor"),
				hidden(-name=>'minor', -value=>$minor)
			),
		);
	}


	print "<tr>",
		td( {-bgcolor=>$cminor, -align=>'right', -width=>80}, b( 'value' ) );

	if (! ref($cp)) {		# simple variable
		undef $cp if (&ispw($major, $minor));

		print td( {-bgcolor=>$ccell}, textfield(-name=>'val', -default=>$cp, -size=>60, -maxlength=>120) );
	}
	else {				# complex variable
		print td( {-bgcolor=>$ccell},
			"<table>",
			( map { Tr(
					td( {-align=>'right'}, i($_) ),
					td( {-bgcolor=>$ccell}, textfield(-name=>"val$_",
						-default=>$cp->{$_},
						-size=>60, -maxlength=>120) )
				)
			} &majorVars($major) ),
			"</table>"
		);
	}

	print "</tr>";

	if (&isreset($major, $minor)) {
		print Tr( td( {-colspan=>2, -align=>'center', -bgcolor=>$ccell}, 
			font({-color=>'red'},
				b('Warning:'),
				'Resetting the RRD files will erase all historical data.', br,
				'Unfortunately, this is necessary when changes are made to the rrd variables (period, rows, etc).', p,
				'If you want to do this, type ', b('yes'), 'into the box above and click', b('save'), '.', p,
				'Otherwise, click ', b('cancel'), '.' )
		) );
	}
	elsif (&isrrd($major)) {
		print Tr( td( {-colspan=>2, -align=>'center', -bgcolor=>$ccell}, 
			font({-color=>'red'},
				b('Note:'),
				'Changes to RRD settings only affect new data sources (i.e., routers and/or RTR probes).', br,
				'To apply a change globally, be sure to click the', b('reset'), 'link after saving the change.')
		) );
	}

	print Tr( td( {-colspan=>2, -align=>'center', -bgcolor=>$ccell}, 
			submit(-name=>'action', -value=>'save'),
			' &nbsp; &nbsp; ',
			submit(-name=>'action', -value=>'delete'),
			' &nbsp; &nbsp; ',
			submit(-name=>'action', -value=>'cancel')
		) ),
		"</table>",
		end_form;
}

sub configEditMain
{
	&navBar('edit');

	print <<EOT;
<SCRIPT>
function edit(major,minor)
{
	document.editform.major.value=major;
	document.editform.minor.value=minor;
	document.editform.submit();
}
</SCRIPT>
EOT

	print start_form(-name=>'editform', -method=>'POST'),
		hidden(-name=>'edit'),
		hidden(-name=>'password'),
		hidden(-name=>'major'),
		hidden(-name=>'minor'),
		"<table cellspacing=0 cellpadding=4>";

	foreach my $major (@configOrder) {

		my $rrdreset;

		if ($major eq 'rrd') {
			$rrdreset = a( {-href=>"javascript:edit('$major','reset')"}, "(reset)");
		}

		print Tr(
			td ({-bgcolor=>$cmajor, -colspan=>2}, b($major),
				a( {-href=>"javascript:edit('$major','new');"}, '(add)' ), $rrdreset )
		);

		foreach my $minor ( sort byPaddedNum keys %{$config->{$major}} ) {

			print "<tr>",
				td ({-bgcolor=>$cminor, -align=>'right'},
					a( {-href=>"javascript:edit('$major','$minor');"}, $minor)
				);

			if (! ref($config->{$major}->{$minor})) {
				print td ({-bgcolor=>$ccell, -class=>'config'},
					&ispw($major,$minor) ? ($config->{$major}->{$minor} ? i('encrypted') : '') :
					&colorit( $config->{$major}->{$minor} ) );
			}
			else {
				print td ({-bgcolor=>$ccell, -class=>'config'},
					"<table>",
					( map	{ $config->{$major}->{$minor}->{$_} ?
							Tr( td( {-align=>'right'}, i($_) ),
							td( $config->{$major}->{$minor}->{$_} ))
							: undef
						}
						&majorVars($major) ),
					"</table>"
				);
			}
			print "</tr>\n";
		}

		print Tr( td( {-colspan=>4}, '&nbsp;' ) );
	}

	print "</table>", end_form;
	&navBar('edit');
}

sub colorit
{
	my $s = shift;
	if ($s =~ /^#[0-9a-f]{6}$/) {
		return font({-color=>$s}, $s);
	}
	else {
		return $s;
	}
}

sub ispw
{
	return (($_[0] eq "misc") && ($_[1] eq "password"));
}

sub isreset
{
	return (($_[0] eq "rrd") && ($_[1] eq "reset"));
}

sub isrrd
{
	return ($_[0] eq "rrd");
}

sub navBar
{
	my $where = shift;
	my @nav;

	my $ref = url(-relative=>1);

	if ($where eq "main") {
		# show password/admin link


		push(@nav, join("",
			( (&config('misc', 'password')) ?
				'Password: ' . password_field(-name=>'password', -size=>10, -maxsize=>20) . ' '
				: ''),
			submit(-name=>'edit', -value=>'IP SLA Admin', -class=>'nav'),
		));
	}
	else {
		if ($where eq "edit") {
			push(@nav,
				submit(-name=>'edit', -value=>'IP SLA Log', -class=>'nav'),
				submit(-name=>'edit', -value=>'IP SLA Info', -class=>'nav')
			);
		}
		elsif ($where eq "log") {
			push(@nav,
				submit(-name=>'edit', -value=>'IP SLA Setup', -class=>'nav'),
				submit(-name=>'edit', -value=>'IP SLA Info', -class=>'nav')
			);
		}
		elsif ($where eq "editvar") {
			push(@nav,
				submit(-name=>'edit', -value=>'IP SLA Setup', -class=>'nav'),
				submit(-name=>'edit', -value=>'IP SLA Log', -class=>'nav'),
			);
		}

		push(@nav,
			button(-name=>'IP SLA Home', -onClick=>"location='$ref';",  -class=>'nav'),
		);
	}

	push(@nav,
		button( -name=>'Documentation',
			-onClick=>"location='ipslaMon.html';",
			-class=>'nav'),

		button(	-name=>unescape(&config('misc', 'linkname')),
			-onClick=>"location='" . &config('misc','linkurl') . "';",
			-class=>'nav')
	);

	print 
		start_form(-method=>'POST'),
		(($where ne "main") ? hidden(-name=>'password') : ''),
		"<table cellpadding=10>",
		Tr( {-valign=>'center'}, map { td( $_ ) } i('Navigation:'), @nav),
		"</table>",
		end_form,
		"\n";
}

sub majorVars
{
	if ($_[0] eq "router") {
		return ('snmp', 'host');
	}
	return;
}

