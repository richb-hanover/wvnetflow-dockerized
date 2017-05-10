#!/usr/bin/perl

# -------------------------------------------------------------------------
# FLOWAGE.PL
#  written by Craig Weinhold (craig.weinhold@cdw.com)
#
#  1 a : an overflowing onto adjacent land b : a body of water formed by
#  overflowing or damming c : floodwater especially of a stream
#     (Merriam-Webster)
#
#  What does this have to do with networking or netflow? Not much, except the
#  name similarity. But, it's supposedly a regional term that only is known
#  in Wisconsin and Illinois, so this program is called 'flowage' to help
#  spead the word.
#
# revision history
#
# 1.0  09-15-00  initial version
# 1.01 09-25-00  added dynamic access-lists
# 1.02 10-15-00  added multiple file formats for output, include directive,
#                and interface/exporter filtering with snmp
# 1.03 10-17-00  added temporal data storage, lock files, logging, and
#                cleaned up a bunch of things.
# 1.04 12-13-01  added ACL groups and text file wrapping
# 1.05 12-18-01  merged in multiprocess code
# 1.10 12-27-01  revised config file
# 1.11 01-08-02  added index file code
# 1.12 01-27-02  added ACL compiler (aka 'eval')
# 1.13 01-28-02  added ACL optimization (reduces redundant tests)
# 1.14 02-05-02  added packetsize, bps, and pps ACL values, and file descriptions
# 1.15 02-28-02  fixed localNextHop bugs
# 1.20 04-25-02  significant performance increase (6-10x) by optimizing wanted().
# 1.21 04-26-02  improvements with file handles and buffered output
# 1.22 04-29-02  speed improvements for CSV/text output
# 1.30 05-09-02  added support for matrices -- arbitrary datafile names based on flow data
# 1.31 05-12-02  full csv matrix support, and matrix 'Other' category
# 1.32 06-15-02  fixed watchDir support
# 1.33 10-27-02  fixed bug in handling of config-file comments
# 1.34 11-07-02  added description and alias files. now localnexthop works with interface matrices.
# 1.35 11-11-02  added tcpflags and icmp codes to the ACLs.
# 1.36 11-26-02  added 'ip host-list' construct and fixed bug in hackIP
# 1.37 11-29-02  now supports datafiles in subdirectories and authorization files
# 1.38 12-01-02  user-defined rrd resolution, interface cache timeout, general cleanup
# 1.39 12-04-02  added DNS resolution for ip/nexthop descriptions
# 1.40 12-09-02  added interface speed collection
# 1.41 01-30-03  fixed DNS bug with max handles in use
# 1.42 02-02-03  added @fooOrdered so that the foo order in index files follows the config file
# 1.50 04-18-03  added IPTracker - tracking of ip hashes for each interface
# 1.51 04-21-03  added some ACL optimizations to wanted()
# 1.52 05-10-03  added buckets, piper updater, and dysfunctional flow cache
# 1.53 05-27-03  changed logfile size check (lines->bytes) and added flow redirection
# 1.54 06-09-03  fixed subinterface bug in hackInterfaces
# 1.55 06-13-03  removed dysfunctional flow cache, streamlined wanted() subroutine, added special flow export
# 1.56 06-18-03  fixed problem with bucket range
# 1.57 10-13-03  added exporterName to inteface cache files
# 1.58 10-28-03  reworked dacl/host-list storage/integration with wvFlowCat
# 1.59 11-07-03  fixed bug in config file comment processing
# 1.60 11-11-03  fixed bugs in fpipe and date-handling of flow-tools files (daylight savings)
# 1.61  3-25-04  add memory protection
# 1.70  7-30-04  added trie structure for host-lists (removed hashes), allowed for host-lists to be used in datafile defs
# 1.71  8-11-04  fixed matrix by matrix datafiles (e.g., source subnet by dest subnet)
# 1.72  9-21-04  fixed bug in fileSizeRotate
# 1.73 10-11-06  forced consolidation to be both AVERAGE and MAX
# 1.74 04-24-07  added strict ACL compilation
# 1.75 04-26-07  added flow-lists and fixed a bunch of annoyances
# 1.76 05-15-07  'directory cache', autoexporter, reparsing of same file, nobucket info, alias cache
# 1.77 05-22-07  improved rrd batch updates, added wayward bucket purges
# 1.78 06-28-07  fixed bug with autoexporter cache
# 1.79 07-20-07  added timestamp keyword, self-healing buckets, and better snmp ifIndex collection
# 1.80 11-12-07  rrd, matrix bug fixes and better debugging
# 1.81 12-19-07  fixed AS parsing bug
# 1.82  3-01-08  lock bug
# 1.83  4-03-08  default source directory
# 1.84  4-30-08  set max IP interfaces to poll at once = 20
# 1.85  5-14-08  now loads autoexporters from multiple tmpDir directories
# 1.86  5-28-08  added 'exact=' for subnet matrices and fixed bug with in/out
# 1.87  5-29-08  added packed rrd support
# 1.88  8-05-08  fixed bucket purge and rrd creation; added bucket windows and temp directory check
# 1.89  8-18-08  added kbps/mbps/gbps and ecn to ACLs
# 1.90  8-29-08  added perl5.10 fix
# 1.91 10-27-08  snmp cache freshness fix
# 1.92  1-08-09  fixed bad bucket issue
# 1.93 09-21-09  fixed bug with multiple ACL's being (paren'd)
# 1.94 05-28-10  added 'exporter no-unknown-interfaces' directive, and summary counters for both unknown exporters and interfaces
# 1.95 09-21-10  added '-skipsnip' option to avoid all SNMP polling during config parsing.
# 1.96 01-27-11  fixed host-list issue with net-patricia updates
# 1.97 09-08-11  added ACL map structure. Also added ACL 'append' keyword
# 1.98 09-21-11  cleaned up config parsing
# 1.99 10-05-11  added support for rrdcached via RRDCACHED_EXPORTER environment variable
# 2.00 10-06-11  release candidate
# 2.01 12-02-11  "use strict" !
# 2.02  2-07-12  support for in/out ACLs on if-matrix files when input/output interface are the same
# 2.03  2-10-12  added static SNMP interface definitions and manual in/out processing override
# 2.04  2-17-12  added support for multiple community strings and exporter name changes
# 2.05  2-28-12  fixed tabulation bug with forced interface in/out processing
# 2.06  3-01-12  changed interface cache behavior to better suit SMP deployments
# 2.07  3-12-12  wanted optimizations for certain bucket conditions
# 2.08  3-21-12  added AutoClock capabilities; fixed RRD issue with sparsely-updated data; cleaned up bucket handling
# 2.09  4-30-12  adjusted autoClock algorithm (removed flow weighting)
# 2.10  5-14-12  fixed bugs with &calcFooBackupBucket and %exporterClockSkew
# 2.11  6-06-12  improved rrdcached error checking
# 2.12  8-02-12  fixed issue with large flow file time gaps in bucket mode
# 2.13  8-07-12  added support for Net::SNMP, including SNMPv3
# 2.14  9-28-12  Net::Patricia eval workaround; added regexp-defined RRD parms
# 2.15 11-12-12  fork configuration (SMP)
# 2.16 01-21-13  rrdBatchUpdater delay bug
# -------------------------------------------------------------------------

use Cflow qw(:flowvars find);	# for reading Cflowd data files
use Socket;			# for socket functions
use POSIX ":sys_wait_h";	# for strftime
use RRDs;			# RRDTOOL stuff
use Time::Local;		# need the timelocal function
use Storable;
use IO::Select;
use Net::Patricia;
use Net::SNMP qw(:snmp);
use strict;			# 
use List::Util 'shuffle';	# included with perl 5.8
no strict "refs";		# concession

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

# -------------------------------------------------------------------------
# start of constants and global data structures -- everything good should be set in flowage.cfg.
# -------------------------------------------------------------------------

sub pwd { chomp($_ = `pwd`); return $_; }		# return current directory

# ----- identify the full path and filename of this script
our $scriptName;

if ($0 =~ /^\//) { $scriptName = $0; }
elsif ($0 =~ /^\.\/(.*)/) { $scriptName = &pwd . "/$1"; }
else { $scriptName = &pwd . "/$0"; }

# ----- identify the full path of where this script is located
our $scriptDir = (($scriptName =~ /^(.*)\/[^\/]+$/) ? $1 : "/");

# ----- default data directory = wherever this script was run from
our $dataDir = $scriptDir;

# ----- default source directory
our $sourceDir = $scriptDir;

# ----- default temp directory
our $stateDir = (-d "/tmp") ? "/tmp" : $scriptDir;

# ----- list of encountered temp directories
our %stateDirs = ( $stateDir => 1 );

# ----- default interface cache directory
our $ifCacheDir;

# ----- default config file (may be changed by command-line switch)
our $configFile = "$scriptDir/flowage.cfg";

# ----- default index file to write
our $indexFile;

# ----- default periodicity of execution (must match flow-tools/cflowd). Defined system-wide in /etc/webview.conf
$period = 300 if (! defined $period);

# ----- default maximum flow length (this is worst-case; 30 minutes is the default on cisco routers)
our $maxFlowAge = 1800;

# ----- AutoClock: exporters with flow timestamps this far away from the average of all flows will be "good." Otherwise they will be "skewed."
our $fudgeFlowTime = 30;

# ----- AutoClock: exporters with flow timestamps this far away from the container flow file's timestamp will be marked as "messed up."
our $fudgeFlowBallpark = 86400;

# ----- misc globals
our $clickMode = "strict-other";
our $noUnknownExporters = 0;
our $noUnknownInterfaces = 0;
our $hierarchicalDir = 0;		# whether directories are hierarchical or flat

# ----- default log file name (blank = output to screen)
our ($logFile, $newLogFile);
our @logBuffer;			# logbuffer holds msgs before config file has been read
our $logFileMaxSize;		# max size of log file (0 = grow infinitely)

# ----- log levels
our $LOG_SUPERDEBUG = 0;
our $LOG_DEBUG = 1;
our $LOG_TRIVIA = 2;
our $LOG_INFO = 3;
our $LOG_ERROR = 4;

# ----- array offsets for certain values
our $BYTE_IN_COUNTER = 0;
our $BYTE_OUT_COUNTER = 1;
our $PKT_IN_COUNTER = 2;
our $PKT_OUT_COUNTER = 3;
our $FLOW_IN_COUNTER = 4;
our $FLOW_OUT_COUNTER = 5;
our $IP_IN_COUNTER = 6;
our $IP_OUT_COUNTER = 7;

our $clock_ticks = POSIX::sysconf( &POSIX::_SC_CLK_TCK );

# ----- maximum number of buckets
our $DEFAULT_STEP = 300;			# default RRD file step

# ----- name of the "Other" category
our $OTHER = 'Other';

# ----- flow output object (foo) types for datafiles
our $foo_null = 0;			# do nothing with this data
our $foo_rrd = 1;			# RRD file
our $foo_text = 2;			# ASCII text file
our $foo_csv = 3;			# ASCII file in CSV format (comma-delimited)
our $foo_flow = 4;			# NETFLOW data file

# ----- determine endian-ness of this machine
our $BIG_ENDIAN = (pack('N', 0x12345678) != pack('L', 0x12345678));

# ----- load predefined base variables including internet names and constants
our (%cisco_tcp_services, %cisco_udp_services, %cisco_permit, %cisco_range, %cisco_ipaddr, %cisco_protocols, %cisco_optionals, %cisco_icmp,
	%cisco_precedence, %cisco_tos, %cisco_dscp, %cisco_ecn, %cisco_tcp_flags, %cisco_ipprotocols);
our (%dynamic_keywords, %facl_expansion, %string_protocol, %string_port, %string_ip, %string_tos, %string_as, %string_if, %colors );

&baseVariables;

# ----- specify the amount of log detail you want (LOG_SUPERDEBUG, LOG_DEBUG, LOG_TRIVIA, LOG_INFO, LOG_ERROR)
our $logFileLevel = $LOG_TRIVIA;

# ----- enable/disable flowage code.
our $OPTIMIZE_ACLS = 1;		# optimize ACLs? default = yes. disable if optimization appears buggy
our $OPTIMIZE_ACL_USAGE = 1;	# optimize the usage of ACLs in the wanted() routine.

# ----- memory overload protection
our $MEM_OVERLOAD_PROTECTION = 0;	# set this to 1 to enable memory overload protection (unix only)
our $MEM_OVERLOAD_LIMIT = '40%';	# set this value to the threshold
our $MEM_OVERLOAD_MASK = '0x3ffff';	# check memory every 256k flows
our $MEM_OVERLOAD_CONDITION = 0;	# state variable, initialize at 0

# ----- use unix 'ps -eo args' search instead of lock file
our $useUnixPS = 0;

our $rrdBatchCounter = 1;
our $RRD_DONE = 0;

# ----- how long should one instance of flowage run for?
our $herniaTime = 7200 * 1;

# ----- default DNS settings
our $dnsTimeout = 5;
our $dnsPacing = 10;
our $dnsMaxHandles = 240;
our $dnsToken = "dNs";
our (%dnsTable, %dnsAuto, $dnsFile, @dnsServers);

# ----- fork options
our ($forkMax, $forkHash, $forkPID, $processLock);

our $FORK_HEALTHCHECK = 10;		# wait 10 seconds on I/O checks
our $FORK_UNRESPONSIVE = 900;		# 900 seconds of inactivity -- kill it!

# ----- interface collection tracking
our $globalLoadInterfaceSNMP = 0;
our $globalLoadInterfaceCache = 0;
our $globalLoadInterfaceSkip = 0;
our $globalLoadInterfaceFail = 0;

# ----- auto-exporter tracking
our $autoExporterTrie = new Net::Patricia;

# ----- bucket variables
our (%buckets, %baseBucket);

# ----- rrdcached in use?
our $rrdcached = $ENV{'RRDCACHED_ADDRESS'};
our $rrdCachedSocketOpen;
our $rrdBadStep = 0;

# ----- flow-import pipe command
our $fpipe = '| /usr/local/netflow/bin/flow-import -f 0 -V 5 -z 0 2>/dev/null >%s';

# ----- track subnetTries
our %subnetTries;

# ----- SNMP session parameters
our %snmpSessions;

our $FACL = {};		# hash of facl information

our @fooOrdered;
our @fooFileIndex;	# files in indexed order

# ----- set default color for 'Other' categories in index file output
our %acl_color = ( $OTHER => &validColor("pink") );

# ----- create a special ACL to hold localNextHops
our $localNextHops = "ACL_localNextHops";

# ----- global depth of recursion routines
our $includeDepth = 1;
our $aclOptimizeDepth = 1;

# ----- debug level
our ($debug, $deepDebugExpression);

our ($infiniteLoop, $checkConfig, $noSNMP, $testMode);
our ($tempcheckFile, $watchFile, $bucketFile, $hostlistFile, $daclFile, $faclFile, $lockFile);
our (@sourceFiles);

our ($papafoo, %papaFoo);	# keeps track of the stem datafile (lots of recursion going on)
our $code;			# used by recursive routines to build a chunk of code
our %groups;			# track the groups
our %foos;			# flow objects - each refers to a rrd file, basically
our %mapOrder;			# keep track of the order of mappings
our (%map_list, %acl_list);	# maps and acls seen
our (%exporterName, %exporterIP); # keep track of every flow source
our %exporterInout;		# force inout processing on exporter
our (%exporterClockGood, %exporterClockSkew, %exporterClockBad, %exporterClockLongFlows);		# tabulator hashses
our $timeStamp;			# global timestamp of current file (may be influenced by several factors)
our @racls;			# list of all dynamic ACL's
our @t_localNextHops;		# master list of nexthops
our (%referenced_dacl, %available_dacl);	# dynamic ACL's (source/dest IP only)
our (%referenced_facl, %available_facl);	# flow tracking (any flow value)

# parameters for each file
our %fileBucket;		# bucket mode
our %fileStep;			# step
our %fileIPTracking;		# IP tracking enabled
our %fileTimeStamp;		# timestamp calc method
our %fileAutoClock;		# auto clock handling
our %filePrefix;		# filename prefix
our %fileSuffix;		# filename suffix
our %fileType;			# type
our %fileMaxSize;		# for text files
our %fileFlowDir;		# source directory from file
our %filePacked;		# if the rrd file is packed (more efficient, less flexible)
our %fileConsolidation;		# rrd file creation properties
our %fileSpecial;		# if flows hit a category, write them raw to this file
our %fileTimestamp;		# how to determine timestamp of each flow
our %fileOrig;			# track original file name (for recursive routines)
our %fileDesc;			# description
our (%fileInACL, %fileOutACL);	# determine flow direction
our %fileBucketHigh;		# keep track of max
our %fileBucketLow;		# and min bucket values
our %highestBucket;		# show who the current highest bucket user is (for error reporting)
our %fileOpened;		# has a (text) file been opened for writing?

our (%watch_getcha, %watch_gotcha);	# track files to be processed
our $lastFileName;		# track progress

our (%lineCount, %nextLine);	# for parsing files

our %fooMatrices;		# if a foo has matrices or not
our %fooMatrixCount;		# if counters are enabled or not
our (%fooCode, %fooACL);	# compiled code for each file, and conditional ACL
our %fooBackupBucket;		# used in case a bucket can't be determined

our @indexHeader;		# stores index info prior to saving it

our %matrices;			# keep track of every matrix variable
our %matrixDescriptions;	# and their properties
our %matrixType;
our %matrixAliases;
our %matrixAuthorization;
our %matrixSpeeds;
our (%matrixCount, %matrixMask, %matrixAuto, %matrixBits, %matrixExact, %matrixXForm);

our ($fileWindowPre, $fileWindowPost);		# how far before/after current we keep buckets active (handle bad flow-expire times)

our %bulkDebugHash;		# used to reduce frequency of log messages

our (%cmatrix_in, %cmatrix_out);	# keep track of flow counters

our ($rrdbatchpid, %kidpids);	# keep track of the rrd batch handler and fork pids
our ($FATAL_ERROR, $GRACEFUL_CLOSE);	# whether to bail or not
our (%aclCode, %aclCodeUnused);	# store the logic for each ACL

our ($fileFlowCounter, $fileFlowMax, $fileFlowFirst, $fileFlowLast);
our ($flowCounter, $localFlowCounter);

my @trackExporterKeys = qw/noBucket noExporters noInterfaces clockGood clockBad clockSkew clockLongFlows/;
our $trackExporters = {}; 	# enable tracking or not
our ($noBucketFlowCounter, %noBucketFlowCounterValues);
our ($noExporterFlowCounter, %noExporterFlowCounterValues);
our ($noInterfaceFlowCounter, %noInterfaceFlowCounterValues);

our ($realtime1, $realtime2);	# benchmark handler

our %snmpoid = ( qw/
	sysName			1.3.6.1.2.1.1.5.0
	sysUpTime		1.3.6.1.2.1.1.3.0
	ifTableLastChange	1.3.6.1.2.1.31.1.5.0
	ifNumber		1.3.6.1.2.1.2.1.0

	ipAdEntIfIndex		1.3.6.1.2.1.4.20.1.2
	ifIndex			1.3.6.1.2.1.2.2.1.1
	ifDescr			1.3.6.1.2.1.2.2.1.2
	ifSpeed			1.3.6.1.2.1.2.2.1.5
	ifAlias			1.3.6.1.2.1.31.1.1.1.18
/ );

# -------------------------------------------------------------------------
# end of constants and globals
# -------------------------------------------------------------------------


# -------------------
# check the command-line for anything interesting

if (@ARGV > 0) {			# testMode
	while ($_ = shift @ARGV) {
		if (/^-+debug$/) { 			# enable debug
			$debug = 1;
			$logFileLevel = $LOG_DEBUG;
			$logFileLevel = $LOG_SUPERDEBUG if (/^-debug!/);
		}
		elsif (/^-+deep$/) {			# 'perldoc flowdumper' and look at the -e option
			$deepDebugExpression = shift @ARGV;
		}
		elsif (/^-+wait$/) {			# set to run in infinite loop mode
			$infiniteLoop = 1;
		}
		elsif (/^-+check$/) {			# check config and exit
			$checkConfig = 1;
		}
		elsif (/^-+(snmp|nosnmp)$/) {		# skip SNMP validation
			$noSNMP = 1;
		}
		elsif (/^-+daemon$/) {			# rrdcached
			$rrdcached = shift @ARGV;
		}
		elsif (/^-f(.*)/) {			# set the config file name
			$configFile = $1 || shift @ARGV;
			if (! -f $configFile) {
				if (! -f "$scriptDir/$configFile") {
					&logit($LOG_ERROR, "config file not found: $configFile");
					exit 1;
				}
				$configFile = "$scriptDir/$configFile";
			}
		}
		elsif (/^-+(\?|help)$/) {		# help screen
			print <<EOT;
flowage.pl 2.15 (craig.weinhold\@cdw.com)

 usage: flowage.pl [--wait] [--check] [--nosnmp] [--daemon <rrdcached>] [-f <config file>] [flow [flow] ...]

Process one or more netflow data files according to the config file
(which defaults to 'flowage.cfg' in the current directory).

With no files specified, it searches for flows.* or ft.* in the data or
watch directory. If using a data directory, each processed file is
moved to the save directory.  If you specify '--wait', then the script
executes in an infinite loop, waiting for files to process. Without
'--wait', the script exits once all files have been processed (suitable
for use with cron). A per-config lock file is also maintained to ensure
that multiple instances of flowage can't run at the same time.

If you specify a flow file or directory on the command line, then flowage
runs in "test" mode where it processes the files but does not manipulate
the flow files or update RRD files. It does update text/flow datafiles.

The --check option validates the config file and exits immediately.

The --nosnmp option prevents the SNMP interrogation of netflow sources.

The --daemon option specifies the address of rrdcached, if used.
EOT
			exit 0;
		}
		elsif (-f $_) {				# flow file -- run in test mode
			push(@sourceFiles, $_);
			$testMode = 1;
		}
		elsif (-d $_) {				# directory of flow files
			opendir(DIR, $_);
			my $count = 0;
			while ( my $x = readdir(DIR) ) {
				$count++;
				push(@sourceFiles, "$_/$x");
			}
			closedir(DIR);
			print "adding directory $_ with $count files\n";
			$testMode = 1;
		}
		else {					# error
			&logit($LOG_ERROR, "invalid \@ARGV or file not found: $_");
			exit 1;
		}
	}
}

print <<EOT if ($testMode);
Running in test mode-- source files will not be moved and rrd files will not
be updated. Other file types (text and flow) will be written as usual.

EOT

# ----- load directories from configFile ("quick" mode)

my $BOMB;

if (my $errors = &readConfig($configFile, 1)) {			# QUICK, load file location info
	$BOMB = "$configFile has $errors errors";
}
else {
	if (! $checkConfig) {
		$logFile = $newLogFile			if (defined $newLogFile);
		$logFile = "$dataDir/$logFile"		if (($logFile) && ($logFile !~ /^\//));
	}

	# now that we have stateDir defined, figure out a bunch of temp files...
	$tempcheckFile = "$stateDir/flowage.tmp";
	$watchFile = "$stateDir/watchdir.txt";
	$bucketFile = "$stateDir/flowage-buckets.bin";
	$hostlistFile = "$stateDir/flowage-hosts.bin";
	$daclFile = "$stateDir/flowage-dacls.bin";
	$faclFile = "$stateDir/flowage-facls.bin";
	$lockFile = "$stateDir/flowage.lck";
	$dnsFile = "$stateDir/dns.txt";

	if ((-f $tempcheckFile) && (! $checkConfig)) {
		open(IN, $tempcheckFile); chomp(my $tempcheck = <IN>); close(IN);
		if ($tempcheck ne $configFile) {
			&logit($LOG_ERROR, "The temp directory $stateDir has been claimed the config file $tempcheck.");
			$BOMB = "If this is in error, delete the file $tempcheckFile.";
		}
	}

	if (! -d $sourceDir) {
		$BOMB = "invalid \$sourceDir in config: $sourceDir";
	}
	elsif (! -d $dataDir) {
		$BOMB = "invalid \$dataDir in config: $dataDir";
	}
}

if ( (! $BOMB) && (! $checkConfig) && (! $testMode) ) {			# not running a config check? grab the lock file!

	if (! &grabLock($lockFile)) {
		if (! $useUnixPS) {
			my $lockFileAge = time - (lstat($lockFile))[9];			# how old is this file?
			&logit($LOG_INFO, "could not grab lock file $lockFile (age=$lockFileAge seconds)")
				if ( $lockFileAge > ($herniaTime * 2) );
		}
		exit 1;
	}

	&logit($LOG_INFO, "----- start of flowage.pl");
}

# read the config file, for real

if (! $BOMB) {
	if (my $errors = &readConfig($configFile)) {
		$BOMB = "$configFile has $errors errors";
	}
	elsif (! &aclCompiler) {		# compile all ACLs
		$BOMB = "Unable to eval ACLs";
	}
	elsif (! &fooCompiler) {		# compile foo logic
		$BOMB = "Unable to compose processing code";
	}
}

if ($BOMB) {		# ensure that the bomb message gets into the log file
	&logit($LOG_ERROR, $BOMB);
	&logit($LOG_ERROR, "quitting...");
	&releaseLock($lockFile);
	exit 1;
}

&logit($LOG_DEBUG, "scriptDir = $scriptDir");
&logit($LOG_DEBUG, "sourceDir = $sourceDir");
&logit($LOG_DEBUG, "dataDir = $dataDir");
&logit($LOG_DEBUG, "stateDir = $stateDir");

$indexFile = "$dataDir/$indexFile"	if (($indexFile) && ($indexFile !~ /^\//));

if (defined $indexFile) {				# write an index file with group/member names
	open(OUT, ">$indexFile");

	foreach (@indexHeader) {
		print OUT $_;
	}

	print OUT "\n[ACLs]\n";
	foreach (sort keys %aclCode) {
		/^(.*?)(_auto|)$/;				# nicen auto-generated ones
		print OUT "$1\t$aclCode{$_}\n";
	}
	foreach (sort keys %aclCodeUnused) {
		/^(.*?)(_auto|)$/;				# nicen auto-generated ones
		print OUT "$1\t$aclCodeUnused{$_}\n";
	}

	foreach my $matrix (keys %matrices) {		# for each matrix variable
		if (defined $matrixDescriptions{$matrix}) {
			print OUT "\n[Descriptions=$matrix]\n";
			foreach (@{$matrixDescriptions{$matrix}}) { print OUT (($_ eq $dnsToken) ? $dnsFile : $_) . "\n"; }
		}
		if (defined $matrixAliases{$matrix}) {
			print OUT "\n[Aliases=$matrix]\n";
			foreach (@{$matrixAliases{$matrix}}) { print OUT "$_\n"; }
		}
		if (defined $matrixAuthorization{$matrix}) {
			print OUT "\n[Authorization=$matrix]\n";
			foreach (@{$matrixAuthorization{$matrix}}) { print OUT "$_\n"; }
		}
		if (defined $matrixSpeeds{$matrix}) {
			print OUT "\n[Speeds=$matrix]\n";
			foreach (@{$matrixSpeeds{$matrix}}) { print OUT "$_\n"; }
		}
	}

	close(OUT);
}

# ---- this would be where we prepare thread arrays, but we run everything 
#      in one array right now.

# %papafoo needs to be extended for maps

our @fooFileArray = keys %papaFoo;	# an array of all the little files
&wantedCompiler;			# compile the wanted subroutine

&saveDacls($hostlistFile, sort keys %subnetTries);	# save host-list files
&saveFacls;

&bulkDebug("fooFileArray", "debug_foofilearray.txt", "\@fooFileArray = @fooFileArray" ) if ($debug);

&logit($LOG_INFO, "Exporters: cache=$globalLoadInterfaceCache snmp=$globalLoadInterfaceSNMP skip=$globalLoadInterfaceSkip fail=$globalLoadInterfaceFail");

&logit($LOG_DEBUG, "Tracking " . join(', ', map { $_ . '[' . $trackExporters->{$_} . ']' } keys %$trackExporters));

# ---- Exit if in test mode
if ($checkConfig) {
	&logit($LOG_ERROR, "----- configuration file '$configFile' looks OK!");
	exit 0;
}

open(OUT, ">$tempcheckFile"); print OUT "$configFile\n"; close(OUT);

map { $SIG{$_} = \&sigHandler } qw/INT TERM QUIT HUP/;

sub sigquick
{
	my $sig = shift;
	if ($sig =~ /(INT|QUIT|HUP)/) {	&logit($LOG_ERROR, "Caught a SIG$sig--shutting down gracefully");	return 0; }
	else {				&logit($LOG_ERROR, "Caught a SIG$sig--shutting down quickly");		return 1; }
}

sub sigHandler {
	my $sig = shift;

	if (! $GRACEFUL_CLOSE) {
		if (! &sigquick($sig)) { $GRACEFUL_CLOSE = 1; return; }
	}
	else {
		&logit($LOG_ERROR, "Caught another SIG$sig--shutting down quickly");
	}

	if (%kidpids) {
		&logit($LOG_ERROR, "Waiting on worker forks (pids " . join(', ', map { $kidpids{$_}->{pid} } keys %kidpids) . ")...");
		map { kill 15, $kidpids{$_}->{pid} } keys %kidpids;
		map { waitpid($kidpids{$_}->{pid}, 0); } keys %kidpids;
		undef %kidpids;
	}

	if (! $rrdcached) {
		&logit($LOG_ERROR, "Waiting on rrdBatchUpdater (pid $rrdbatchpid)...");
		kill 2, $rrdbatchpid;
		waitpid($rrdbatchpid, 0);		# may take some time
	}

	&releaseLock($lockFile);
	exit 0;
}

sub sigHandlerFork {		# used by forked processes
	my $sig = shift;
	exit 0 if (&sigquick($sig));
}

sub sigHandlerRrd
{
	my $sig = shift;
	&logit($LOG_DEBUG, "Caught a SIG$sig--shutting down rrdBatchUpdater...");
	$RRD_DONE = 1;
};


# -------------------
# figure out how RRD files will be updated...

if ($rrdcached) { # if rrdcached info is available, see if it's working
	if (! &rrdCachedOpen($rrdcached) ) { undef $rrdcached; }
	else {
		&logit($LOG_INFO, "RRDCACHED: connected at $rrdcached");
	}
}

if (! $rrdcached) {
	# fork off the RRD update process unless running in rrdcached mode
	$rrdbatchpid = &rrdBatchUpdater;

	if (! defined $rrdbatchpid) {
		&logit($LOG_ERROR, "Could not fork RRD updater process");
		exit 1;
	}
}

# -------------------
# create files if necessary

&grabOldestFileStamp;
our $errCount = 0;

foreach my $foo (keys %papaFoo) {
	my $pfoo = $papaFoo{$foo};			# master foo
	next if (($fileType{$pfoo} == $foo_rrd) || (defined $fooMatrices{$pfoo})); # skip files created on-the-fly

	if (! &createFile(&hierarchical($filePrefix{$pfoo} . $foo . $fileSuffix{$pfoo}),
		$fileType{$pfoo}, $fileMaxSize{$pfoo})
	)  {
		$errCount++;
	}
}

exit 1 if ($errCount);

# ----------------------------------------------------------------------------
#                              M A I N   L O O P
# ----------------------------------------------------------------------------

$herniaTime += time;

our @sourceFiles;

MAINLOOP: while (1) {				# infinite loop
	if (@sourceFiles == 0) {			# no files? whatever shall we do?
		last if ($testMode);

		@sourceFiles = &readWatchDir($sourceDir);

		if (@sourceFiles == 0) {			# still no files?
			&fileSizeRotate($logFile, $logFileMaxSize);

			last if (! $infiniteLoop);			# quit if not an infinite loop
			sleep 30;					# take a nap
			next;
		}
	}

	foreach my $fName (@sourceFiles) {
		&logit($LOG_INFO, "reading $fName");
		&doAutoClock($fName) if (%fileAutoClock);

		if ( $forkMax <= 1 ) {			# single process
			&mainProcessing($fName);
		}
		else {					# multiple processes. <sigh>
			&bench;
			my $fc=0; my $lfc=0; my $nbfc=0; my $nefc=0; my $nifc=0;	# total counters

			for $forkPID (1 .. $forkMax) {
				my($pid, $fh);

				if (! defined ($pid = open($fh, "-|"))) {		# create kids
					$FATAL_ERROR = 1;
					&logit($LOG_ERROR, "Unable to fork child process: $!");
					last MAINLOOP;
				}

				if (! $pid) {							# ... kid code here ...
					map { $SIG{$_} = \&sigHandlerFork } qw/INT TERM QUIT HUP/;
					$rrdBatchCounter += $forkPID - 1;
					undef $logFile;			# use STDOUT to parent
					&mainProcessing($fName);
					$| = 1;
					&logitraw("CHILD DONE $flowCounter $localFlowCounter $noBucketFlowCounter $noExporterFlowCounter $noInterfaceFlowCounter");
					exit $FATAL_ERROR;
				}

				$kidpids{$forkPID} = {					# remember the kid
					'pid' => $pid, 'fh' => $fh, 'buf' => '', 'lastio' => time,
				};
			}

			while (%kidpids) {		# wait and worry

				my $s = IO::Select->new( map { $kidpids{$_}->{fh} } keys %kidpids);
				my @fhs = $s->can_read($FORK_HEALTHCHECK);					# check for input

				foreach my $fh (@fhs) {
					my $id; map { $id = $_ if ($kidpids{$_}->{fh} eq $fh) } keys %kidpids;
					if (! exists $kidpids{$id}) {
						&logit($LOG_ERROR, "Received data on unknown child filehandle $fh"); last MAINLOOP;
					}

					my $kp = $kidpids{$id};
					$kp->{lastio} = time;
					my $bytes = sysread( $kp->{fh}, $kp->{buf}, 4096, length($kp->{buf}) );
					$kp->{buf} =~ s/^(.*?\n)/&logitraw($1)/e;

					if ($kp->{buf}  =~ /^CHILD DONE (\d+) (\d+) (\d+) (\d+) (\d+)/) {
						$fc += $1; $lfc += $2; $nbfc += $3; $nefc += $4; $nifc += $5;

						waitpid($kp->{pid}, 0);
						$FATAL_ERROR |= ($? >> 8);
						delete $kidpids{$id};
					}
				}
				next if (@fhs);

				foreach (keys %kidpids) {				# reap awol and/or unresponsive kids
					if (! exists $kidpids{$_}->{pid}) {
						&logit($LOG_ERROR, "Fork $_ died prematurely");
						delete $kidpids{$_};
					}
					elsif ( (time - $kidpids{$_}->{lastio}) > $FORK_UNRESPONSIVE) {
						&logit($LOG_ERROR, "Fork $_ has been unresponsive for $FORK_UNRESPONSIVE seconds. Terminating.");
						kill 15, $kidpids{$_}->{pid};
					}
				}

				while ( ( my $kid = waitpid(-1, WNOHANG) ) > 0) {	# check for awol
					my $id; map { $id = $_ if ($kidpids{$_}->{pid} eq $kid) } keys %kidpids;
					if (! exists $kidpids{$id}) {
						&logit($LOG_ERROR, "Unexpected child exit on pid $kid"); last MAINLOOP;
					}

					delete $kidpids{$id}->{pid};
				}
			}

			my $duration = &bench || 1;
			$forkPID = 'total';
			&logit($LOG_INFO, "processed $fc flows, " .
				"$lfc localFlows, " .  "$nbfc no-bucket flows, " .
				"$nefc no-exporter flows, and $nifc no-interface flows " .
				"in $duration seconds (" .
				sprintf("%.1f", $fc / $duration) . " per sec)");
			undef $forkPID;
		}

		$rrdBatchCounter += ($forkMax || 1);

		&saveWatchData if (! $testMode);

		last MAINLOOP if ( ($FATAL_ERROR) || ($GRACEFUL_CLOSE) );
	}

	undef @sourceFiles;				# zap the sourceFiles back to the stone age

	last if ((! $infiniteLoop) && (time > $herniaTime));
}

# ----------------------------------------------------------------------------
#                       E N D   O F   M A I N   L O O P
# ----------------------------------------------------------------------------

if ($FATAL_ERROR) {
	&logit($LOG_ERROR, "Operation aborted due to fatal error")
}

if (! $rrdcached) {
	&logit($LOG_DEBUG, "Waiting for piper to end") if ($debug);
	kill 2, $rrdbatchpid;
	waitpid($rrdbatchpid, 0);		# may take some time
}

&releaseLock($lockFile) if (! $testMode);

&logit($LOG_TRIVIA, "----- end of flowage.pl");
exit 0;

# ----------------------------------------------------------------------------
#                       M A I N   P R O C E S S I N G
# ----------------------------------------------------------------------------
sub mainProcessing
{
	my $fName = shift;

	$processLock = 0;
	&loadDacls;						# load dynamic (temporal) data
	&loadFacls;						# load facls
	&loadBucketCache;					# load bucket cache

	if ($fileFlowFirst) { 		# see if buckets are in the right ballpark
		my $err;
		foreach my $pfoo (keys %fileBucket) {
			next if (! exists $baseBucket{$pfoo});

			my $bucketStamp = $baseBucket{$pfoo} * $fileBucket{$pfoo};		# buckets start at this timestamp
			if ( ($bucketStamp + $period) < ($fileFlowFirst - $period) ) {
				$err = "Note: Flow file timestamps have skipped ahead by more than " . ($period * 2) . " seconds; resetting buckets.";
			}
			elsif ($bucketStamp > ($fileFlowLast + $period) ) {
				$err = "Note: Flow file timestamps have skipped backwards; expect RRD \"one-second-step\" messages.";
			}
		}
		if ($err) {
			&logit($LOG_INFO, $err);

			#quick purge of all bucket information
			%buckets = ( );
			%baseBucket = ( );
			%highestBucket = ( );
		}
	}

	$fileFlowCounter = 0;
	$flowCounter = 0;			# global
	$localFlowCounter = 0;			# global

	$noBucketFlowCounter = 0;		# global
	$noExporterFlowCounter = 0;		# global
	$noInterfaceFlowCounter = 0;		# global

	undef %noBucketFlowCounterValues;
	undef %noInterfaceFlowCounterValues;
	undef %noExporterFlowCounterValues;

	&bench;
	&openAllFiles;

	Cflow::find(\&wanted, \&perfile, $fName);
	$processLock = 1;

	$flowCounter += $fileFlowCounter;
	&flushData;					# flush last file

	map { $noBucketFlowCounter += $_ } values %noBucketFlowCounterValues if ($trackExporters->{noBuckets});
	map { $noExporterFlowCounter += $_ } values %noExporterFlowCounterValues if ($trackExporters->{noExporter});
	map { $noInterfaceFlowCounter += $_ } values %noInterfaceFlowCounterValues if ($trackExporters->{noInterfaces});

	my $duration = &bench || 1;

	&logit($LOG_INFO, "processed $flowCounter flows, " .
		"$localFlowCounter localFlows, " .  "$noBucketFlowCounter no-bucket flows, " .
		"$noExporterFlowCounter no-exporter flows, and $noInterfaceFlowCounter no-interface flows " .
		"in $duration seconds (" .
		sprintf("%.1f", $flowCounter / $duration) . " per sec)");

	&logExpList("Exporters w/ no-bucket flows", undef, \%noBucketFlowCounterValues, keys %noBucketFlowCounterValues) if ($trackExporters->{noBuckets});
	&logExpList("Exporters w/ no-interface flows", undef, \%noInterfaceFlowCounterValues, keys %noInterfaceFlowCounterValues) if ($trackExporters->{noInterface});
	&logExpList("Exporters w/ no-exporter flows", undef, \%noExporterFlowCounterValues, keys %noExporterFlowCounterValues) if ($trackExporters->{noExporter});

	if (! $testMode) {
		&closeAllFiles;
		&saveBucketCache;			# save bucket cache
		&saveDacls(&forkFileName($daclFile), &getDynamicList);		# save those we are responsible for
		&saveFacls;
		&dnsResolver if (%dnsTable);
		my $duration = &bench || 1;
		&logit($LOG_DEBUG, "cleanup processing took $duration seconds");
	}
	undef $timeStamp;
}

sub logExpList
{
	my $label = shift @_;
	my $max = shift @_;
	my $hp = shift @_;

	my @vals = map { $exporterName{$_} . '[' . &unhackIP($_) . ']' . ( (ref($hp) eq 'HASH') ? '=' . $hp->{$_} : '') } sort {$a <=> $b} @_;
	my $count = scalar @vals;
	$label .= ": $count";
	my $sep = " -- ";

	if ((defined $max) && ($max == 0)) {
		&logit($LOG_INFO, $label);
	}
	elsif ((defined $max) && (@vals > $max)) {
		&logit($LOG_INFO, $label . $sep . join(', ', splice(@vals, 0, $max), 'and ' . ((scalar @vals) - $max) . ' others'));
	}
	elsif (@vals > 1) {
		&logit($LOG_INFO, $label . $sep . join(', ', splice(@vals, 0, -1), "and @vals"));
	}
	elsif (@vals) {
		&logit($LOG_INFO, $label . $sep . $vals[0]);
	}
}

sub loadBucketCache
{
	my $file = &forkFileName($bucketFile);
	open(BUCKETCACHE, $file) || return;
	&logit($LOG_DEBUG, "Loading bucket cache ($file)");
	%baseBucket = %{Storable::fd_retrieve(\*BUCKETCACHE)};
	%buckets = %{Storable::fd_retrieve(\*BUCKETCACHE)};
	close(BUCKETCACHE);

	&dumpBucketCacheInfo if ($debug);
}

sub saveBucketCache
{
	my $file = &forkFileName($bucketFile);
	&dumpBucketCacheInfo if ($debug);

	%baseBucket = ( ) if (! %baseBucket);
	%buckets = ( ) if (! %buckets);

	if (open(BUCKETCACHE, ">" . $file)) {
		&logit($LOG_DEBUG, "Saving bucket cache ($file)");
		Storable::store_fd(\%baseBucket, \*BUCKETCACHE);
		Storable::store_fd(\%buckets, \*BUCKETCACHE);
		close(BUCKETCACHE);
	}
	else {
		&logit($LOG_ERROR, "Could not write to file $file");
	}
}

sub purgeBuckets
{
	my $purgeFoo = shift;
	my $purgeCount = 0;

	if ((%buckets) && ($fileBucket{$purgeFoo})) {		# purge buckets
		foreach (keys %buckets) {
			if (/^$purgeFoo\./) {
				$purgeCount ++;
				delete $buckets{$_};
			}
		}
		delete $baseBucket{$purgeFoo};
		delete $highestBucket{$purgeFoo};

		if (! %buckets) {
			&logit($LOG_DEBUG, "Purging all buckets");
			%buckets = ( );
			%baseBucket = ( );
			%highestBucket = ( );					# NEW
		}
		else {
			&logit($LOG_DEBUG, "Purged $purgeCount buckets from $purgeFoo");
		}
	}
	return $purgeCount;
}

# this routine reads in all cache files and tries to SNMP poll them.

sub loadAutoExporters
{
	my %autoips;

	opendir(DIR, $ifCacheDir);
	map { $autoips{&hackIP($1)} = 1 if (/^ifData.([\d\.]+)$/); } readdir(DIR);
	closedir(DIR);

	foreach my $exp ( shuffle(keys %autoips) ) {		# shuffle the list so that two parallel processes work on different exporters
		if ((! exists $exporterName{$exp}) && (my $hashp = $autoExporterTrie->match_integer($exp))) {
			my($ifs,$newExporterName) = &loadInterfaces($exp, undef, $hashp, $LOG_DEBUG);
			$exporterName{$exp} = $newExporterName;		# may be undef -- that's ok.
		}
	}
}

# ----------------------------------------------------------------------------
# Perform RRD updates in the background (batched and non-blocking to the main process)
# $stateDir/rrd-updates.$time

sub rrdBatchUpdater
{
	if (my $pid = fork()) {
		return $pid if ((! defined $pid) || ($pid > 0));
	}

	$RRD_DONE = 0;
	map { $SIG{$_} = \&sigHandlerRrd } qw/INT TERM QUIT HUP/;

	while (1) {
		sleep 2;

		my $start = time;

		opendir(DIR, $stateDir);
		my @files = grep(/^rrd-updates.\d+$/, sort readdir(DIR));
		closedir(DIR);

		my ($batchCount, $fooCount, $updateCount) = (0, 0, 0);
		my $updates = {};

		foreach my $f (@files) {
			open(IN, "$stateDir/$f");
			seek(IN, -3, 2);			# 3 bytes from eof
			$_ = <IN>;
			chomp;
			next if ($_ ne "GA");			# file is not done yet
			seek(IN, 0, 0);
		
			&logit($LOG_DEBUG, "rrdBatchUpdater reading $stateDir/$f");

			while ( <IN> ) {
				chomp;
				my($foo, @updates) = split(/\t/);

				foreach (@updates) {
					$updates->{$foo}->{$1} = $_ if (/^(\d+)\:/);	# help avoid dups
				}
			}
			close(IN);

			if ($debug) {			# save update files
				`mv $stateDir/$f $stateDir/$f.old`;
			}
			else {
				unlink("$stateDir/$f") || &logit($LOG_ERROR, "Error deleting $stateDir/$f: $!");
			}
			$batchCount++;
		}

		foreach my $foo (keys %$updates) {
			$fooCount++;
			$updateCount += scalar keys %{$updates->{$foo}};

			RRDs::update($foo, sort { $a <=> $b } values %{$updates->{$foo}});	# numerical sort works

			if (my $err = RRDs::error) { &rrdErrTabulator($foo, $err); } 
		}

		&logit($LOG_TRIVIA, "RRD Batcher took " . (time - $start) . " seconds for " .
			"$batchCount/$fooCount/$updateCount batches/files/updates")
			if ($updateCount);

		&rrdErrReport;

		last if ($RRD_DONE);
	}

	&logit($LOG_DEBUG, "rrdBatchUpdater done");
	exit 0;
}

sub rrdErrTabulator
{
	my($foo, $err) = @_;

	if ($err =~ /minimum one second step/) {
		print STDERR "$foo: $err\n";
		$rrdBadStep++;
	}
	else {
		&logit($LOG_ERROR, "RRD UPDATE error $foo: $err");
	}
}

sub rrdErrReport
{
	&logit($LOG_INFO, "Received $rrdBadStep out-of-order RRD errors (check STDERR for details)") if ($rrdBadStep);
	$rrdBadStep = 0;
}

# ----------------------------------------------------------------------------
# recurse through the directory tree, finding any flow files that haven't
# been processed. uses globals %watch_getcha and %watch_gotcha
# ----------------------------------------------------------------------------
sub readWatchDir
{
	my(@files);
	undef %watch_getcha;

	&loadWatchData if (! %watch_gotcha);
	&readWatchDirStuff($_[0]);

	# first, delete keys for files that no longer exist
	foreach (keys %watch_gotcha) {
		delete $watch_gotcha{$_} if (! defined $watch_getcha{$_});
	}

	foreach (sort { (stat($watch_getcha{$a}))[9] <=> (stat($watch_getcha{$b}))[9] } keys %watch_getcha) {
		if (! defined $watch_gotcha{$_}) {
			$watch_gotcha{$_} = 1;

			if ($watch_getcha{$_} =~ /\.gz$/) {		# gzip'd?  oh no!
				`gzip -d -c $watch_getcha{$_} > $stateDir/$_`;
				push(@files, "$stateDir/$_");
				unlink("$stateDir/$_");
			}
			else {
				push(@files, $watch_getcha{$_});
			}

			last if (@files >= 1);		# only do 1 at a time
		}
	}
	return(@files);
}

sub readWatchDirStuff
{
	my($dir) = $_[0];
	my(@files);

	opendir(DIR, $dir);
	@files = readdir(DIR);
	closedir(DIR);

	foreach (sort {$a cmp $b} @files) {
		if ((-d "$dir/$_") && (! /^\.+$/)) {		# directory
			&readWatchDirStuff("$dir/$_");
		}
		elsif (/^(flows\..*)\.gz$/) {			# a compressed cflowd file
			$watch_getcha{$1}="$dir/$_";
		}
		elsif (/^(flows\..*)$/) {			# an uncompressed cflowd file
			$watch_getcha{$1}="$dir/$_";
		}
		elsif (/^ft-.*/) {				# a flow-tools file
			$watch_getcha{$_}="$dir/$_";
		}
	}
}

# ----------------------------------------------------------------------------
# Lock file routines
# ----------------------------------------------------------------------------
sub grabLock
{
	my($lock) = $_[0];

	if ($useUnixPS) {		# unix PS search
		my($prog) = join(" ", $0, @ARGV);
		foreach (`ps -eo pid,args`) {
			chomp;
			if ((index($_, $prog) >= 0) && (/^\s*(\d+)/)) {
				if ($1 != $$) {			# if the pid isn't ours
					&logit($LOG_INFO, "this process is already running (mypid=$$, pid=$1, args=$prog");
					return 0;
				}
			}
		}
		return 1;
	}

	# normal lock file

	return 0 if (-f $lock);

	open(LOCKOUT, ">$lock");
	print LOCKOUT "$$\n";
	close(LOCKOUT);
	return 1;
}

sub releaseLock
{
	my($lock) = $_[0];
	unlink($lock) if (! $useUnixPS);
}

sub checkMemOverload
{
	return if ($MEM_OVERLOAD_LIMIT !~ /^([\d\.]+)(\%?)$/);

	my $tval = $1;
	my $cpu = (($2) ? 'pmem' : 'vsz');
	my $mem = `ps --no-headers -o $cpu $$`;
	my $ocond = $MEM_OVERLOAD_CONDITION;
	chomp $mem;

	$MEM_OVERLOAD_CONDITION = ($mem >= $tval);

	my $msg = "Flows $fileFlowCounter, current memory usage/limit = $mem/$tval (protection " . 
		(($MEM_OVERLOAD_CONDITION) ? "Enabled!)" : "disabled)");

	&logit( (($MEM_OVERLOAD_CONDITION != $ocond) ? $LOG_ERROR : $LOG_INFO), $msg );
}


# ----------------------------------------------------------------------------
# silly routine to set the timestamp to the oldest file date, prior to
# running config (in case RRD files need to be created, they'll have a
# stamp old enough to accomodate this data).
# ----------------------------------------------------------------------------
sub grabOldestFileStamp
{
	my(@files);

	opendir(DIR, $sourceDir);
	@files = sort grep (/flows.\d+/, readdir(DIR));
	closedir(DIR);

	if ($_ = shift @files) {
		$timeStamp = &getFileStamp("$sourceDir/$_");
	}
}

sub dumpBucketCacheInfo
{
	my $bucketCount = 0;
	my $totalBucketIpCount = 0;
	my $totalBucketRowCount = 0;

	my ($maxBucketRowCount, $maxBucketIpCount);
	my ($maxBucketRow, $maxBucketIp);

	foreach my $bucket (keys %buckets) {
		my $file = $1 if ($bucket =~ /^([^\.]+)/);

		my $bucketRowCount = 0;
		my $bucketIpCount = 0;

		foreach my $b (@{$buckets{$bucket}}) {
			$bucketIpCount += scalar keys %{$b->[6]};
			$bucketIpCount += scalar keys %{$b->[7]};
			$bucketRowCount++;
		}

		if ($bucketRowCount > $maxBucketRowCount->{$file}) {
			$maxBucketRowCount->{$file} = $bucketRowCount;
			$maxBucketRow->{$file} = $bucket;
		}

		if ($bucketIpCount > $maxBucketIpCount->{$file}) {
			$maxBucketIpCount->{$file} = $bucketIpCount;
			$maxBucketIp->{$file} = $bucket;
		}

		$totalBucketIpCount += $bucketIpCount;
		$totalBucketRowCount += $bucketRowCount;
		$bucketCount++;
	}

	if ($bucketCount) {
		my $avgBucketIpCount = $totalBucketIpCount / $bucketCount;
		my $avgBucketRowCount = $totalBucketRowCount / $bucketCount;

		&logit($LOG_TRIVIA,
			sprintf("bucketCount: %d  AvgBucketIpCount: %.02f AvgBucketRowCount: %0.02f",
				$bucketCount, $avgBucketIpCount, $avgBucketRowCount)
		);

		foreach my $file (sort keys %$maxBucketRowCount) {
			&logit($LOG_TRIVIA,
				sprintf("file %s: maxBucketIpCount=%d (%s) maxBucketRowCount=%d (%s)",
					$file, $maxBucketIpCount->{$file}, $maxBucketIp->{$file},
					$maxBucketRowCount->{$file}, $maxBucketRow->{$file})
			);
		}
	}
}

sub dumpBuckets
{
	my($bucket) = $_[0];
	my $row = 0;
	my @dp;

	return if (! defined $buckets{$bucket});

	&logit($LOG_DEBUG, "Dump of bucket '$bucket'");

	foreach my $b (@{$buckets{$bucket}}) {

		&logit($LOG_DEBUG, sprintf( "  bucket %02d: %.02f %.02f %.02f %.02f %.02f %.02f %3d %3d",
			$row++, $b->[0], $b->[1], $b->[2], $b->[3], $b->[4], $b->[5],
			scalar keys %{$b->[6]}, scalar keys %{$b->[7]}) );

		for ( 0 .. 5 ) { 	# BYTE_IN_COUNTER TO FLOW_OUT_COUNTER
			my $x = $b->[$_];
			$dp[$_] = $x if ($x > $dp[$_]);
		}
		for ( 6 .. 7) {		# IP_IN_COUNTER to IP_OUT_COUNTER
			my $x = scalar keys %{$b->[$_]};
			$dp[$_] = $x if ($x > $dp[$_]);
		}
	}
	&logit($LOG_DEBUG, sprintf("     totals: %.02f %.02f %.02f %.02f %.02f %.02f %3d %3d\n", @dp));
}


# -------------------------------------------------------------------------
# any stuff we have in memory? Let's rrd it before going on
# -------------------------------------------------------------------------
sub flushData {
	my $fName = shift;
	my ($x, $then);

	if ((defined $lastFileName) && (! $forkMax)) { &updateWatchData($lastFileName); }
	$lastFileName = $fName;

	return if (! defined $timeStamp);			# no time stamp? no go.

	&logit($LOG_DEBUG, "Flushing Data...");

#	On some perl builds, the following line can avoid 'modification of read-only variable' error msgs
#	%buckets = %{Storable::dclone(\%buckets)};

	# for all 'dnsAuto' matrices, shuffle values to dnsTable for future lookup
	foreach my $matrix (keys %dnsAuto) {
		${"MATRIX_$matrix"}->climb(sub { $dnsTable{$_[0]} = 1; });
	}

	if ($debug) {
		foreach my $pfoo (keys %foos) {
			&logit($LOG_DEBUG, "$pfoo: baseBucket=" . $baseBucket{$pfoo} .
				"  highestBucket=" . $highestBucket{$pfoo});
		}
	}

	open(RRDUPDATER, sprintf(">$stateDir/rrd-updates.%08d", $rrdBatchCounter) ) if (! $rrdcached);

	foreach my $tfoo (@fooFileArray) {
		last if ($FATAL_ERROR);

		my $pfoo = $papaFoo{$tfoo};
		next if (($fileType{$pfoo} != $foo_rrd) && (! defined $fooMatrices{$pfoo})) ;	# not an RRD and no matrices?

		if (($debug) && (0)) {
			&logit($LOG_DEBUG, "  papafoo $pfoo (\"$tfoo\")");

			foreach my $matrix (@{$fooMatrices{$pfoo}}) {
				&logit($LOG_DEBUG, "    Breakdown of \%MATRIX_$matrix" . ":");
				foreach (keys %{"MATRIX_$matrix"}) {
					&logit($LOG_DEBUG, "      $_");
				}
			}
		}

		foreach my $foo (&fooMatrixExpansion($tfoo, $fooMatrices{$pfoo}) ) {		# expand matrices
#			&logit($LOG_INFO, "foo $foo   fileBucket{\$pfoo} = $fileBucket{$pfoo}");
			last if ($FATAL_ERROR);

			if ($fileType{$pfoo} == $foo_rrd) {		# RRD
				my ($res, $dpTotal, $dpTimeStamp, $bucketChunk, @updates);

				if ($res = $fileBucket{$pfoo}) {		# BUCKET MODE

					next if (! $highestBucket{$pfoo});

					$bucketChunk = &bucketsPerStep($res, $fileStep{$pfoo});					# how many buckets are needed for each step
					$dpTotal = POSIX::floor(($highestBucket{$pfoo} - $fileBucketLow{$pfoo}) / $bucketChunk);	# how many steps are available for processing
					$dpTimeStamp = ( $baseBucket{$pfoo} + 1 ) * $res;

					next if (! ($dpTotal > 0));

					next if (scalar @{$buckets{$foo}} < $bucketChunk);
				}
				else {						# FILE MODE
					$res = $period;
					$bucketChunk = 1;
					$dpTotal = 1;
					$dpTimeStamp = $timeStamp;

					&logit($LOG_ERROR, "timeStamp '$timeStamp' not defined!") if (! $dpTimeStamp);
				}

				for (my $dpCount=0; $dpCount < $dpTotal; $dpCount++) {
					my $skip = 1;
					my $update;
					my $pIndex = 0;

					while (1) {
						my $buck = ($filePacked{$pfoo}) ? $buckets{$foo}->[$pIndex++] : $buckets{$foo};
						my @dp;			# one datapoint

						if ($fooMatrixCount{$pfoo})  {		# we have counters
							# when I have time, change these (and render) to use IP_[IN|OUT]_COUNTER
							$dp[$FLOW_IN_COUNTER] = scalar keys %{$cmatrix_in{$foo}};
							$dp[$FLOW_OUT_COUNTER] = scalar keys %{$cmatrix_out{$foo}};
						}
						else {					# perform bucket consolidation
							# note that without resolution set, bucketChunk = 1

							foreach my $b (splice(@$buck, 0, $bucketChunk)) {
								next if (! defined $b);

								for ( 0 .. 5 ) { 	# BYTE_IN_COUNTER TO FLOW_OUT_COUNTER
									my $x = $b->[$_];
									$dp[$_] = $x if ($x > $dp[$_]);
								}
								for ( 6 .. 7) {		# IP_IN_COUNTER to IP_OUT_COUNTER
									my $x = scalar keys %{$b->[$_]};
									$dp[$_] = $x if ($x > $dp[$_]);
								}
							}
						}

						$update .= sprintf(":%.05f:%.05f:%.05f:%.05f:%.05f:%.05f:%.05f:%.05f",
							$dp[$BYTE_IN_COUNTER] * 8 / $res,
							$dp[$BYTE_OUT_COUNTER] * 8 / $res,
							$dp[$PKT_IN_COUNTER] / $res,
							$dp[$PKT_OUT_COUNTER] / $res,
							$dp[$FLOW_IN_COUNTER] / $res,
							$dp[$FLOW_OUT_COUNTER] / $res,
							$dp[$IP_IN_COUNTER],
							$dp[$IP_OUT_COUNTER]
						);

						$skip = 0 if ($dp[$FLOW_IN_COUNTER]) || ($dp[$FLOW_OUT_COUNTER]);	# if any flows, don't skip

						last if ( (! defined $filePacked{$pfoo}) || ($pIndex >= $filePacked{$pfoo}) );
					}

					# The following is to compensate for RRD behavior. RRD expects updates at a regular basis. But,
					# on infrequently-used categories, hours or days may pass between webview updates. RRD treats
					# those gaps as NaN, and the actual values are normalized into oblivion. The solution is to
					# wrap the actual value with NaN values ("U"). Only then will the sparse updates survive
					# RRD normalization. The step must be 3 or more seconds for this wrapping to work.
					#
					# see https://lists.oetiker.ch/pipermail/rrd-users/2006-January/010851.html
					# see http://www.vandenbogaerdt.nl/rrdtool/process.php

					if ($fileStep{$pfoo} < 3) {
						push(@updates, $dpTimeStamp . $update);
					}
					elsif (! $skip) {
						my $updatewrapper = $update;
						$updatewrapper =~ s/([\d\.]+)/U/g;

						push(@updates, ($dpTimeStamp - $fileStep{$pfoo} + 1) . $updatewrapper);
						push(@updates, ($dpTimeStamp - int($fileStep{$pfoo} / 2)) . $update);
						push(@updates, $dpTimeStamp . $updatewrapper);
					}

					$dpTimeStamp += $fileStep{$pfoo};
				}

				if ((@updates) && (! $testMode)) {
					my $ffoo = &hierarchical($filePrefix{$pfoo} . $foo . $fileSuffix{$pfoo});

					if (! -f $ffoo) {
						$updates[0] =~ /^(\d+)/;
						my $fStamp = $1 || $timeStamp;

						if (! &createFile($ffoo, $foo_rrd,
							$fileConsolidation{$pfoo},
							$fileStep{$pfoo},
							$filePacked{$pfoo},
							$fStamp - 1)
						) {
							$FATAL_ERROR = 1;
							last;
						}
					}

					my $rrdUpdateStatus;

					if ($rrdcached) {
						$rrdUpdateStatus = &rrdCachedPut(join(" ", "UPDATE", $ffoo, @updates));
						&rrdErrTabulator($ffoo, $1) if (&rrdCachedGet =~ /^\-\d+\s+(.*)/);
					}
					else {
						$rrdUpdateStatus = print RRDUPDATER join("\t", $ffoo, @updates), "\n";
					}

					if (! $rrdUpdateStatus) {
						$FATAL_ERROR = 1;
						last;
					}
				}
			}
			elsif (length $$foo) {				# TXT, CSV, or RAW
				my $ffoo = &hierarchical($filePrefix{$pfoo} . $foo . $fileSuffix{$pfoo});

				if ($fileMaxSize{$pfoo}) {			# use rotate/open facility of createFile
					&createFile($ffoo, $fileType{$pfoo}, $fileMaxSize{$pfoo});
				}
				else {
					open($ffoo, ">>$ffoo");
				}
				print $ffoo $$foo;
				close($ffoo);
				delete $fileOpened{$ffoo};

				&logit($LOG_DEBUG, "Wrote " . (length $$foo) . " bytes to $ffoo") if ($debug);
				undef $$foo;
			}
			else {
#				&logit($LOG_DEBUG, "No updates to $foo") if ($debug);
			}
		}

	}

	if ($rrdcached) {
		&rrdErrReport;
	}
	else {
		print RRDUPDATER "GA\n";		# go ahead and process these...
		close RRDUPDATER;
	}

	foreach my $pfoo (keys %foos) {			# update baseBucket and reset range tracking
		next if ( (! $fileBucket{$pfoo}) || (! $highestBucket{$pfoo}) );

		my $bucketChunk = &bucketsPerStep($fileBucket{$pfoo}, $fileStep{$pfoo});
		my $dpTotal = POSIX::floor(($highestBucket{$pfoo} - $fileBucketLow{$pfoo}) / $bucketChunk);
		my $orig = $baseBucket{$pfoo};
		$baseBucket{$pfoo} += $dpTotal * $bucketChunk if ($dpTotal > 0);
		&logit($LOG_SUPERDEBUG, "foo $pfoo: highestBucket=$highestBucket{$pfoo} bucketChunk=$bucketChunk dpTotal=$dpTotal baseBucket $orig->" . $baseBucket{$pfoo});
	}

	undef %cmatrix_in;
	undef %cmatrix_out;
}


sub openAllFiles
{
	my($fh);

	foreach (@fooFileArray) {
		my $pfoo = $papaFoo{$_};
		next if (($fileType{$pfoo} == $foo_rrd) || (defined $fooMatrices{$pfoo}));
		$fh = $filePrefix{$pfoo} . $_ . $fileSuffix{$pfoo};
		open($fh, ">>$fh");		# use the filename as a handle. Why not?
		$fileOpened{$fh} = 1;
	}
}

sub closeAllFiles
{
	# close all the output files that may have been opened during this run...
	foreach (keys %fileOpened) {
		close($_);
		delete $fileOpened{$_};
	}
}

# -------------------------------------------------------------------------
# this function is called once for every flow file read. It updates RRDs
# and resets counters. It also sets the global variable $timeStamp
# -------------------------------------------------------------------------
sub perfile {
	my($fName) = $_[0];

	$flowCounter += $fileFlowCounter;
	$fileFlowCounter = 0;

#	&flushData($fName);		# flush old file

	foreach my $pfoo (keys %foos) {	
		$highestBucket{$pfoo} = 0 if ($fileBucket{$pfoo});	# update baseBucket and reset range tracking

		foreach my $fh (values %{$fileSpecial{$pfoo}}) {	# open special file for writing
			next if ($fName !~ /([^\/]+)$/);
			my $pipe = sprintf($fpipe, $fh . "/" . $1);

			close $fh;
			if (! open($fh, $pipe)) {
				&logit($LOG_ERROR, "Could not write to '$pipe'");
			}
			else {
				$fileOpened{$fh} = 1;
			}
		}
	}

	if (-f $fName) {				# does it still exist?
		$timeStamp = &getFileStamp($fName);
#		&logit($LOG_INFO, "reading $fName");
		return 1;			# read it
	}

	return 0;				# skip it (moved or deleted?)
}

sub doAutoClock
{
	my $fName = shift;
	$timeStamp = &getFileStamp($fName);
	my $now = scalar localtime($timeStamp);

	if (! &fileSummary($fName, $timeStamp)) {
		&logit($LOG_INFO, "Note: AutoClock configured, but no summary data found");
	}
}

sub fileSummary
{
	my($ftFile, $ftStamp) = @_;		# file to process and local timestamp of file

	undef %exporterClockSkew;
	undef %exporterClockGood;
	undef %exporterClockBad;
	undef %exporterClockLongFlows;

	$fileFlowMax = 0;
	undef $fileFlowFirst;
	undef $fileFlowLast;

	my ($tabFirst, $tabLast, $tabFlows);
	my $exps = {};

	open(SUMMARY, "$flowCheck --full $ftFile |");
	while ( <SUMMARY> ) {
		chomp;
		# recn: exaddr,interface,direction,flows,octets,packets,first,last
		next if (! /^(\d+\.\d+\.\d+\.\d+),,2,(\d+),\d+,\d+,(\d+),(\d+)$/);

		my($expip,$flows,$first,$last) = ($1,$2,$3,$4);
		my $exp = &hackIP($expip);

		$exps->{$exp} = {
			'flows' => $flows,
			'first' => $first,
			'last' => $last,
		};

		$fileFlowMax += $flows;

		if ( ($last < ($ftStamp - $fudgeFlowBallpark)) || ($last > ($ftStamp + $fudgeFlowBallpark)) ) {
			$exporterClockBad{$exp} = 1;
		}
		else {
			$tabFirst += $first;		# $flows * $first;
			$tabLast += $last;		# $flows * $last;
			$tabFlows += 1;			# $flows;
		}
	}
	close(SUMMARY);

	return undef if (! $fileFlowMax);

	if ($tabFlows) {
		$tabFirst /= $tabFlows;
		$tabLast /= $tabFlows;
		my $tabDur = $tabLast - $tabFirst;		# this should be about period + 60 seconds.
		&logit($LOG_DEBUG, "summary tabFirst=" . &datestr($tabFirst) . " tabLast=" . &datestr($tabLast) . " tabDur=$tabDur");
	}

	foreach my $exp (keys %$exps) {
		$exporterClockBad{$exp} = 1 if (! $tabFlows);
		next if ($exporterClockBad{$exp});

		my $first = $exps->{$exp}->{first};
		my $last = $exps->{$exp}->{last};
		my $dur = $last - $first;
		my $skew = 0;

		if ($dur > ($period + 60 + $fudgeFlowTime)) {
			# this exporter may not have its flow expiration timeout set properly
			$exporterClockLongFlows{$exp} = $dur;
		}

		if ( (($last >= ($tabLast - $fudgeFlowTime)) || ($first >= ($tabFirst - $fudgeFlowTime))) && ($last <= ($tabLast + $fudgeFlowTime))) {
			# timestamps for this exporter seem trustworthy

			$exporterClockGood{$exp} = 1;
		}
		elsif ($dur < ($maxFlowAge + $fudgeFlowTime)) {
			# timestamps seem valid, but skewed

			$exporterClockSkew{$exp} = $skew = int($last - $tabLast);
			$first -= $skew; $last -= $skew;
		}
		else {
			# otherwise, this exporter is "messed up". Use interpolated time instead.

			$exporterClockBad{$exp} = 1;
			next;
		}

		$fileFlowFirst = $first if (($first < $fileFlowFirst) || (! defined $fileFlowFirst));
		$fileFlowLast = $last if ($last > $fileFlowLast);
	}

	if (! defined $fileFlowFirst) {			# no exporters or every exporter has a bad clock -- use the file timestamp
		$fileFlowFirst = $timeStamp;
		$fileFlowLast = $fileFlowFirst + $period;
	}

	&logExpList("Exporters w/ bad clocks", undef, undef, keys %exporterClockBad) if ($trackExporters->{clockBad});
	&logExpList("Exporters w/ skewed clocks", undef, \%exporterClockSkew, keys %exporterClockSkew) if ($trackExporters->{clockSkew});
	&logExpList("Exporters w/ good clocks", undef, \%exporterClockGood, keys %exporterClockGood) if ($trackExporters->{clockGood});
	&logExpList("Exporters w/ long flows", undef, undef, keys %exporterClockLongFlows) if ($trackExporters->{clockLongFlows});
	return 1;
}

sub datestr
{
	return POSIX::strftime("%H:%M:%S", localtime(shift));
}

sub getFileStamp
{
	my($fName) = $_[0];

	# if the filename contains a timestamp, use it (e.g., 20000926_21:46:56-0500)
	# ft-v05.2006-04-12.114233-0400

	if ($fName =~ /(\d\d\d\d)-(\d\d)-(\d\d).(\d\d)(\d\d)(\d\d)/) {
		return timelocal($6, $5, $4, $3, $2 - 1, $1);
	}
	elsif ($fName =~ /(\d\d\d\d)(\d\d)(\d\d)_(\d\d):(\d\d):(\d\d)/) {
		return timelocal($6, $5, $4, $3, $2 - 1, $1);
	}
	else {			# otherwise, use the unixtime for the file itself...
		return (lstat($fName))[9] - $period;
	}
}

# ----------------------------------------------------------------------------
#  Creates the wanted() subroutine. This function is called once for every
#  so it must be really fast. It generally avoids the use of:
#
#     subroutine calls
#     conditional clauses dependent on variables that don't change
#     curly-braced sections
#     loops
#     hash references
#
#  As a result, the code is ugly, difficult to maintain, and quite
#  incomprehensible to the newcomer. To see the wanted routine, use the
#  --debug switch to put it in a standalone file ("debug_wanted.txt").
# ----------------------------------------------------------------------------

sub wantedCompiler
{
	my($code_lnh, $code_acl, $code_racl, $code_counter, $code_if, $code_nonif, $code_debug, $code_cache, $code_fork);
	my($code);

	# ---- return if this is a local next hop
	if (defined $aclCode{$localNextHops}) {
		$code_lnh = <<EOT;
	if $aclCode{$localNextHops} {
		\$localFlowCounter++;
		return;
	}
EOT
	}

	# ---- fork code
	if ($forkMax) {
		$code_fork = <<EOT;
	return if ( (($forkHash) % $forkMax) != (\$forkPID - 1) );
EOT
	}

	# ---- increment flowCounter
	if ($MEM_OVERLOAD_PROTECTION) {
		$code_counter = "\t\&checkMemOverload if (! (\$fileFlowCounter++ & $MEM_OVERLOAD_MASK));\n";
	}
	else {
		$code_counter = "\t\$fileFlowCounter++;\n";
	}

	$code_counter = "&logit(\$LOG_SUPERDEBUG, &finfo);\n" if ($logFileLevel == $LOG_SUPERDEBUG);

	my $noExpCode = ($trackExporters->{noExporters}) ? "\$noExporterFlowCounterValues{\$exporter}++" : "\$noExporterFlowCounter++";
	my $noIfCode = ($trackExporters->{noInterfaces}) ? "\$noInterfaceFlowCounterValues{\$exporter}++" : "\$noInterfaceFlowCounter++";
	my $noBucketCode = ($trackExporters->{noBuckets}) ? "\$noBucketFlowCounterValues{\$exporter}++" : "\$noBucketFlowCounter++";

	# ---- check the exporter discovery
	if ($noUnknownExporters) { 
		$code_counter .= "\tif (exists \$exporterName{\$exporter}) {\n";
		$code_counter .= "\t\tif (! defined \$exporterName{\$exporter}) { $noExpCode; return; }\n";
		$code_counter .= "\t}\n";
		if ($autoExporterTrie->climb() > 0) {
			$code_counter .= "\telsif (! \&checkAutoExporter(\$exporter)) { $noExpCode; return; }\n";
		}
	}
	elsif ($autoExporterTrie->climb() > 0) {
		$code_counter .= "\tif (! exists \$exporterName{\$exporter}) { \&checkAutoExporter(\$exporter); }\n";
	}


	# ---- check out the interface names
	$code_counter .= "\t\$master_input_if_name = (\${\"iif_clean_\$exporter\"}{\$input_if} || (\$input_if ? " .
		($noUnknownInterfaces ? "$noIfCode && return" : "\"snmpIf\$input_if\"") .
		" : 'Local'));\n";

	$code_counter .= "\t\$master_output_if_name = (\${\"iif_clean_\$exporter\"}{\$output_if} || (\$output_if ? " .
		($noUnknownInterfaces ? "$noIfCode && return" : "\"snmpIf\$output_if\"") .
		" : 'Local'));\n";

	if (! $OPTIMIZE_ACL_USAGE) {
		# ---- set all global ACL variables
		foreach my $acl (keys %aclCode) {
			$code_acl .= "\t\$$acl = " . $aclCode{$acl} . ";\n" if ($acl ne $localNextHops);
		}
	}

	# ---- process the RACLs, if any
	foreach my $racl (@racls) {
		$code_racl .= "\tif (\$$racl->{acl}) {\n";

		if (defined $racl->{setSourceIP}) {
			$code_racl .= "\t\t\$" . $racl->{setSourceIP} . "->add_string(\$srcaddr, \$endtime + $racl->{timeout});\n";
		}

		if (defined $racl->{setDestinationIP}) {
			$code_racl .= "\t\t\$" . $racl->{setDestinationIP} . "->add_string(\$dstaddr, \$endtime + $racl->{timeout});\n";
		}

		if (defined $racl->{setFlow}) {
			$code_racl .= "\t\t# " . $racl->{setFlow} . "\n";

			while ( my ($hashkey, $facl) = each %{$FACL->{$racl->{setFlow}}->{hashes}}) {
				$code_racl .= "\t\t\$" . $facl . "{" . $hashkey . "} = \$endtime + $racl->{timeout};\n";
			}
		}

		$code_racl .= "\t}\n";
	}

	# ---- process each individual foo
	my ($fooIoMode, $lastBucketFoo);			# used for minor code optimizations.
	my $anyACL;

	foreach (keys %foos) { if ((exists $fileBucket{$_}) && (exists $fooACL{$_})) { $anyACL = 1; last; } }

	foreach my $foo (keys %foos) {
		$code = "\n\t# ---- process foo $foo\n";

		# ---- set input/output interface names appropriately

		my $fooNewIoMode = ((defined $fileInACL{$foo}) ? 1 : 0) + ((defined $fileOutACL{$foo}) ? 2 : 0);

		if ((! defined $fooIoMode) || ($fooIoMode != $fooNewIoMode)) {
			$fooIoMode = $fooNewIoMode;

			my $iotest;
			if ($fooIoMode) {
				$iotest = "(\$input_if) && (\$output_if)";
				$iotest .= " && (! exists \$exporterInout{\$exporter})" if (keys %exporterInout);
			}
			else {
				$iotest = "1";
			}

			$code .= <<EOT;
	if ($iotest) {
		\$input_if_name = \$master_input_if_name;
		\$output_if_name = \$master_output_if_name;
	}
	else {
EOT
			if (defined $fileInACL{$foo}) {
				$code .= <<EOT;
		if (\$$fileInACL{$foo}) {
			\$input_if_name = \$master_input_if_name;
			undef \$output_if_name;
		}
EOT
				if (defined $fileOutACL{$foo}) {
					$code .= <<EOT;
		elsif (\$$fileOutACL{$foo}) {
			undef \$input_if_name;
			\$output_if_name = \$master_output_if_name;
		}
		else {
			return;
		}
EOT
				}
				else {
					$code .= <<EOT;
		else {
			undef \$input_if_name;
			\$output_if_name = \$master_output_if_name;
		}
EOT
				}
			}
			elsif (defined $fileOutACL{$foo}) {
				$code .= <<EOT;
		if (\$$fileOutACL{$foo}) {
			undef \$input_if_name;
			\$output_if_name = \$master_output_if_name;
		}
		else {
			\$input_if_name = \$master_input_if_name;
			undef \$output_if_name;
		}
EOT
			}
			else {
				$code .= <<EOT;
		\$input_if_name = \$master_input_if_name;
		undef \$output_if_name;
EOT
			}
			$code .= <<EOT;
	}
EOT
		}

		my $bucketcode;

		if ($fileBucket{$foo}) {
			my @code;
			my $res = $fileBucket{$foo};

			my $stime = "\$startime";
			my $etime = "\$endtime";
			my $bucketCode = 
				($fileTimestamp{$foo} eq 'start') ?  "\$sbucket = int (STIME \/ $res);" :
				($fileTimestamp{$foo} eq 'end') ?  "\$sbucket = int( ETIME \/ $res);" :
				($fileTimestamp{$foo} eq 'average') ?  "\$sbucket = int ( (STIME + DUR \/ 2) \/ $res);" :
				"\$sbucket = int (STIME \/ $res); \$bucketMax = int (DUR \/ $res) + 1;";

			### do this code only if the definition of sbucket/bucketMax are different from the previous datafile

			if ( (! defined $lastBucketFoo) || ($anyACL) || ($fileBucket{$foo} ne $fileBucket{$lastBucketFoo}) || ($fileTimestamp{$foo} ne $fileTimestamp{$lastBucketFoo}) || ($fileAutoClock{$foo} ne $fileAutoClock{$lastBucketFoo}) ) {

				if ($fileAutoClock{$foo}) {
					my $maxFlowDuration = $fileBucketLow{$foo} * $res;		# clip to this

					my $bucketCodeScrewedUp = $bucketCode;
					$bucketCodeScrewedUp =~ s/STIME/((\$timeStamp + \$fileFlowCounter * $period \/ \$fileFlowMax) - \$duration)/g;
					$bucketCodeScrewedUp =~ s/ETIME/(\$timeStamp + \$fileFlowCounter * $period \/ \$fileFlowMax)/g;
					$bucketCodeScrewedUp =~ s/DUR/\$duration/g;

					my $bucketCodeGood = $bucketCode;
					$bucketCodeGood =~ s/STIME/(\$startime - \$exporterClockSkew{\$exporter})/g;
					$bucketCodeGood =~ s/ETIME/(\$endtime - \$exporterClockSkew{\$exporter})/g;
					$bucketCodeGood =~ s/DUR/\$duration/g;

					push(@code, "if (exists \$exporterClockBad{\$exporter}) {",
						"\t\$duration = (\$endtime < \$startime) ? 1 : (\$endtime > (\$startime + $maxFlowDuration)) ? $maxFlowDuration : \$endtime - \$startime;",
						"\t$bucketCodeScrewedUp",
						"}",
						"else {",
						"\t\$duration = (\$endtime - \$startime);",
						"\t$bucketCodeGood",
						"}"
					);
				}
				else {
					$bucketCode =~ s/STIME/\$startime/g;
					$bucketCode =~ s/ETIME/\$endtime/g;
					$bucketCode =~ s/DUR/\$duration/g;
					push(@code, 
						"\$duration = (\$endtime - \$startime);",
						$bucketCode
					);
				}

				push(@code, &tabulatorBucketInit) if ($fileTimestamp{$foo} !~ /(start|end|average)/);

				$lastBucketFoo = $foo;

				if ($deepDebugExpression) {
					push(@code,
						"\$DEEPDEBUG = ($deepDebugExpression);",
						"if (\$DEEPDEBUG) {",
						"print \"flow \$srcip:\$srcport -> \$dstip:\$dstport startime=$stime endtime=\$endtime" .
							" sbucket=\$sbucket bucketMax=\$bucketMax" .
							" bytes=\$bytes bbytes=\$bbytes\\n\";",
						"}"
					);
				}
			}

			### do this code for all bucket foo's.
			my $preBuckets = &bucketsPerStep($res);		# don't pass fileStep so that preBuckets is set properly to one file.

			push(@code,
				"if (! \$baseBucket{\'$foo\'}) {",
				"	&logit(\$LOG_DEBUG, \"$foo: startime=\$stime  sbucket=\$sbucket  set baseBucket=\" . " .
				"		(\$sbucket - $fileBucketLow{$foo}) );",		#  - $preBuckets - ((\$sbucket - $fileBucketLow{$foo}) % $preBuckets)) );",
				"}",

				"\$bucket = \$sbucket - (\$baseBucket{\'$foo\'} || " .
					"(\$baseBucket{\'$foo\'} = (\$sbucket - $fileBucketLow{$foo}) ) );",	# - $preBuckets - ((\$sbucket - $fileBucketLow{$foo}) % $preBuckets))));"
			);

			push(@code,
				"if (\$DEEPDEBUG) {",
				"	print \"bucket=\$bucket, baseBucket{\$foo}=\" . \$baseBucket{\'$foo\'} . \", highestBucket=\" . \$highestBucket{\'$foo\'} . \"\\n\";",
				"	print \"input_if_name='\$input_if_name', output_if_name='\$output_if_name'\\n\";",
				"}"
			) if ($deepDebugExpression);

			push(@code,
				"if (\$bucket < 0) {",
				"	$noBucketCode;",
				"	return if ( (! defined (\$bucket = \$fooBackupBucket{\'$foo\'})) || (! defined (\$bucket = &calcFooBackupBucket(\'$foo\', $stime, \$bucket) ) ) );",
				"}",
				"elsif (\$bucket > \$highestBucket{\'$foo\'}) {",
				"	if (\$bucket >= $fileBucketHigh{$foo}) {",
				"		$noBucketCode;",
#				"		return if (! defined (\$bucket = \$fooBackupBucket{\'$foo\'} || &calcFooBackupBucket(\'$foo\', $stime, \$bucket) ) );",
				"		return if ( (! defined (\$bucket = \$fooBackupBucket{\'$foo\'})) || (! defined (\$bucket = &calcFooBackupBucket(\'$foo\', $stime, \$bucket) ) ) );",
				"	}",
				"	else {",
				"		\$highestBucket{\'$foo\'} = \$bucket;",
				"	}",
				"}"
			);

			foreach (@code) { $bucketcode .= ((/^$/) ? "\n" : "\t" . $_ . "\n"); }
		}

		if (defined $fooMatrices{$foo}) {		# if a matrix, then fooCode has it all

			if (exists $fooACL{$foo}) {
				$code .= "\tif " . $fooACL{$foo} . " {\n" . $bucketcode . $fooCode{$foo} . "\t}\n";
			}
			else {				# no ACL's anywhere.
				$code .= $bucketcode . $fooCode{$foo};
			}

			my($ifMatrix) = 0;

			foreach (@{$fooMatrices{$foo}}) {	# check if it contains an interface matrix
				if ($matrixType{$_} eq "if") { $ifMatrix = 1; last; }
			}

			if ($ifMatrix) {			# if ifMatrix, add code at top (above LNH)
				$code_if .= $code;
			}
			else {					# else, add code at bottom
				$code_nonif .= $code;
			}
			next;
		}

		# below this point is code for foos that do not have matrices (simple ACLs and groups -- rarely used anymore)

		$code .= "\tmy(\@fooTargets);\n";
		$code .= $fooCode{$foo};

		$code .= "\tforeach (\@fooTargets) {\n";
		$code .= "\t\t\$foo = \$fooFileIndex[\$_];\n";	# put actual filename into embedded $foo

		if ($fileType{$foo} == $foo_rrd) {		# RRD files
			my ($inCode, $outCode);

			$inCode = &tabulator('$foo', "\t\t\t", "in",
				$fileBucket{$foo},
				$fileStep{$foo},
				$fileIPTracking{$foo},
				($fileTimestamp{$foo} !~ /(start|end|average)/)
			);

			$outCode = &tabulator('$foo', "\t\t\t", "out",
				$fileBucket{$foo},
				$fileStep{$foo},
				$fileIPTracking{$foo},
				($fileTimestamp{$foo} !~ /(start|end|average)/)
			);

			if (defined $fileInACL{$foo}) {
				$code .= "\t\tif (\$$fileInACL{$foo}) {\n" . $inCode .  "\t\t}\n";

				if (defined $fileOutACL{$foo}) {
					$code .= "\t\telsif (\$$fileOutACL{$foo}) {\n" . $outCode . "\t\t}\n";
				}
				else {
					$code .= "\t\telse {\n" . $outCode . "\t\t}\n";
				}
			}
			elsif (defined $fileOutACL{$foo}) {
				$code .= "\t\tif (\$$fileOutACL{$foo}) {\n" . $outCode . "\t\t}\n";
				$code .= "\t\telse {\n" . $inCode . "\t\t}\n";
			}
			else {
				$code .= $inCode;
			}
		}
		elsif ($fileType{$foo} == $foo_text) {		# TEXT files
			$code .= "\t\t\$fName = \"$filePrefix{$foo}\$foo$fileSuffix{$foo}\";\n";
			$code .= "\t\tprint \$fName " . &wantedTXT . ";\n";
		}
		elsif ($fileType{$foo} == $foo_csv) {		# CSV files
			$code .= "\t\t\$fName = \"$filePrefix{$foo}\$foo$fileSuffix{$foo}\";\n";
			$code .= "\t\tprint \$fName " . &wantedCSV . ";\n";
		}
		elsif ($fileType{$foo} == $foo_flow) {		# raw FLOW files
			$code .= "\t\t\$fName = \"$filePrefix{$foo}\$foo$fileSuffix{$foo}\";\n";
			$code .= "\t\tsyswrite(\$fName, \$raw, length \$raw);\n";
		}

		$code .= "\t}\n";

		$code_nonif .= $code;
	}

	if (! $OPTIMIZE_ACL_USAGE) {
		if (defined $code_if) {			# ACLs before LNH
			$code = join("", $code_fork, $code_debug, $code_counter, $code_cache, $code_acl,
					$code_racl, $code_if, $code_lnh, $code_nonif);
		}
		else {					# ACLs after LNH (faster)
			$code = join("", $code_fork, $code_debug, $code_counter, $code_cache, $code_lnh,
					$code_acl, $code_racl, $code_if, $code_nonif);
		}
	}
	else {
		# if an ACL is used more than once or if it is used in a RACL, then 
		# it must be added to code_acl

		my $foocode = $code_racl . "\n" . $code_if . "\n" . $code_nonif;
		my %aclTracker;

		$foocode =~ s/\$(ACL_\w+)/$aclTracker{$1}++/ge;

		foreach my $acl (keys %aclTracker) {
			if ($aclTracker{$acl} >= 2) {		# cannot be optimized
				$code_acl .= "\t\$$acl = " . $aclCode{$acl} . ";\n";
				delete $aclTracker{$acl};
			}
		}

		$code = join("", $code_fork, $code_debug, $code_counter, $code_cache, $code_acl,
				$code_racl, $code_if, $code_lnh, $code_nonif);

		$code =~ s/\(\$(ACL_[^\)]+)\)/'(' . ($aclTracker{$1} ? $aclCode{$1} : '$' . $1) . ')'/ge;
	}

	$code = "sub wanted\n{\n" . $code . "}\n";

	&bulkDebug("Subroutine 'wanted()'", "debug_wanted.txt", \$code) if ($debug);

	# test code for errors
	no strict "vars";
	eval $code;
	use strict "vars";

	if ($@) {
		&logit($LOG_ERROR, "Error EVAL'ing subroutine wanted().");
		&logit($LOG_ERROR, " " . $@);
 		&logit($LOG_ERROR, " Use -debug option to troubleshoot.");
		return 0;
	}
}

# if a no-bucket flow is received, try to put it somewhere...
sub calcFooBackupBucket
{
	my ($foo, $stamp, $badbucket) = @_;

	my $sbucket = int( $timeStamp  / $fileBucket{$foo} );	# from current flow file
	my $bucket = $sbucket - $baseBucket{$foo};
	$bucket = 0 if ($bucket == -1);			# nudge it if it's really close...

	if (($bucket < 0) || ($bucket > $fileBucketHigh{$foo})) {		# the file timestamp is way off. Our bucket system is probably broken

		# delete baseBucket{foo} so that it's recomputed on next flow

		if ( my $count = &purgeBuckets($foo) ) {
			&logit($LOG_ERROR, "Recalibrating bucket cache for '$foo' (count=$count); some data from this file may be lost");
			&logit($LOG_DEBUG, "trigger $badbucket, bucket $bucket, max " . $fileBucketHigh{$foo} . ").");
		}

		$baseBucket{$foo} = $sbucket - 8;

		&logit($LOG_DEBUG, "new baseBucket=" . (scalar(localtime($baseBucket{$foo} * $fileBucket{$foo}))) .
			", flow startime=" . (scalar(localtime($stamp))) .
			", file stamp=" . (scalar(localtime($timeStamp)))  );

		$bucket = $sbucket;
	}

	return $fooBackupBucket{$foo} = $bucket;
}

sub finfo
{
	return "(". (scalar(localtime($startime))) . ",$exporterip,$srcip:$srcport,$dstip:$dstport,$bytes)";
}


sub bulkDebug
{
	my($desc, $file, $contents) = @_;
	my $ok = "Error";

	unlink $file if (! $bulkDebugHash{$file});		# remove existing file, if there

	if (open(BULKOUT, ">>$file")) {				# append to file
		print BULKOUT (ref($contents) ? $$contents : $contents);
		close(BULKOUT);
		$ok = "Success";
	}
	&logit($LOG_DEBUG, "$ok writing $desc to file $file") if ($desc ne $bulkDebugHash{$file});
	$bulkDebugHash{$file} = $desc;
}

sub wantedACL
{
	my($acl, $hash) = @_;
	return '($' . $acl . (($hash->{$acl}++) ? ')' : '=' . $aclCode{$acl} . ')' );
}

sub wantedCSV
{
	# --- generate code for displaying IP addresses quickly
	my $ip ="%d.%d.%d.%d";
	my $code_nexthop = &wantedIP("\$nexthop");
	my $code_srcaddr = &wantedIP("\$srcaddr");
	my $code_dstaddr = &wantedIP("\$dstaddr");
	my $code_exporter = &wantedIP("\$exporter");

	return "sprintf('%u,$ip,$ip,%s,%u,$ip,%u,%s,%u,$ip,%u,%s,%u,%u\n'," .
		"\$startime, $code_exporter, $code_nexthop, " .
		"\${\"iif_\$exporter\"}{\$input_if}, \$src_as, $code_srcaddr, \$srcport, " .
		"\${\"iif_\$exporter\"}{\$output_if}, \$dst_as, $code_dstaddr, \$dstport, " .
		"\$cisco_iprotocols{\$protocol} || \$protocol, \$pkts, \$bytes)";
}

sub wantedTXT
{
	# --- generate code for displaying IP addresses quickly
	my $ip ="%d.%d.%d.%d";
	my $code_nexthop = &wantedIP("\$nexthop");
	my $code_srcaddr = &wantedIP("\$srcaddr");
	my $code_dstaddr = &wantedIP("\$dstaddr");

	return "sprintf('%s [%15.15s] %15.15s:%-5hu %15.15s:%-5hu %-5.5s %10u %10u\n', " .
		"\$localtime, sprintf('$ip', $code_nexthop), " .
		"sprintf('$ip', $code_srcaddr), \$srcport, " .
		"sprintf('$ip', $code_dstaddr), \$dstport, " .
		"\$cisco_iprotocols{\$protocol} || \$protocol, \$pkts, \$bytes)";
}

# ----------------------------------------------------------------------------
# returns code that displays an IP address -- faster than calling a subroutine
# (or even pack/unpack, which is why endian-ness is tested here!). Assumes the results
# will be passed into a sprintf("%d.%d.%d.%d, &wantedIP($x));
sub wantedIP
{
	if ($BIG_ENDIAN) {	# big-endian needs to be flipped
		return ( "$_[0] & 0xff, $_[0] >> 8 & 0xff, $_[0] >> 16 & 0x0ff, $_[0] >> 24");
	}
	else {			# little-endian is already in native network order
		return ( "$_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff");
	}
}

# ----------------------------------------------------------------------------
#  FOO COMPILER code 
#  takes all the foos and creates one big block of code that tests every
#  single one. the global array @fooTargets is filled with index numbers of
#  which files should be updated.
# ----------------------------------------------------------------------------
sub fooCompiler
{
	foreach my $foo (keys %foos) {
		$papafoo = $foo;			# a global

		my($not, @myGroups, @acls);
		my($indent) = "\t";

		undef $code;				# a global

		foreach (@{$foos{$foo}}) {
			if ($matrices{$_}) {
				push(@myGroups, $_);
				push(@{$fooMatrices{$foo}}, $_);
			}
			elsif ($groups{$_}) {	push(@myGroups, $_); }
			elsif (/^\!$/) {	$not = 1; next; }
			else {			push(@acls, (($not) ? "!" : "") . "\$$_"); }
			undef $not;
		}

#		if (@acls) { $code .= "if (" . join('&&', map { "($_)" } @acls) . ") {\n"; $indent = "\t$indent"; }

		# does this foo have groups or matrices?
		if (@myGroups) { return 0 if (! &fooGroupExpander([$foo], [@myGroups], $indent)); }		# yes
		else { $code .= $indent . "push(\@fooTargets, " . &fooFileIndex($foo) . ");\n"; }		# no

#		if (@acls) { $code .= "}\n"; }

		$fooCode{$foo} = $code;
		if (@acls) { $fooACL{$foo} = "(" . join('&&', map { "($_)" } @acls) . ")"; }

		# ---- create a set of strict ACLs for clickable graphs

		my $groupName;

		foreach (@{$foos{$foo}}) {
			if ($groups{$_}) {
				if (defined $groupName) { undef $groupName; last; }	# bomb out if more than one group is used
				$groupName = $_;
			}
		}

		if (defined $groupName) {	 # valid single group for this matrix
			my $aclNameBase = "Strict:$foo:$groupName:%s";
			my @strictAclCode;

			# add the local nexthop code, if it exists
			push(@strictAclCode, '(' . $aclCode{$localNextHops} . ')' ) if (exists $aclCode{$localNextHops});

			# add per-foo ACLs, if they exist
			push(@strictAclCode,  '(' . join('&&', @acls) . ')') if (@acls);

			foreach my $acl ( @{$groups{$groupName}} ) {
				if ($acl =~ /^MAP_/) {
					push(@strictAclCode, '!' . &mapCode($acl, 1));
				}
				else {
					$aclCode{sprintf($aclNameBase,$acl)} =
						($clickMode eq 'strict') ?
							'(' . join('&&', @strictAclCode, $aclCode{$acl}) . ')' :
							$aclCode{$acl};

					push(@strictAclCode, '!' . $aclCode{$acl});
				}
			}

			$aclCode{sprintf($aclNameBase,"ACL_$OTHER")} = '(' . join('&&', @strictAclCode) . ')'
				if ($clickMode ne 'loose');
		}
	}
	return 1;
}

# -------------------------------------------------------------------------
# given a filename, pushes it into an array and returns the index number
sub fooFileIndex
{
	my($foo) = $_[0];

	for (my $i=0; $i<@fooFileIndex; $i++) {		# safety check...
		return $i if ($foo eq $fooFileIndex[$i]);
	}

	push(@fooFileIndex, $foo);
	$papaFoo{$foo} = $papafoo;

	return $#fooFileIndex;
}

# -------------------------------------------------------------------------
# Perform foo group expansion. This routine recursively calls
# itself since multiple groups might need expanding. $indent contains
# a number of tabs, for human-readability.
# -------------------------------------------------------------------------
sub fooGroupExpander
{
	my($fileNames, $myGroups, $indent, $pIndex, $map) = @_;

	my(@otherGroups) = @{$myGroups};
	my($group) = shift @otherGroups;
	my($if) = "if";
	my($acl, @newFileNames);

	if (! defined $group) {		# end-of-the-road!  time to do something (generate tabulation code)

		$code .= $indent . "\$category = \$category->{v};\n" if ($map);

		if (defined $fooMatrices{$papafoo}) {		# matrices = dynamic name generation

			foreach my $suffix (keys %{$fileSpecial{$papafoo}}) {
				foreach (@{$fileNames}) {
					next if (! /\.$suffix$/);
					$code .= $indent . "# '$_' gets something special\n";
					$code .= $indent . "print {\"" . $fileSpecial{$papafoo}->{$suffix} . "\"} \$raw;\n";
				}
			}

			# the array of names has %s's that need to be replaced with a
			# variable number of matrix values

			# first, set a papafoo value if there are any matrix counters
			foreach (@{$fooMatrices{$papafoo}}) {
				$fooMatrixCount{$papafoo} = 1 if ($matrixCount{$_});
			}

			my $stemcount = 0;
			my %stem;
			foreach my $matrix (@{$fooMatrices{$papafoo}}) {
				my $stemvar = "\$stem" . $stemcount;
				if (my $stem = &fooMatrixStem($matrixType{$matrix})) {
					$code .= $indent . "$stemvar = " . $stem . ";\n";
					$stem{$stemcount} = 1;
				}
				$stemcount++;
			}

			my $ifmatrixflag = 0;
			foreach (@{$fooMatrices{$papafoo}}) {
				$ifmatrixflag = 1, last if (/^interfaces$/i);
			}

			foreach my $inout ("in", "out") {

				if ($inout eq "out") {		# for 'out' data, skip if all matrices are nexthop or protocol, which are directionless.
					next if ( ! grep(!/^(nexthop|protocol)$/i, @{$fooMatrices{$papafoo}}) );
				}

				my $bracketsNeeded;
				foreach my $matrix (@{$fooMatrices{$papafoo}}) {
					if (defined $matrixMask{$matrix} || (! $matrixAuto{$matrix})) {
						$bracketsNeeded = 1; last;
					}
				}

				$code .= $indent . "# analyze flow in the '$inout' direction\n";
				if ($ifmatrixflag) {
					$code .= $indent . "if (defined \$$inout" . "put_if_name) {\n";
					$bracketsNeeded=1;
				}
				elsif ($bracketsNeeded) {
					$code .= $indent . "{\n";
				}

				$indent = "$indent\t";

				my(@chashes, @hashes, $hashvar, $stemvar);
				my $hashcount = 0;
				my %matrixTypeTracker;			# used to see if we need to invert in/out on duplicate matrices

				foreach my $matrix (@{$fooMatrices{$papafoo}}) {
					my $io = ($inout eq "in");			# shortcut

					$io = ! $io if ($matrixTypeTracker{$matrixType{$matrix}} % 2);

					$matrixTypeTracker{$matrixType{$matrix}}++;

					# for nexthop/protocol, only add this flow to the 'in' category

					$stemvar = "\$stem" . $hashcount if ($stem{$hashcount});
					$hashvar = "\$hash" . $hashcount++;

					# 8-2-2004 this could be optimized by a trie, too...
					$code .= $indent . "last if (! " .
						&fooMatrixMask($matrixType{$matrix}, $io, $matrixMask{$matrix}) .
						" );\n" if (defined $matrixMask{$matrix});

					if ($matrixCount{$matrix}) {
						push(@chashes,
							&fooMatrixValue($matrixType{$matrix},
								$io,
								$matrixCount{$matrix}) ); 
						next;
					}

					push(@hashes, $hashvar);

					# IP matrices
					if ($matrixType{$matrix} =~ /^(ip|subnet|nexthop)$/) {
						my $maskVar = ( ($matrixType{$matrix} ne "subnet") ? "32" : 
							(($io) ? "\$src_mask" : "\$dst_mask")
						);

						my $ipVar = ( ($matrixType{$matrix} eq "nexthop") ? "\$nexthop" :
							(($io) ? "\$srcaddr" : "\$dstaddr")
						);

						if ($matrixAuto{$matrix}) {		# AUTO
							if (defined $matrixExact{$matrix}) {
					#			$code .= "$indent\$bits = $matrixExact{$matrix};\n";
								$maskVar = $matrixExact{$matrix};
							}
							elsif (defined $matrixBits{$matrix}) {
								$code .= "$indent\$bits = (" .
									"((! $maskVar) || ( $maskVar > $matrixBits{$matrix})) ? " .
									$matrixBits{$matrix} . " : $maskVar );\n";
								$maskVar = "\$bits";
							}

							$code .= $indent . "if (! ($hashvar = \$MATRIX_$matrix->match_exact_integer(" .
								"$ipVar, $maskVar)) ) {\n";

							$code .= $indent . "\t$hashvar = " .
								(($stemvar) ? "$stemvar . " : '') .
								&fooMatrixValue($matrixType{$matrix},
									$io,
									$matrixCount{$matrix},
									$maskVar) .
									";\n";

							$code .= $indent . "\t\$MATRIX_$matrix" . "->add_string( " .
								&fooMatrixIP($ipVar, $maskVar) . ", $hashvar);\n";

							$code .= $indent . "}\n";

						}
						else {
							$code .= $indent . "$hashvar = \$MATRIX_$matrix" . "->match_integer(" .
								"$ipVar) || '$OTHER';\n";
						}
					}

					# Non-IP matrices
					else {
						my $key =  (($stemvar) ? "$stemvar . " : '') .  &fooMatrixValue($matrixType{$matrix}, $io, $matrixCount{$matrix});

						if (defined $matrixXForm{$matrix}) {		# perform xform
							$code .= "$indent$hashvar = (\$XFORM_$matrix" . "[$key] || $key);\n";
						}
						else {
							$code .= "$indent$hashvar = $key;\n";
						}

						if (! $matrixAuto{$matrix}) {	# use 'Other' if nonexistant and not in auto mode
							$code .= $indent . "$hashvar = '$OTHER' " .
								"if (! exists \$MATRIX_$matrix" . "{$hashvar});\n";
						}
						else {
							$code .= $indent .
								"\$MATRIX_$matrix" . "{$hashvar} = 1;\n";
						}
					}
				}

				foreach my $f (@{$fileNames}) {
					# register the filenames for flushData use

					if ($map) {		# register all map values
						foreach ( @{$mapOrder{$map}} ) {
							my $newf = $f;
							$newf =~ s/\$category/$_/;
							&fooFileIndex($newf);
						}
					}
					else {
						&fooFileIndex($f);
					}


					# THIS IS THE BAD BOY

					next if ($f =~ /\.Any/);	# no 'Any' files!
					$code .= "\n" . $indent . "# tally for $f\n";

					# code to generate the filename is in $tfoo
					my $tfooVar = "\$tfoo";

					if (@hashes) {
						my $count = 0;
						$f =~ s/\%s/$hashes[$count++]/ge;
						$code .= $indent . "\$tfoo = \"$f\";\n";

					}
					else {
						$tfooVar = "'" . $f . "'";
					}

					if (@chashes) {			# simple 'unique key' counters
						$code .= $indent . "\$cmatrix_$inout" . "{$tfooVar}->{" .
							join(",", @chashes) . "} ++;\n";
					}
					elsif ($fileType{$papafoo} == $foo_rrd) {		# RRD files
						$code .= &tabulator('$tfoo', $indent, $inout,
							$fileBucket{$papafoo},
							$fileStep{$papafoo},
							$fileIPTracking{$papafoo},
							($fileTimestamp{$papafoo} !~ /(start|end|average)/),
							$pIndex);
					}
					elsif ($fileType{$papafoo} == $foo_text) {		# TEXT files
						$code .= $indent . "\$\$tfoo .= " . &wantedTXT . ";\n";
					}
					elsif ($fileType{$papafoo} == $foo_csv) {		# CSV files
						$code .= $indent . "\$\$tfoo .= " . &wantedCSV . ";\n";
					}
					elsif ($fileType{$papafoo} == $foo_flow) {		# raw FLOW files
						$code .= $indent . "\$\$tfoo .= \$raw;\n";
					}

					if ($deepDebugExpression) {
						$code .= "if (\$DEEPDEBUG) {\n" .
							"\tprint \"tabulating tfoo '\$tfoo', inout '$inout'\\n\";\n" .
							"}\n";
					}
				}

				chop $indent;
				$code .= $indent . "}" if ($bracketsNeeded);
				$code .= "\n";
			}

		}
		else {					# no matrices = static name generation
			my(@fooTargetIndecies);

			foreach (@{$fileNames}) {
				push(@fooTargetIndecies, &fooFileIndex($_));
			}

			$code .= $indent . "push(\@fooTargets, " . join(", ", @fooTargetIndecies) . ");\n";
		}

		return 1;
	}


	# For a matrix, ...
	if ($matrixType{$group}) {		# interfaces
		undef @newFileNames;
		foreach (@{$fileNames}) {
			if ($matrixCount{$group}) {	# for matrix tabulations, use a special file
				push(@newFileNames, "$_._" . $matrixType{$group});
			}
			else {				# for matrix tracking, use a file based on the matrix name
				push(@newFileNames, "$_.%s");
			}
		}

		return &fooGroupExpander([@newFileNames], [@otherGroups], $indent);
	}

	# For a group, create a big set of if, elsif, elsif, ... clauses

	my $index = 0;

	foreach my $acl (@{$groups{$group}}) {
		my $map;

		if ($acl =~ /^MAP_/) { 			# this ain't an ACL; it's a map!
			$map = $acl;
			$code .= $indent . "$if (" . &mapCode($acl) . ") {\n";
			$if = "elsif";
		}
		elsif ($acl =~ /^ACL_/) {
			$code .= $indent . "$if (\$$acl) {\n";
			$if = "elsif";
		}
		else {
			&logit($LOG_ERROR, "Internal error! Unrecognized ACL type - $acl");
			print "ACL error\n";
			return 0;
		}

		if ( ($filePacked{$papafoo}) && (! @otherGroups) ) {	# don't add last group value to filename if packed
			@newFileNames = @{$fileNames};
		}
		else {
			undef @newFileNames;
			foreach my $f (@{$fileNames}) {
				if ($acl =~ /^ACL_(.*)/) {
					push(@newFileNames, "$f.$1");
				}
				elsif ($acl =~ /^MAP_/) {
					push(@newFileNames, "$f.\$category");

				}
				push(@newFileNames, "$_.Any");
			}
		}

		return 0 if (! &fooGroupExpander([@newFileNames], [@otherGroups], "\t$indent", ($filePacked{$papafoo}) ? $index++ : undef, $map) );

		$code .= $indent . "}\n";
	}

	# then, add the final else clause (aka 'other')

	$code .= $indent . "else {\n";

	undef @newFileNames;
	foreach (@{$fileNames}) {
		if ( ($filePacked{$papafoo}) && (! @otherGroups)) {
			push(@newFileNames, $_);
		}
		else {
			push(@newFileNames, "$_.$OTHER");
		}
	}

	return 0 if (! &fooGroupExpander([@newFileNames], [@otherGroups], "\t$indent", ($filePacked{$papafoo}) ? $index++ : undef) );
	$code .= $indent . "}\n";

	return 1;
}

# generate perl code for checking a map
sub mapCode
{
	my $map = shift;
	my $simple = shift;
	my $code;

	if ($simple) {
		$code = <<EOT;
( (\$$map->match_integer(\$srcaddr)) || (\$$map->match_integer(\$dstaddr)) )
EOT
	}
	else {
		$code = <<EOT;
(
	((\$protocol==6) || (\$protocol == 17)) &&
	(
		( (\$srcport < 1024) && (\$category=\$$map->match_integer(\$srcaddr)) )  ||
		( (\$dstport < 1024) && (\$category=\$$map->match_integer(\$dstaddr)) )
	)
)
|| (\$category=\$$map->match_integer(\$srcaddr))
|| (\$category=\$$map->match_integer(\$dstaddr))
EOT
	}

	$code =~ s/\s+/ /gm;
	return $code;
}

# ----------------------------------------------------------------------------
# returns code to tabulate a flow. Used by fooGroupExpander and wantedCompiler
#  foo = variable to be used, including $ (should be like '$tfoo') - may be a ref to an array of variables
#  indent = text indenting
#  inout = 'in' or 'out'
#  res = file resolution or blank for default  (bucket)
#  step = how many seconds per datapoint  (UNUSED)
#  iptrack = 1 if ip tracking enabled
#  dist = 1 if bucketMax is defined and traffic is to be distributed...
#  pIndex = 1

# must include this code for any foo that uses buckets
sub tabulatorBucketInit
{
	return split(/\n/, <<EOT);
if (\$bucketMax > 1) {
	\$bbytes = \$bytes / \$bucketMax;
	\$bpkts = \$pkts / \$bucketMax;
	\$bflows = 1 / \$bucketMax;

	if (\$bucketMax > 10) {
		&logit(\$LOG_INFO, "Excessively long flow \$exporterip \$srcip:\$srcport->\$dstip:\$dstport bucketMax=\$bucketMax");
	}
}
EOT
}

sub tabulator
{
	my($foo, $indent, $inout, $res, $step, $iptrack, $dist, $skipcalcs, $pIndex) = @_;
	my($acc, @tabFoos, @code);

	if (! ref($foo)) {	# scalar
		push(@tabFoos, ($foo !~ /^\$/) ? "'" . $foo . '"' : $foo);
	}
	else {			# arrayref
		foreach (@$foo) {
			push(@tabFoos, (! /^\$/) ? "'" . $_ . '"' : $_);
		}
	}
	
	my $BYTE_COUNTER = (($inout eq "in") ? $BYTE_IN_COUNTER : $BYTE_OUT_COUNTER);
	my $PKT_COUNTER = (($inout eq "in") ? $PKT_IN_COUNTER : $PKT_OUT_COUNTER);
	my $FLOW_COUNTER = (($inout eq "in") ? $FLOW_IN_COUNTER : $FLOW_OUT_COUNTER);

	if ($res > 0) {
		if ( $dist) {
			push(@code,
				"if (\$bucketMax > 1) {",
			);

#			push(@code,
#				"\t\$bbytes = \$bytes / \$bucketMax;",
#				"\t\$bpkts = \$pkts / \$bucketMax;",
#				"\t\$bflows = 1 / \$bucketMax;",
#			) if (! $skipcalcs);

			push(@code,
				"\tforeach (1 .. \$bucketMax) {"
			);

			foreach (@tabFoos) {
				push(@code,
					"\t\t\$b = \\\$buckets{" . $_ . "}->" . ((defined $pIndex) ? "[$pIndex]->" : "") . "[\$bucket + \$_ - 1];",
					"\t\t\$\$b->[$BYTE_COUNTER] += \$bbytes;",
					"\t\t\$\$b->[$PKT_COUNTER] += \$bpkts;",
					"\t\t\$\$b->[$FLOW_COUNTER] += \$bflows;"
				);

				if ( ($iptrack) && ($inout eq "in") ) {
					push(@code, "\t\tif (! \$MEM_OVERLOAD_CONDITION) {") if ($MEM_OVERLOAD_PROTECTION);
					push(@code, 
						"\t\t\$\$b->[$IP_IN_COUNTER]->{\$srcaddr} = 1;",
						"\t\t\$\$b->[$IP_OUT_COUNTER]->{\$dstaddr} = 1;"
					);
					push(@code, "\t\t}") if ($MEM_OVERLOAD_PROTECTION);
				}
			}

			push(@code,
				"\t}",
				"}",
				"else {"
			);

		}

		foreach (@tabFoos) {
			push(@code,
#				"\t\$b = \\\$buckets{" . $_ . "}->[\$bucket];",
				"\t\$b = \\\$buckets{" . $_ . "}->" . ((defined $pIndex) ? "[$pIndex]->" : "") . "[\$bucket];",
				"\t\$\$b->[$BYTE_COUNTER] += \$bytes;",
				"\t\$\$b->[$PKT_COUNTER] += \$pkts;",
				"\t\$\$b->[$FLOW_COUNTER] ++;"
			);

			if ( ($iptrack) && ($inout eq "in") ) {
				push(@code, "\tif (! \$MEM_OVERLOAD_CONDITION) {") if ($MEM_OVERLOAD_PROTECTION);
				push(@code, 
					"\t\t\$\$b->[$IP_IN_COUNTER]->{\$srcaddr} = 1;",
					"\t\t\$\$b->[$IP_OUT_COUNTER]->{\$dstaddr} = 1;"
				);
				push(@code, "\t}") if ($MEM_OVERLOAD_PROTECTION);
			}
		}

		if ($dist) {
			push(@code,
				"}"
			);
		}
	}
	else {						# default '$period' resolution
		foreach (@tabFoos) {
			push(@code,
				"\$b = \\\$buckets{" . $_ . "}->" . ((defined $pIndex) ? "[$pIndex]->" : "") . "[0];",
				"\$\$b->[$BYTE_COUNTER] += \$bytes;",
				"\$\$b->[$PKT_COUNTER] += \$pkts;",
				"\$\$b->[$FLOW_COUNTER] ++;"
			);

			push(@code, 
				"\$\$b->[$IP_IN_COUNTER]->{\$srcaddr} = 1;",
				"\$\$b->[$IP_OUT_COUNTER]->{\$dstaddr} = 1;"
			) if ( ($iptrack) && ($inout eq "in") );
		}
	}

	foreach (@code) { $acc .= ((/^$/) ? "\n" : $indent . $_ . "\n"); }
	return $acc;
}

# ----------------------------------------------------------------------------
sub bucketsPerStep
{
	my($BUCKETS) = $_[0];				# $fileBucket
	my($PERIOD_OR_STEP) = $_[1] || $period;		# $fileStep, if set. otherwise $period.

	return POSIX::ceil($PERIOD_OR_STEP / ($BUCKETS || 300));
}

# ----------------------------------------------------------------------------
# returns code that generates a matrix name compatible IP address, AS number, or whatever
#  $myvar is the variable to be assigned
#  $inout = 1 for in, 0 for out
#  $matrixType = 'as', 'ip', 'subnet', 'if', 'protocol', 'port', 'nexthop',
#  $indent = an indentation amount (tabs)

sub fooMatrixStem
{
	my $matrixType = shift;
	my $exp;

	if ($matrixType =~ /^if$/) {
		if ($BIG_ENDIAN) {	# big-endian needs to be flipped
			$exp = "\$exporterName{\$exporter} || sprintf('%d-%d-%d-%d', " .
				"\$exporter & 0xff, \$exporter >> 8 & 0xff, \$exporter >> 16 & 0x0ff, \$exporter >> 24)";
		}
		else {			# little-endian is already in native network order
			$exp = "\$exporterName{\$exporter} || sprintf('%d-%d-%d-%d', " .
				"\$exporter >> 24, \$exporter >> 16 & 0x0ff, \$exporter >> 8 & 0xff, \$exporter & 0xff)";
		}

		return "($exp) . '#'";
	}
	return;
}

sub fooMatrixValue
{
	my($matrixType, $inout, $simple, $maskOverride) = @_;
	my($code, $stem);

	if ($matrixType =~ /^(ip|nexthop)$/) {		# key is 
		my $v = ($matrixType =~ /^nexthop$/) ? "\$nexthop" : ($inout) ? "\$srcaddr" : "\$dstaddr";
		return $v if ($simple);

		if ($BIG_ENDIAN) { $code = "sprintf('%d-%d-%d-%d', $v & 0xff, $v >> 8 & 0xff, $v >> 16 & 0x0ff, $v >> 24)"; }
		else { $code = "sprintf('%d-%d-%d-%d', $v >> 24, $v >> 16 & 0x0ff, $v >> 8 & 0xff, $v & 0xff)"; }
	}
	elsif ($matrixType =~ /^subnet$/) {
		my $v = ($inout) ? "\$srcaddr" : "\$dstaddr";
		my $vm = ($maskOverride) || (($inout) ? "\$src_mask" : "\$dst_mask");
		$v = "($v & (($vm) ? (0xffffffff << (32-$vm)) : 0))";
		return $v if ($simple);

		# note, a global $v2 is created by this routine (faster than using $_ or 'my')
		if ($BIG_ENDIAN) {	# big-endian needs to be flipped
			$code = "sprintf('%d-%d-%d-%d_%d', (\$v2 = $v) & 0xff, " .
				"\$v2 >> 8 & 0xff, \$v2 >> 16 & 0x0ff, \$v2 >> 24, $vm)";
		}
		else {			# little-endian is already in native network order
			$code = "sprintf('%d-%d-%d-%d_%d', (\$v2 = $v) >> 24, " .
				"\$v2 >> 16 & 0x0ff, \$v2 >> 8 & 0xff, \$v2 & 0xff, $vm)";
		}
	}
	elsif ($matrixType =~ /^as$/) {
		$code = (($inout) ? "\$src_as" : "\$dst_as");
	}
	elsif ($matrixType =~ /^protocol$/) {
		return "\$protocol" if ($simple);
		$code = "\$cisco_iprotocols{\$protocol} || \$protocol";
	}
	elsif ($matrixType =~ /^port$/) {
		$code = (($inout) ? "\$srcport" : "\$dstport");
	}
	elsif ($matrixType =~ /^if$/) {
		my($if, $exp);

		$if = (($inout) ? "\$input_if" : "\$output_if");
		return "\$exporter-$if" if ($simple);

		$code .= $if . "_name";		# precomputed name
	}
	return $code;
}

sub fooMatrixIP
{
	my ($v, $m) = @_;
	my $code;

	if ($BIG_ENDIAN) {	# big-endian needs to be flipped
		if ($m) { $code = "sprintf('%d.%d.%d.%d\/%d', $v & 0xff, $v >> 8 & 0xff, $v >> 16 & 0x0ff, $v >> 24, $m)"; }
		else {    $code = "sprintf('%d.%d.%d.%d', $v & 0xff, $v >> 8 & 0xff, $v >> 16 & 0x0ff, $v >> 24)"; }
	}
	else {
		if ($m) { $code = "sprintf('%d.%d.%d.%d\/%d', $v >> 24, $v >> 16 & 0x0ff, $v >> 8 & 0xff, $v & 0xff, $m)"; }
		else {    $code = "sprintf('%d.%d.%d.%d', $v >> 24, $v >> 16 & 0x0ff, $v >> 8 & 0xff, $v & 0xff)"; }
	}

	return $code;
}

# ----------------------------------------------------------------------------
# if a matrix is restricted by a mask, compile a boolean clause that returns
# true if the mask passes, or false if it fails.
# ----------------------------------------------------------------------------
sub fooMatrixMask
{
	my($matrixType, $inout, $matrixMask) = @_;
	my($v, @masks, $ipaddr, $ipmask);

	if ($matrixType =~ /^(ip|subnet|nexthop)$/) {	# ip or subnet
		if (($1 eq "ip") || ($1 eq "subnet")) {
			$v = ($inout) ? "\$srcaddr" : "\$dstaddr";
		}
		elsif ($1 eq "nexthop") {
			$v = "\$nexthop";
		}

		foreach (@$matrixMask) {
			next if (! /^(.*)\/(\d+)$/);
			$ipmask = 0xffffffff << (32-$2);
			next if (! defined ($ipaddr = &hackIP($1)));
			$ipaddr = $ipaddr & $ipmask;
			push(@masks, (! $ipmask) ? "($v == " . &hexit($ipaddr) . ")" :
				"(($v & " . &hexit($ipmask) . ") == " . &hexit($ipaddr) . ")" );
		}
	}
	elsif ($matrixType =~ /^(as|port)$/) {		# as or port range
		if ($1 eq "as") {
			$v = ($inout) ? "\$src_as" : "\$dst_as";
		}
		elsif ($1 eq "port") {
			$v = ($inout) ? "\$srcport" : "\$dstport";
		}

		foreach (@$matrixMask) {
			if (/^(\d+)-(\d+)$/) {
				push(@masks, &aclCompileMatchRange($v, 5, $1, $2));
			}
			elsif (/^(\d+)$/) {
				push(@masks, &aclCompileMatchRange($v, 1, $1));
			}
		}
	}

	return (@masks) ? "(" . join(" || ", @masks) . ")" : "(1)";
}

# ----------------------------------------------------------------------------
# converts an ASCII string into a matrix value, or returns undef if an error.
# fiddles with Cflow's global values...
# ----------------------------------------------------------------------------
sub a2MatrixValue
{
	my($matrixType, $fodder) = @_;

	if ($matrixType =~ /^ip$/) {
		return undef if (! defined ($dstaddr = &hackIP($fodder)));
	}
	elsif ($matrixType =~ /^nexthop$/) {
		return undef if (! defined ($nexthop = &hackIP($fodder)));
	}
	elsif ($matrixType =~ /^subnet$/) {
		return undef if ($fodder !~ /^(\d+)([\d\.]+)\/?(\d*)$/);
		$dst_mask = $3 || (($1<128) ? 8 : ($1<192) ? 16 : 24);
		return undef if (! defined ($dstaddr = &hackIP("$1$2")));
	}
	elsif ($matrixType =~ /^as$/) {
		return undef if ($fodder !~ /^(\d+)$/);
		$dst_as = $fodder;
	}
	elsif ($matrixType =~ /^port$/) {
		return undef if ($fodder !~ /^(\d+)$/);
		$dstport = $fodder;
	}
	elsif ($matrixType =~ /^protocol$/) {
		if ($fodder !~ /^(\d+)$/) {
			$fodder = $cisco_protocols{lc $fodder} || return undef;
		}
		$protocol = $fodder;
	}
	else { return undef; }

	eval "return " . &fooMatrixValue($matrixType) . ";";
}

# ----------------------------------------------------------------------------
# given a foo name ("Videoconf.%s.%s") and an pointer to array of matrices, this
# returns an array of foo file names. Calls itself recursively.
# ----------------------------------------------------------------------------
sub fooMatrixExpansion
{
	my($foo, $matrices, $level, $values) = @_;
	my($matrix);

	{
		$matrix = ${$matrices}[$level++];
		redo if ($matrixCount{$matrix});		# skip matrix tabulations...
	}

	if (defined $matrix) {
		my (@stuff, $hash);

		if ($matrixType{$matrix} =~ /^(ip|subnet|nexthop)$/) {
			${"MATRIX_$matrix"}->climb(sub { $hash->{$_[0]} = 1; });
		}
		else {
			$hash = \%{"MATRIX_$matrix"};
		}

# forgot what I was trying to accomplish with this code
#
#		if ($matrixType{$matrix} eq "if") {		# possibly poll 
#			foreach (keys %$hash) {
#				if (/^(\d+)\-(\d+)\-(\d+)\-(\d+)#(\d+)$/) {		# exporter#interface
#				}
#			}
#		}

		foreach (keys %$hash) {
			push(@stuff, &fooMatrixExpansion($foo, $matrices, $level, [@$values, $_]));
		}

		if (! $matrixAuto{$matrix}) {		# include the 'Other' category
			push(@stuff, &fooMatrixExpansion($foo, $matrices, $level, [@$values, $OTHER]));
		}

		return @stuff;
	}
	else {			# end of the road
		return sprintf($foo, @$values);
	}
}

# ----------------------------------------------------------------------------
#  ACL COMPILER code -- compiles ACLs into a single perl expression that can
#  be used for assignment, boolean tests, or otherwise. The expression may
#  be long, but it'll always work. expressions are stored in the global hash
#  %aclCode with the ACL name as the key.
# ----------------------------------------------------------------------------
sub aclCompiler
{
	my($foo, $acl, $racl, $x, @unusedACLs);

	# compile all foo ACLs...
	foreach my $foo (keys %foos) {
		foreach my $x (@{$foos{$foo}}) {
			next if ($x eq "!");

			if ($groups{$x}) {		# group of ACLs
				foreach my $acl (@{$groups{$x}}) {
					return 0 if (! &aclCompileIt($acl));
				}
			}
			else {				# a single ACL
				return 0 if (! &aclCompileIt($x));
			}
		}

		if (defined $fileInACL{$foo}) {
			return 0 if (! &aclCompileIt($fileInACL{$foo}));
		}

		if (defined $fileOutACL{$foo}) {
			return 0 if (! &aclCompileIt($fileOutACL{$foo}));
		}
	}

	# compile racl ACLs...
	foreach my $racl (@racls) {
		return 0 if (! &aclCompileIt($racl->{acl}));
	}

	# compile localNextHops...
	return 0 if (! &aclCompileIt($localNextHops));

	# if there are other ACLs, compile them but add them to %aclCodeUnused (they may actually be used for ACL maps)
	foreach my $acl (keys %acl_list) {
		push(@unusedACLs, $acl) if (&aclCompileIt($acl) == 2);		# special return code
	}

	foreach my $acl (@unusedACLs) {
		$aclCodeUnused{$acl} = delete $aclCode{$acl};
	}

	return 1;
}

# ----------------------------------------------------------------------------
# for each ACL, generates a subroutine of the same name with only the code necessary
# to process the ACL
sub aclCompileIt
{
	my($acl) = @_;
	my($rule, $code, @rules);
	my($ruleCounter) = 0;
	my($lastPermit) = -1;

	# -- see if the subroutine already exists...
	return 1 if ( (defined $aclCode{$acl}) || ($acl !~ /^ACL_/) );

	# -- compose ACL code
	foreach my $rule (@{$acl}) {
		$ruleCounter++;

		if ($OPTIMIZE_ACLS) {		# Generate optimized ACLs (experimental)
			if ($rule->{permit} != $lastPermit) {
				if (@rules) {
					$code .= &aclCompileOptimizer(@rules) . " ? $lastPermit : ";
					undef @rules;
				}
				$lastPermit = $rule->{permit};
			}

			my %ruleHash;
			foreach (&aclCompileRule($rule)) { $ruleHash{$_} = 1; }
			push(@rules, \%ruleHash);
		}
		else {				# Generate run-of-the-mill ACLs
			$code .= "( " . join(" && ", &aclCompileRule($rule)) . ") ? $rule->{permit} : ";
		}
	}

	if (($OPTIMIZE_ACLS) && ($lastPermit)) {		# Add last set of optimized ACL rules
		$code .= &aclCompileOptimizer(@rules) . " ? $lastPermit : 0";
	}
	else {
		$code .= "0";
	}

	if ($ruleCounter > 0) {		# -- compile the code
		$srcaddr = &composeIP(0, 0, 0, 0);
		$dstaddr = &composeIP(0, 0, 0, 0);
		$code = "($code)";
		no strict "vars";
		eval $code;
		use strict "vars";

		if ($@) {
			&logit($LOG_ERROR, "Error EVAL'ing acl $acl");
			&logit($LOG_ERROR, " " . $@);
 			&logit($LOG_ERROR, " code: $code");
			return 0;
		}
		$aclCode{$acl} = $code;
	}

	return 2;
}

# -------------------------------------------------------------------------
# Given an array of hash pointers, one array element for each rule and the hash
# composed of the expressions to evaluate, this returns a string containing
# the optimal expression, eliminating duplicate tests wherever possible. In
# practice, this only helps speed up large, poorly-written ACLs. Well-designed
# ACLs see little benefit.

sub aclCompileOptimizer
{
	my(@rules) = @_;
	my($rule, @orExps);

	return if (! @rules);
	die "OPTIMIZE_ACLS recursion depth gone amuck!" if ($aclOptimizeDepth++ > 100);

	while (@rules) {		# while we have rules to process...
		my($maxExp, %keyCounter);

		# tabulate the expressions across all rules and find the one with the most ($maxExp)
		foreach my $rule (@rules) {
			foreach (keys %$rule) {
				$maxExp = $_ if (++$keyCounter{$_} > $keyCounter{$maxExp});
			}
		}

		my(@toProcess, @toPostpone);
		foreach (@rules) {
			if (delete $$_{$maxExp})	{ push(@toProcess, $_) if (scalar keys %$_); }
			else				{ push(@toPostpone, $_); }
		}

		@rules = @toPostpone;
		push(@orExps, smartJoin(' && ', $maxExp, &aclCompileOptimizer(@toProcess)) );
	}

	$aclOptimizeDepth--;
	return smartJoin(' || ', @orExps);
}

# ----------------------------------------------------------------------------
# like a normal join, but adds paren's around the whole thing if there are multiple elements
sub smartJoin
{
	return (@_ > 2) ? "(" . join(shift @_, @_) . ")" : pop @_;
}

# ----------------------------------------------------------------------------
# This rule is broken down into an array of expressions needed to satisfy
# the rule. Ordering of the array is not important since it will be
# optimized once all the rules have been generated.

sub aclCompileRule
{
	my($rule) = $_[0];
	my($x, @code);

	# check a facl hash
	if (exists $rule->{facl}) {
		push(@code, $rule->{facl});
	}

	# check the protocol (always in the ACL, but may be 0 for a wildcard)
	if ($rule->{protocol} > 0) {
		push(@code, '($protocol == ' . $rule->{protocol} . ')' );
	}

	# check to see if we are looking for a specific exporter

	# check the nexthop
	if (defined $rule->{exporterIP}) {
		if ($rule->{exporterMask} == 0xffffffff) {				# single IP
			push(@code, '($exporter == ' . &hexit($rule->{exporterIP}) . ')' );

			# and if we have matched a specific exporter, check for interface rules
			if (defined $rule->{sourceIf}) {
				push(@code, '($input_if == ' . $rule->{sourceIf} . ')' );
			}

			if (defined $rule->{destinationIf}) {
				push(@code, '($output_if == ' . $rule->{destinationIf} . ')' );
			}
		}
		else {									# wildcard
			push(@code, '(($exporter & ' . &hexit($rule->{exporterMask}) . ') == ' . &hexit($rule->{exporterIP}) . ')' );
		}
	}

	# ToS and precedence are combined into a one-byte value, '$tos'. It has two
	# interpretations...
	#
	#   0x80  0x40  0x20  0x10  0x08  0x04  0x02  0x01
	#  +-----+-----+-----+-----+-----+-----+-----+-----+
	#  |   PRECEDENCE    |          TOS          |  0  |
	#  +-----+-----+-----+-----+-----+-----+-----+-----+
	#
	#  +-----+-----+-----+-----+-----+-----+-----+-----+
	#  |             DSCP                  | ECN | ECN |
	#  +-----+-----+-----+-----+-----+-----+-----+-----+
	#
	# TOS (0-15)
	#  1000 - minimize delay
	#  0100 - maximize throughput
	#  0010 - maximize reliability
	#  0001 - minimize monetary cost
	#  0000 - normal service
	#
	# PRECEDENCE (0-7)
	#  111 - Network Control
	#  110 - Internetwork Control
	#  101 - CRITIC/ECP
	#  100 - Flash Override
	#  011 - Flash
	#  010 - Immediate
	#  001 - Priority
	#  000 - Routine
	#
	# DSCP (0-63)

	if (defined $rule->{tos}) {
		push(@code, '($tos == ' . $rule->{tos} . ')' );
	}

	if (defined $rule->{precedence}) {
		push(@code, '(($tos >> 5) == ' . $rule->{precedence} . ')' );
	}

	if (defined $rule->{dscp}) {
		push(@code, '(($tos >> 2) == ' . $rule->{dscp} . ')' );
	}

	if (defined $rule->{ecn}) {
		if ($rule->{ecn} >= 4) { 	# match ect0 or ect1
			push(@code, '((($tos & 3) == 1) || (($tos & 3) == 2))' );
		}
		else {
			push(@code, '(($tos & 3) == ' . $rule->{ecn} . ')' );
		}
	}

	# check the nexthop
	if (defined $rule->{nextHopIP}) {
		if ($rule->{nextHopMask} == 0xffffffff) {				# single IP
			push(@code, '($nexthop == ' . &hexit($rule->{nextHopIP}) . ')' );
		}
		else {									# wildcard
			push(@code, '(($nexthop & ' . &hexit($rule->{nextHopMask}) . ') == ' . &hexit($rule->{nextHopIP}) . ')' );
		}
	}

	# check source AS (always in ACL, but may be 0 for wildcard)
	if (defined $rule->{sourceAS}) {
		push(@code, '($src_as == ' . $rule->{sourceAS} . ')' );
	}

	if ($rule->{sourceDACL}) {						# source IP is a DACL
		push(@code, '($' . $rule->{sourceIP} . '->match_integer($srcaddr)' .
			( ($available_dacl{$rule->{sourceIP}}) ? ' >= $startime' : '' ) .
			')' );
	}
	elsif ($rule->{sourceMask} == 0xffffffff) {				# single IP
		push(@code, '($srcaddr == ' . &hexit($rule->{sourceIP}) . ')' );
	}
	elsif ($rule->{sourceIP}) {						# wildcard
		push(@code, '(($srcaddr & ' . &hexit($rule->{sourceMask}) . ') == ' . &hexit($rule->{sourceIP}) . ')' );
	}

	# check source port (optional in ACL)
	if (defined $rule->{sourcePortMatch}) {
		push(@code, &aclCompileMatchRange(
			'$srcport', $rule->{sourcePortMatch},
			$rule->{sourcePort1}, $rule->{sourcePort2} )
		);
	}

	# check destination AS (always in ACL, but may be 0 for wildcard)
	if (defined $rule->{destinationAS}) {
		push(@code, '($dst_as == ' . $rule->{destinationAS} . ')' );
	}

	if ($rule->{destinationDACL}) 		{				# destination IP is a DACL
		push(@code, '($' . $rule->{destinationIP} . '->match_integer($dstaddr)' .
			( ($available_dacl{$rule->{destinationIP}}) ? ' >= $startime' : '' ) .
			')' );
	}
	elsif ($rule->{destinationMask} == 0xffffffff) {			# single IP
		push(@code, '($dstaddr == ' . &hexit($rule->{destinationIP}) . ')' );
	}
	elsif ($rule->{destinationIP}) {					# wildcard
		push(@code, '(($dstaddr & ' . &hexit($rule->{destinationMask}) . ') == ' . &hexit($rule->{destinationIP}) . ')' );
	}

	# check icmp codes
	if (defined $rule->{icmpMsgs}) {
		my($icmpType, $icmpCode, @icmpItems);
		foreach (@{$rule->{icmpMsgs}}) {
			$icmpType = ($_ >> 8) & 0xff;
			$icmpCode = $_ & 0xff;
			push(@icmpItems, ($icmpCode == 0xff) ?
				"(\$ICMPType == $icmpType)" :						# wildcard
				"((\$ICMPType == $icmpType) && (\$ICMPCode == $icmpCode))");		# specific
		}
		push(@code, "(" . join(" || ", @icmpItems) . ")" );
	}

	# check tcp flags
	if (defined $rule->{tcpFlags}) {
		push(@code, '(($tcp_flags & 0x' . sprintf("%02x", $rule->{tcpFlags}) . ') == 0x' .
			sprintf("%02x", $rule->{tcpFlags}) . ')' );
	}
	if (defined $rule->{tcpNotFlags}) {
		push(@code, '(! ($tcp_flags & 0x' . sprintf("%02x", $rule->{tcpNotFlags}) . '))' );
	}

	# check destination port (optional in ACL)
	if (defined $rule->{destinationPortMatch}) {
		push(@code, &aclCompileMatchRange(
			'$dstport', $rule->{destinationPortMatch},
			$rule->{destinationPort1}, $rule->{destinationPort2} )
		);
	}

	# check bytes (optional in ACL)
	if (defined $rule->{bytesMatch}) {
		push(@code, &aclCompileMatchRange(
			'$bytes', $rule->{bytesMatch}, $rule->{bytes1}, $rule->{bytes2} )
		);
	}

	# check packets (optional in ACL)
	if (defined $rule->{packetsMatch}) {
		push(@code, &aclCompileMatchRange(
			'$pkts', $rule->{packetsMatch}, $rule->{packets1}, $rule->{packets2} )
		);
	}

	# check seconds (optional in ACL)
	if (defined $rule->{secondsMatch}) {
		push(@code, &aclCompileMatchRange(
			'$endtime - $startime', $rule->{secondsMatch},
			$rule->{seconds1}, $rule->{seconds2} )
		);
	}

	# check bps, Bytes Per Second (optional in ACL)
	if (defined $rule->{bpsMatch}) {
		push(@code, &aclCompileMatchRange(
			'$Bps', $rule->{bpsMatch}, $rule->{bps1}, $rule->{bps2} )
		);
	}

	# check pps, Packets Per Second (optional in ACL)
	if (defined $rule->{ppsMatch}) {
		push(@code, &aclCompileMatchRange(
			'$pps', $rule->{ppsMatch}, $rule->{pps1}, $rule->{pps2} )
		);
	}

	# check packetsize, Average Packet Size (optional in ACL)
	if (defined $rule->{packetsizeMatch}) {
		push(@code, &aclCompileMatchRange(
			'($bytes / ($pkts ? $pkts : 1))', $rule->{packetsizeMatch},
			$rule->{packetsize1}, $rule->{packetsize2} )
		);
	}

	return "1" if (! @code);				# permit ip any any

	return @code;
}

# -------------------------------------------------------------------------
# for readability, convert IPs/masks to hex for eval code generation
sub hexit
{
	return sprintf("0x%8.8x", $_[0]);
}

# -------------------------------------------------------------------------
# returns a snippet of code that performs a check on a number range (typically for ports)
# returns 0 for no match, != 0 for match
# -------------------------------------------------------------------------
sub aclCompileMatchRange
{
	my($target, $match, $m1, $m2) = @_;

	return "($target == $m1)" if ($match == 1);				# eq
	return "($target != $m1)" if ($match == 2);				# neq
	return "($target > $m1)" if ($match == 3);				# gt
	return "($target < $m1)" if ($match == 4);				# lt
	return "(($target >= $m1) && ($target <= $m2))" if ($match == 5);	# range
	return "($target >= $m1)" if ($match == 6);				# ge
	return "($target <= $m1)" if ($match == 7);				# le
	return "(0)";								# should never happen
}

sub loadWatchData
{
	my $stem;
	open(IN, $watchFile);
	while ( <IN> ) {
		chomp;
		if (/(flows[^\/]*)\.(gz|Z|zip)$/) {	$stem = $1; }
		elsif (/(flows[^\/]*)$/) {		$stem = $1; }
		elsif (/(ft-.*)/) {			$stem = $1; }
		else {					$stem = $_; }
		$watch_gotcha{$stem} = 1;
	}
	close(IN);
}

sub saveWatchData
{
	open(OUT, ">" . $watchFile);
	foreach (sort {$a cmp $b} keys %watch_gotcha) { print OUT "$_\n"; }
	close(OUT);
}

sub updateWatchData
{
	open(OUT, ">>" . $watchFile);
	foreach (@_) { print OUT "$_\n"; }
	close(OUT);
}

sub forkFileName
{
	my $file = shift;
	if ( ($forkMax) && ($forkPID) && ($file =~ /^(.*)(\.bin)$/) ) { $file = "$1-$forkPID$2"; }
	return $file;
}

sub saveDacls
{
	my ($file, @elements) = @_;
	my $count=0;

	if (open(DACL, ">$file")) {
		Storable::store_fd(\@elements, \*DACL);
		foreach (@elements) {
			my %hash;
			$$_->climb(sub { $hash{$_[0]->{k}} = $_[0]->{v}; $count++; });		# trie -> hash
			Storable::store_fd(\%hash, \*DACL);
		}
		close(DACL);
		&logit($LOG_DEBUG, "Saved " . (scalar @elements) . " dacls/host-lists with $count elements to $file") if (@elements);
	}
	elsif (! $checkConfig) {
		&logit($LOG_ERROR, "Could not write to file $file");
	}
}

sub loadDacls
{
	my $file = &forkFileName($daclFile);
	my(@elements);

	if (open(DACL, $file)) {
		@elements = @{Storable::fd_retrieve(\*DACL)};
		foreach my $elem (@elements) {
			$$elem = new Net::Patricia;
			my %hash = %{Storable::fd_retrieve(\*DACL)};
			foreach (keys %hash) { $$elem->add_string($_, { 'k'=>$_, 'v'=>$hash{$_} } ); }		# hash -> trie
		}
		close(DACL);
		&logit($LOG_DEBUG, "Loaded " . (scalar @elements) . " dacls/host-lists from $file") if (@elements);
	}

	return @elements;
}

sub saveFacls
{
	my $file = &forkFileName($faclFile);
	my $count = 0;
	my @facls;
	foreach (keys %$FACL) { push(@facls, values %{$FACL->{$_}->{hashes}}); }

	foreach my $facl (@facls) {
		while ( my($key,$timeout) = each %{$facl} ) {
			delete ${$facl}{$key} if ($timeout < $timeStamp);
		}
		$count += scalar %{$facl};
	}

	if (open(FACL, ">$file")) {
		Storable::store_fd(\@facls, \*FACL);
		foreach (@facls) { Storable::store_fd(\%{$_}, \*FACL); }
		close(FACL);
		&logit($LOG_DEBUG, "Saved " . (scalar @facls) . " facls with $count elements to $file") if (@facls);
	}
	elsif (! $checkConfig) {
		&logit($LOG_ERROR, "Could not write to file $file");
	}
}

sub loadFacls
{
	my $file = &forkFileName($faclFile);
	my @elements;

	if (open(FACL, $file)) {
		@elements = @{Storable::fd_retrieve(\*FACL)};
		foreach (@elements) { %{$_} = %{Storable::fd_retrieve(\*FACL)}; }
		close(FACL);
		&logit($LOG_DEBUG, "Loaded " . (scalar @elements) . " facls from $file") if (@elements);
	}
}

sub getDynamicList
{
	my($racl, %dynamics);

	foreach my $racl (@racls) {
		$dynamics{$racl->{setSourceIP}} = 1 if (defined $racl->{setSourceIP});
		$dynamics{$racl->{setDestinationIP}} = 1 if (defined $racl->{setDestinationIP});
	}
	return sort keys %dynamics;
}

# -------------------------------------------------------------------------
# create a datafile of any type. fOpts = maxsize for ascii/flow files or resolution for rrd
sub createFile
{
	sub createDir
	{
		my(@fNewParts, @fParts, $fDir);
		@fParts = split(/\//, $_[0]);
		pop(@fParts);					# get rid of filename

		while (@fParts) {
			last if (-d ($fDir = join("/", @fParts) . "/"));
			unshift(@fNewParts, pop @fParts);
			undef $fDir;
		}

		foreach (@fNewParts) {
			return "ERROR creating $fDir: " . $^E if (! mkdir($fDir .= $_ . "/"));
		}
		return undef;
	}

	my($fName, $fType, $fOpts, $fStep, $fPacked, $tStamp) = @_;

	if (! -f $fName) {				# create directory structure, if necessary
		my $err = &createDir($fName);
		if ($err) {
			&logit($LOG_ERROR, $err);
			return 0;
		}
	}

	if ($fType == $foo_rrd) {
		return 1 if (-f $fName);				# create RRD
		my ($fOpt, $re, @res);

		&logit($LOG_DEBUG, "Creating file $fName");
		foreach (@$fOpts) {
			($re, @res) = split(/$;/);
			next if ( (defined $re) && ($fName !~ /$re/));		# optional regexp qualifier
			$fOpt = join(':', @res) . (defined $re) ? ':/' . $re . '/' : '';
			last;
		}

		if (! defined $fOpt) {
			push(@res, 1, 14, 90, 730);	# 1 day of step, 14 days of 5-minute, 90 days of hourly, 2 years of daily
			$fOpt = join(':', @res) . "[default]"; 
		}
		&logit($LOG_DEBUG, "using fOpt '$fOpt': @res");

		my %rra;
		$fStep = (($period < $DEFAULT_STEP) ? $period : $DEFAULT_STEP) if (! $fStep);	# use default period if none specified
		$tStamp = $timeStamp if (! $tStamp);			# use file timestamp if none other

		foreach (1, 300, 3600, 86400) {
			my $steps = POSIX::ceil($_ / $fStep);		# how many steps?
			my $dur = $steps * $fStep;			# calc true duration
			my $days = shift @res;				# how many days
			next if (! $days);

			if (my $rows = $days * 86400 / $dur) {		# how many rows?
				$rra{$steps} = sprintf("RRA:%s:0.5:%d:%d", 'MAX', $steps, $rows);
				$rra{"$steps.1"} = sprintf("RRA:%s:0.5:%d:%d", 'AVERAGE', $steps, $rows);
			}
		}

		if (! defined $rra{1}) {				# none matches base res -- put in the minimum # of steps
			my $rows = (sort {$a <=> $b} keys %rra)[0];
			$rra{"1"} = sprintf("RRA:%s:0.5:%d:%d", 'MAX', 1, $rows);
			$rra{"1.1"} = sprintf("RRA:%s:0.5:%d:%d", 'AVERAGE', 1, $rows);
		}

		&logit($LOG_DEBUG, "RRAs: " . join(" ", (map { $rra{$_} } sort {$a <=> $b} keys %rra)) );

		my $hb = POSIX::ceil($fStep * 1.05);	# heartbeat

		my $dst = "GAUGE";
		$hb = $fStep;

		my @createArgs = (
			$fName,
			"--step", $fStep,			# period of file
			"--start", $tStamp - 1,			# first stamp in list
			(map { $rra{$_} } sort {$a <=> $b} keys %rra)
		);

		if ($fPacked) {
			push ( @createArgs, map {
				("DS:$_-Bits-in:$dst:$hb:U:U",
				"DS:$_-Bits-out:$dst:$hb:U:U",
				"DS:$_-Packets-in:$dst:$hb:U:U",
				"DS:$_-Packets-out:$dst:$hb:U:U",
				"DS:$_-Flows-in:$dst:$hb:U:U",
				"DS:$_-Flows-out:$dst:$hb:U:U",
				"DS:$_-IPs-in:$dst:$hb:U:U",
				"DS:$_-IPs-out:$dst:$hb:U:U")
			} (0 .. $fPacked - 1) );
		}
		else {
			push (@createArgs, 
				"DS:Bits-in:$dst:$hb:U:U",
				"DS:Bits-out:$dst:$hb:U:U",
				"DS:Packets-in:$dst:$hb:U:U",
				"DS:Packets-out:$dst:$hb:U:U",
				"DS:Flows-in:$dst:$hb:U:U",
				"DS:Flows-out:$dst:$hb:U:U",
				"DS:IPs-in:$dst:$hb:U:U",
				"DS:IPs-out:$dst:$hb:U:U"
			);
		}

		&logit($LOG_DEBUG, "RRDs::create " .  join(' ', @createArgs));
		RRDs::create(@createArgs);
		my $err=RRDs::error;

		if ($err) {
			&logit($LOG_ERROR, "ERROR creating $fName ($fOpt): $err");
			return 0;
		}
		else {
			&logit($LOG_TRIVIA, "RRDs::create $fName ($fOpt)");
		}
	}
	elsif (($fType == $foo_text) || ($fType == $foo_flow) || ($fType == $foo_csv)) {
		&fileSizeRotate($fName, $fOpts);

		if (! open($fName, ">>$fName")) {
			&logit($LOG_ERROR, "ERROR opening $fName for writing: " . $^E);
			return 0;
		}
		$fileOpened{$fName} = 1;
	}

	# return success code
	return 1;
}

# rotate a file if its size becomes too large
sub fileSizeRotate
{
	my($fName, $fSize) = @_;

	if ((defined $fSize) && (-s $fName > $fSize)) {
		&logit($LOG_INFO, "Rotating file: $fName because size " .
			(-s $fName) . " > $fSize");

		open(IN, $fName);
		if (open(OUT, ">" . $fName . ".old")) {
			while ( <IN> ) { print OUT $_; }
			close(OUT);
		}
		else {
			&logit($LOG_ERROR, "Unable to write $fName.old");
		}
		close(IN);

		unlink($fName);
	}
}

sub hierarchical
{
	my ($x) = $_[0];
	if ($hierarchicalDir) {				# if hierarchical directories are enabled
		$x =~ tr/\./\//;
		$x =~ s/\/(\w*)$/\.$1/;		# return file extension
	}
	return $x;
}

# -------------------------------------------------------------------------
# read the configuration file in
#
# globals (not necessarily complete):
#	%foos (pointer to arrays), @t_localNextHops $dataDir,
#	@racls, %dacl, %referenced_dacl, %available_dacl
# -------------------------------------------------------------------------
our ($configFileDir, $lastConfigFileDir);

sub readConfig
{
	my $configFile = shift;
	my $quick = shift;

	my($acl, $aclp, $nacl, $racl);
	my($foo, $not, $err, $errCount);
	my($grp, $grpp, $dacl, $mapp, $daclp, $matrix, %dumpGroups);
	my(@acls, @groups);
	my($fileName, $fileDesc);
	my($raclCount, $fooCount, $aclCount);
	my(@trieCombines);

	###### READ IN THE CONFIG FILE (supports include files)
	$configFileDir = ($configFile =~ /^(.*)\/[^\/]+$/) ? $1 : '.';
	$errCount = &readConfigFile("FILE_$includeDepth", $configFile, $quick);

	return $errCount if ($quick);

	###### READ IN THE AUTOEXPORTER CACHE
	$ifCacheDir = $stateDir if (! defined $ifCacheDir);
	&loadAutoExporters;

	###### SANITY CHECK: ensure that colors are only assigned to valid ACLs
	foreach (keys %acl_color) {
		next if (/^($OTHER|Any)$/);

		if (! $acl_list{"ACL_$_"}) {
			&logit($LOG_ERROR, "Undefined ACL in color assignment: $_ = $acl_color{$_}");
			$errCount++;
			next;
		}
	}

	###### PROCESSING: clean up logic operators in foos
	foreach my $foo (keys %foos) {
		my($windowFilePre, $windowFilePost);
		$aclp = delete $foos{$foo};			# grab the ACL (array pointer)

		undef $not;
		undef @acls;
		foreach (@{$aclp}) {				# these may be ACLs, groups of ACLs, or "and", "not", etc...
			if (/^MaxSize=([\d\_]+)$/i) {		# specify a maximum file size, in bytes
				$fileMaxSize{$foo} = &noUnderscores($1);
				next;
			}
			elsif (/^Consolidation=(.*)/i) {	# RRD creation parameters
				my ($orig, $c, $re, @copts);
				$orig = $c = $1;
				if ($c =~ /^(.*)\:(\/[^\/]*\/)$/) { $c = $1; $re = $2; }

				if ($c =~ /^(MAX\:|AVERAGE\:|MIN\:|MAX\:|LAST\:|)(.*)/i) {	# RRD creation parameters
					$c = $2;
					if ($c =~ /^[\d\.\:]+$/) {
						@copts = split(/\:/, $c);
						if (@copts == 3) { @copts = ($copts[0], undef, $copts[1], $copts[2]); }

						if (@copts == 4) {
							push(@{$fileConsolidation{$foo}}, join($;, $re, map { $_ || 0 } @copts));
							next;
						}
					}
				}
				&logit($LOG_ERROR, "Invalid datafile consolidation: $orig");
				$errCount++;
				next;
			}
			elsif (/^Buckets?=(\d+)/i) {
				$fileBucket{$foo} = $1;
				$fileStep{$foo} = $1 if (! exists $fileStep{$foo});
				next;
			}
			elsif (/^Steps?=(\d+)/i) {
				$fileStep{$foo} = $1;
				$fileBucket{$foo} = $1 if (! exists $fileBucket{$foo});
				next;
			}
			elsif (/^Timestamps?=(start|end|average|distribute)/i) {
				$fileTimestamp{$foo} = lc($1);
				next;
			}
			elsif (/^Window=(\d+)\:?(\d*)/i) {
				$fileWindowPre = $1;
				$fileWindowPost = $2;
				next;
			}
			elsif (/^AutoClock$/i) {
				$fileAutoClock{$foo} = 1;
				next;
			}
			elsif (/^IPTrack.*/i) {			# Enable IP tracking
				$fileIPTracking{$foo} = 1;
				next;
			}
			elsif (/^(\w+)\:(\/.+)$/) {		# Special handling
				if (-d $2) { $fileSpecial{$foo}->{$1} = $2; }
				else {
					&logit($LOG_ERROR, "Directory does not exist: $2");
					$errCount++;
				}
				next;
			}

			if (/^(in|out)=(\S+)$/i) {		# defining 'in' and 'out' for this file
				$acl = "ACL_$2";
				if ($#$acl < 0) {
					&logit($LOG_ERROR, "undefined ACL in datafile $fileOrig{$foo}: $2");
					$errCount++;
					next;
				}
				if ($1 =~ /in/i)	{ $fileInACL{$foo} = $acl; }
				else			{ $fileOutACL{$foo} = $acl; }
				next;
			}

			if (/=/) {
				&logit($LOG_ERROR, "Invalid datafile directive: $_");
				$errCount++;
				next;
			}

			next if (/^(and|\&|\&\&)$/i);		# skip 'and'

			if ((/^or$/i) || (/[\(\)]/)) {		# 'or' or parenthesis
				&logit($LOG_ERROR, "unsupported operator in datafile $fileOrig{$foo}: $_");
				$errCount++;
				next;
			}

			($not = 1) && next if (/^(not|\^|\!)$/i);	# separate 'not'
			($not = 1) && ($_ = $1) if (/^\!(.*)/);		# attached 'not'

			push(@acls, "!") if ($not);
			push(@acls, $_);
			undef $not;
		}
		push(@{$foos{$foo}}, @acls);

		$fileBucket{$foo} = $fileStep{$foo} if ($fileBucket{$foo} > $fileStep{$foo});

		if ($fileBucket{$foo}) {
			$fileBucketLow{$foo} = POSIX::ceil( ($fileWindowPre) ? $fileWindowPre / $fileBucket{$foo} : $period * 1.5 / $fileBucket{$foo} );
			$fileBucketHigh{$foo} = $fileBucketLow{$foo} + POSIX::ceil( ($fileWindowPost) ? $fileWindowPost / $fileBucket{$foo} : $period * 1.5 / $fileBucket{$foo} );

			&logit($LOG_DEBUG, "$foo: fileBucketLow=$fileBucketLow{$foo}  fileBucketHigh=$fileBucketHigh{$foo}  fileBucket=$fileBucket{$foo}  fileStep=$fileStep{$foo}");
		}
	}

	###### PROCESSING: compute packed group size
	foreach my $foo (keys %foos) {
		if ($filePacked{$foo}) {
			my $last;
			foreach (@{$foos{$foo}}) {
				if ( $matrixType{$_} ) { undef $last; }
				elsif ( $groups{$_} ) { $last = $_; }
			}

			if (! defined $last) {
				&logit($LOG_ERROR, "Packed-rrd '$foo' must conclude with a group");
				$errCount++;
			}
			else {
				$filePacked{$foo} = scalar @{$groups{$last}} + 1;
			}
		}
	}

	###### PROCESSING: create an index file
	if (defined $indexFile) {				# write an index file with group/member names
		undef @indexHeader;
		my @indexHeader2;

		push(@indexHeader, "[files]\n");

		foreach my $foo (@fooOrdered) {
			$fileName = $fileOrig{$foo};			# original "name"
			$fileDesc = delete $fileDesc{$fileName};	# nice name for indexing

			$aclp = $foos{$foo};			# grab the ACL (array pointer)

			my $fooName = $foo;
			foreach (@{$aclp}) {			# these are either ACLs or GROUPs or MAPs
				if ($matrixType{$_}) {
					$fooName .= "\.[\%$_]";
				}
				elsif ($groups{$_}) {
					$fooName .= "\.[$_]";
					$dumpGroups{$_} = 1;
				}
			}

			$fooName =~ s/\.\[([^\[]+?)\]$/\.\[packed=$1]/ if ($filePacked{$foo});

			$fooName = $filePrefix{$foo} . $fooName . $fileSuffix{$foo};

			push(@indexHeader, "$fooName\t$fileDesc\n");
			push(@indexHeader2, "$fooName\t$fileFlowDir{$foo}\n");
		}
		push(@indexHeader, "\n[capture]\n", @indexHeader2);

		foreach my $grp (keys %dumpGroups) {
			push(@indexHeader, "\n[$grp]\n");

			foreach (@{$groups{$grp}}, $OTHER) {

				if (exists $map_list{"MAP_$_"}) {			# push map
					push(@indexHeader, map { $_ . (( exists $acl_color{$_} ) ? "\t" . $acl_color{$_} : "") . "\n" } @{$mapOrder{"MAP_$_"}});
				}
				else {							# push one item
					push(@indexHeader, $_ . (( exists $acl_color{$_} ) ? "\t" . $acl_color{$_} : "") . "\n");
				}
			}
		}
		undef %dumpGroups;
	}

	###### SANITY CHECK: ensure that all index file descriptions are accounted for
	foreach (keys %fileDesc) {
		&logit($LOG_ERROR, "Undefined datafile in description: $_ = $fileDesc{$_}");
		$errCount++;
	}

	###### PROCESSING: extract and process host-lists (which are masquerading as groups)
	foreach my $grp (keys %groups) {
		next if ($grp !~ /^DACL_/);

		$dacl = $grp;
		$daclp = delete $groups{$dacl};
		$subnetTries{$dacl} = 1;
		$$dacl = new Net::Patricia;

		foreach (@$daclp) {
			if (/^\@/) {				# another host-list
				s/\@/DACL_/;
				push(@trieCombines, "$dacl,$_");
			}
			elsif (! eval { $$dacl->add_string($_, { 'k'=>$_, 'v'=>1 } ) } ) {
				$err = "Invalid IP in host-list $dacl: $_";
				$err =~ s/DACL_/\@/;		# convert back to human-readable form
				&logit($LOG_ERROR, $err);
				$errCount++;
				last;
			}
		}
	}

	###### PROCESSING: combine nested tries
	foreach (@trieCombines) {
		my($dst, $src) = split(/,/);
		if (exists $subnetTries{$src}) {
			$$src->climb(sub { $$dst->add_string($_[0]->{'k'}, $_[0]); });
		}
		else {
			$err = "Undefined host-list referred to in host-list $dst: $src";
			$err =~ s/DACL_/\@/;			# convert back to human-readable form
			&logit($LOG_ERROR, $err);
			$errCount++;
		}
	}

	###### SANITY CHECK: ensure group names point to valid ACL or MAP names
	foreach my $grp (keys %groups) {
		if ($acl_list{"ACL_$grp"}) {
			&logit($LOG_ERROR, "Group and ACL have identical name: $grp");
			$errCount++;
			next;
		}

		undef @acls;
		$grpp = delete $groups{$grp};

		if (defined $matrixType{$grp}) {		# if this is really a matrix, change its type
			push(@{$matrices{$grp}}, @{$grpp});
			next;
		}

		foreach (@{$grpp}) {
			if (exists $acl_list{"ACL_$_"}) {
				push(@acls, "ACL_$_");
			}
			elsif (exists $map_list{"MAP_$_"}) {
				push(@acls, "MAP_$_");
			}
			else {
				&logit($LOG_ERROR, "Undefined ACL in group $grp: $_");
				$errCount++;
				next;
			}
		}
		push(@{$groups{$grp}}, @acls);
	}

	###### PROCESSING: handle access-list maps
	foreach my $map (keys %map_list) {

		$mapp = $map_list{$map};			# a pointer to the map
		$$map = new Net::Patricia;			# map trie
		$subnetTries{$map} = 1;

BOMB:		foreach my $acl (keys %$mapp) {

			# first, build an internal-use trie

			my $mytrie = "DACL_" . $acl . "_auto";
			my $myacl = "ACL_" . $acl . "_auto";

			if ( (! exists $subnetTries{$mytrie}) &&  (! exists $acl_list{$myacl})) {

				# first time for this DACL/ACL, build the trie and dummy ACL

				$$mytrie = new Net::Patricia;
				$subnetTries{$mytrie} = 1;

				foreach ( @{$mapp->{$acl}} ) {		# host-lists or individual IP addresses...
					if (/^\@/) {				# another host-list
						s/\@/DACL_/;
						if (exists $subnetTries{$_}) {
							$$_->climb(sub { $$mytrie->add_string($_[0]->{'k'}, $_[0]); });
						}
						else {
							$err = "Undefined host-list referred to in ACL map $map: $_";
							$err =~ s/(MAP|DACL)_/\@/;		# convert back to human-readable form
							&logit($LOG_ERROR, $err);
							$errCount++;
							last BOMB;
						}
					}
					elsif (! eval { $$mytrie->add_string($_, {'k'=>$_, 'v'=>1} ) } ) {
						$err = "Invalid IP in ACL map $map: $_";
						$err =~ s/(MAP|DACL)_/\@/;		# convert back to human-readable form
						&logit($LOG_ERROR, $err);
						$errCount++;
						last BOMB;
					}
				}
	
				# create ACL_$acl with "permit ip host @TLIST any reverse"
				$acl_list{$myacl} = 1;
				@$myacl = (
					{ 'permit' => 1, 'sourceIP' => $mytrie, 'sourceDACL' => 1, },
					{ 'permit' => 1, 'destinationIP' => $mytrie, 'destinationDACL' => 1, }
				);
			}

			# then build up the map trie with each IP pointing to the ACL. No overlap checking is done.
			$$mytrie->climb(sub { $$map->add_string($_[0]->{k}, {'k'=>$_[0]->{k}, 'v'=>$acl} ); });
		}
	}

	###### PROCESSING: matrix options (matrixType = as, if, ip, nexthop, subnet, protocol, or port)
	my %matrixTypeCount;
	foreach my $matrix (keys %matrices) {
		$matrixTypeCount{$matrixType{$matrix}}++;

		my $matrixType;
		$matrixAuto{$matrix} = 0;			# default = manual

		if ($matrixType{$matrix} =~ /^(ip|subnet|nexthop)$/i) {		# trie-based
			$matrixType = 1;
			${"MATRIX_$matrix"} = new Net::Patricia;
		}
		elsif ($matrixType{$matrix} =~ /^(as|port)$/i) {		# integer-based
			$matrixType = 2;
			${"MATRIX_$matrix"} = {};
		}
		else {
			$matrixType = 3;
			${"MATRIX_$matrix"} = {};
		}

		foreach (@{$matrices{$matrix}}) {
			if (/^auto$/i) {
				$matrixAuto{$matrix} = 1;
			}

			elsif (/^counter/i) {
				$matrixCount{$matrix} = 1;
			}

			elsif (/^mask=(.*)$/i) {			# matrixMask
				my $mask = $1;
				my $maskErr;

				if ($matrixType == 3) { $maskErr = "No masks allowed"; }

				foreach (split(/,/, $mask)) {
					last if ($maskErr);
					if ( ($matrixType == 1) && ((! /^(.*)\/(\d+)$/) || ($2 > 32) || (! defined &hackIP($1))) ) {
						$maskErr = "Invalid mask ($_)";
					}
					elsif ( ($matrixType == 2) && ((! /^\d+-\d+$/) && (! /^\d+$/)) ) {
						$maskErr = "Invalid mask ($_)";
					}
					else {
						push(@{$matrixMask{$matrix}}, $_);
					}
				}

				if (defined $maskErr) {
					&logit($LOG_ERROR, $maskErr . " in $matrixType{$matrix}-matrix '$matrix'");
					$errCount++;
				}
			}

			elsif (/^xform=(\d+)\:([\d\-\,]+)$/) {
				my($target, $mask) = ($1, $2);
				my $xErr;

				if ($matrixType != 2) { $xErr = "Xforms not allowed for $matrixType{$matrix}-matrix"; }

				foreach (split(/,/, $mask)) {
					last if ($xErr);

					if (/^\d+$/) { ${"XFORM_$matrix"}[$_] = $target; }
					elsif (/^(\d+)-(\d+)$/) { for ($1 .. $2) { ${"XFORM_$matrix"}[$_] = $target; } }
					else { $xErr = "Invalid xform ($_)"; }
				}

				$matrixXForm{$matrix} = 1;

				if (defined $xErr) {
					&logit($LOG_ERROR, $xErr . " in $matrixType{$matrix}-matrix '$matrix'");
					$errCount++;
				}
			}

			elsif (/^(bits|exact)=(\d+)$/i) {				# set bit limit
				my $label = $1;
				my $bits = $2;

				if ($matrixType{$matrix} !~ /^subnet$/) {
					&logit($LOG_ERROR, "The 'bits=' option isn't valid for $matrixType{$matrix}-matrix '$matrix'");
					$errCount++;
				}
				elsif ( (($bits > 0) && ($bits <= 31)) || ($bits eq "0")) {
					if ($label =~ /bits/i)	{ $matrixBits{$matrix} = $bits; }
					else			{ $matrixExact{$matrix} = $bits; }
				}
				elsif ($bits > 32) {
					&logit($LOG_ERROR, "Invalid '$label'. Must be between 0 and 32.");
					$errCount++;
				}
			}

			elsif (/^(descriptions|aliases|authorization)=(.*)$/i) {	# informational file
				my $fType = $1;
				my $f1 = $2;
				my($f2, $fileErr);

				next if (($f1 =~ /^auto$/i) && ($fType !~ /auth/i));

				if (($fType =~ /desc/i) && ($f1 =~ /^dns$/i) && ($matrixType{$matrix} =~ /^(ip|nexthop)$/i)) {
					push(@{$matrixDescriptions{$matrix}}, $dnsToken);
					$dnsAuto{$matrix} = 1;
				}
				elsif (($fType =~ /alias/i) && ($f1 =~ /simple/)) {
					push(@{$matrixAliases{$matrix}}, "(\\S.*)\t\$1\tdescription-only");
				}
				elsif (($fType =~ /desc/i) && ($matrixType{$matrix} =~ /^if$/)) {
					$fileErr = "Descriptions must be 'auto'";
				}
				elsif (! defined ($f2 = &locateFile($f1, $configFileDir, $scriptDir, $lastConfigFileDir))) {
					$fileErr = "Error reading $fType file";
				}
				elsif ($fType =~ /desc/i) {
					push(@{$matrixDescriptions{$matrix}}, $f2);
				}
				elsif ($fType =~ /alias/i) {
					push(@{$matrixAliases{$matrix}}, $f2);
				}
				elsif ($fType =~ /auth/i) {
					push(@{$matrixAuthorization{$matrix}}, $f2);
				}

				if ($fileErr) {
					&logit($LOG_ERROR, $fileErr . " in $matrixType{$matrix}-matrix '$matrix': $f1");
					$errCount++;
				}
			}

			elsif (defined (my $x = &a2MatrixValue($matrixType{$matrix}, $_)) ) {	# prepopulate
				if ($matrixType == 1) {
					${"MATRIX_$matrix"}->add_string($_, $x);
				}
				else {
					${"MATRIX_$matrix"}{$x} = 1;
				}
			}

			elsif ((/^\@(.*)$/) && ($matrixType == 1)) {				# host-list
				my $grp = "DACL_$1";
				if (ref($$grp) =~ /Patricia/) {
					$$grp->climb(sub { ${"MATRIX_$matrix"}->add_string($_[0], &a2MatrixValue($matrixType{$matrix}, $_[0])); });
				}
				else {
					$err = "Undefined host-list referred to in datafile $matrix: $grp";
					$err =~ s/DACL_/\@/;			# convert back to human-readable form
					&logit($LOG_ERROR, $err);
					$errCount++;
				}
			}
			else {
				&logit($LOG_ERROR, "Invalid value in $matrixType{$matrix}-matrix '$matrix': $_");
				$errCount++;
			}
		}

		# add auto-descriptions for interface matrices
		if ($matrixType{$matrix} eq "if") {
			foreach my $exp (keys %exporterName) {
				foreach my $ifIndex (keys %{"iif_clean_$exp"}) {
					push(@{$matrixDescriptions{$matrix}},
						$exporterName{$exp} . "#" .
						${"iif_clean_$exp"}{$ifIndex} . "\t" .
						${"ifAlias_$exp"}{$ifIndex}
					);

					push(@{$matrixSpeeds{$matrix}},
						$exporterName{$exp} . "#" .
						${"iif_clean_$exp"}{$ifIndex} . "\t" .
						${"ifSpeed_$exp"}{$ifIndex}
					);
				}
			}
		}
	}

	###### PROCESSING: calculate a hash function for forking, if needed
	if ($forkMax) {
		my @mTypes = keys %matrixTypeCount;
		if (@mTypes > 1) {
			&logit($LOG_INFO, "fork=$forkMax ignored because config file has multiple matrix types (@mTypes)");
			undef $forkMax;
		}
		elsif (keys %fileSpecial) {
			&logit($LOG_INFO, "fork=$forkMax ignored because special piping is in place");
			undef $forkMax;
		}
		else {
			my $mType = shift @mTypes;
			if ($mType eq 'if') { $forkHash = '($exporter >> 24) ^ ($exporter >> 16 & 0xff) ^ ($exporter >> 8 && 0xff) ^ ($exporter & 0xff)'; }
			elsif ($mType eq 'protocol') { $forkHash = '$protocol'; }
			elsif ($mType eq 'nexthop') { $forkHash = 'nexthop'; }
			else {
				&logit($LOG_INFO, "fork=$forkMax ignored because its incompatible with $mType-matrix");
				undef $forkMax;
			}
		}
	}

	###### PROCESSING: ensure all ACLs exist and massage data into run-ready
	foreach my $foo (keys %foos) {
		$aclp = delete $foos{$foo};				# grab the ACL (array pointer)

		undef @acls;
		undef @groups;
		our %badacl;

		foreach (@{$aclp}) {				# these may be ACLs, groups of ACLs, or "and", "not", etc...
			if (/^\!$/i) { push(@acls, $_); next; }
			elsif (($groups{$_}) || ($matrixType{$_})) { push(@groups, $_); next; }

			$acl = "ACL_$_";			# expand ACL name
			if ($#$acl < 0) {
				&logit($LOG_ERROR, "undefined ACL in datafile $fileOrig{$foo}: $_") if (! $badacl{$acl});
				$badacl{$acl}++;
				$errCount++;
				next;
			}
			push(@acls, $acl);
		}

		push(@{$foos{$foo}}, @acls, @groups);		# @groups = groups and matrices
	}

	###### SANITY CHECK: validate LocalNextHops
	foreach (@t_localNextHops) {
		my $cli = $_;
		my $a = &hackACL(\$cli, undef, 2);
		if ($a !~ /([\d\.]+)\/([\d\.]+)/) { 
			&logit($LOG_ERROR, "invalid localNextHop: $_");
			$errCount++;
			last;
		}

		my $rule;
		$rule->{nextHopIP} = $1;
		$rule->{nextHopMask} = $2;
		$rule->{permit} = 1;

		push(@{$localNextHops}, $rule);
	}

	###### SANITY CHECK: ensure all referenced host-lists exist
	foreach my $dacl (keys %referenced_dacl) {
		$err = "undefined host-list: $dacl";
		$err =~ s/DACL_/\@/;				# convert back to human-readable form

		foreach (keys %available_dacl) {
			if ($_ eq $dacl) {			# whoopie! we're okay
				undef $err; last;
			}
		}

		if ($err) {
			$errCount++;
			&logit($LOG_ERROR, $err);
		}
	}

	###### SANITY CHECK: ensure all referenced facls exist
	foreach my $facl (keys %referenced_facl) {
		$err = "undefined flow-list: $facl";
		$err =~ s/FACL_/\%/;				# convert back to human-readable form

		foreach (keys %available_facl) {
			if ($_ eq $facl) {			# whoopie! we're okay
				undef $err; last;
			}
		}

		if ($err) {
			$errCount++;
			&logit($LOG_ERROR, $err);
		}
	}

	if (0) {

	###### SANITY CHECK: ensure no recursive DACLs/FACLs (why not? That could be cool)
	foreach my $racl (@racls) {
		$acl = $racl->{acl};

		if ($#$acl < 0) {
			$acl =~ s/^ACL_//;				# trim back to what the user expects
			&logit($LOG_ERROR, "undefined ACL in dynamic: $acl");
			$errCount++;
			next;
		}

		foreach my $rule (@{$acl}) {
			if ( ($rule->{sourceDACL}) || ($rule->{destinationDACL}) || ($rule->{facl}) ) {
				$acl =~ s/^ACL_//;				# trim back to what the user expects
				&logit($LOG_ERROR, "recursive dynamic ACLs are not allowed: $acl");
				$errCount++;
				last;
			}
		}
	}

	}

	$raclCount = @racls;
	$aclCount = scalar keys %acl_list;
	$fooCount = scalar keys %foos;

	&logit($LOG_TRIVIA, "config contains $fooCount datafile(s), $aclCount ACL(s), and $raclCount dynamic(s)");
	return ($errCount);
}

# ---------------------------------------------
# searches for a filename in multiple paths, returning the first one where the file is.
sub locateFile
{
	my($fName, @paths) = @_;
	return $fName if (($fName =~ /^\//) && (-f $fName));
	foreach (@paths) { return "$_/$fName" if (-f "$_/$fName"); }
	return undef;
}

# ---------------------------------------------

sub snarfText
{
	my ($fh, $indented) = @_;

	while (1) {
		$lineCount{$fh}++;

		if (defined $nextLine{$fh}) {
			$_ = delete $nextLine{$fh};
		}
		else {
			$_ = <$fh>;
			return undef if (! defined $_);		# EOF

			chomp;
			next if (/^\s*\#/);	# skip comment-only lines

			s/\s*\s[\#\;].*//;	# get rid of comments
			s/\s+$//;		# get rid of trailing whitespace
			s/\s+/ /g;		# make sure all whitespace is realy a single space
		}

		if ($indented) {	# looking for all indented lines...
			if (s/^\s+//) {		# if it has leading whitespace, get rid of it and...
				return $_;
			}
			else {			# reached the end-of-the-line
				$lineCount{$fh}--;
				$nextLine{$fh} = $_;
				return undef;
			}
		}
		else {
			next if (! $_);		# skip blank lines
			s/^\s+//;		# delete leading spaces (bad form, but allowed)
			return $_;
		}
	}
}

# ---------------------------------------------
# read the file, this may be called recursively with 'include'

sub readConfigFile
{
	my($fh, $fname, $quick) = @_;

	my($cli, $rule, $newrule, $a, $a1, $a2, $a3, $a4);
	my($errCount, $err, $reverse);
	my($foo, $acl, $lnh, $grp, $map);
	my($listType, $racl);
	my($fileType, $fileName);
	my($errfname);

	my($MAXBYTE) = 2**8 - 1;
	my($MAXINT) = 2**16 - 1;
	my($MAXLONG) = 2**32 - 1;

	my $DACL = 1;

	chomp(my $p = `pwd`);
	my $f;
	if ($fname =~ /^\//) {
		if (open($fh, $fname)) {
			$f = $fname;
			$lastConfigFileDir = $1 if ($fname =~ /^(.*)\/[^\/]+$/);
		}
	}
	else { 
		if (defined ($f = &locateFile($fname, $configFileDir, $scriptDir, $lastConfigFileDir, $p))) {
			undef $f if (! open($fh, $f));
		}
	}

	if (! defined $f) {
		&logit($LOG_ERROR, "config file not found: $fname");
		$errCount++;
		return $errCount;
	}

	&logit($LOG_DEBUG, "reading config file $f");

	delete $nextLine{$fh};
	$lineCount{$fh} = 0;

	while ( $cli = &snarfText($fh, 0) ) {
		undef $err;
		undef $reverse;

		if ($cli =~ /^include (\S+)$/i) {					# include another config file
			$a = $1;			# include file name
			$a =~ s/[\"\']//g;		# get rid of quotes, if any

			if (! &filenameChars($a)) {
				$err = "invalid include filename: $a";
			}
			elsif ($includeDepth >= 10) {
				$err = "recursion depth exceeded (too many 'include' statements)";
			}
			else {
				$includeDepth++;
				$errCount += &readConfigFile("FILE_$includeDepth", $a, $quick);
				$includeDepth--;
			}
		}
		elsif ($cli =~ /^directory (\S+)\s*(\S*?)\/?$/i) {			# where to store files
			$a1 = $1;
			$a2 = $2;

			# these assignments need quoting to get around weird bug/problem
			# that may be due to tainting...

			if ($a1 =~ /^(temp|state)$/i)	{ $stateDir  = "$a2"; $stateDirs{$stateDir}=1; }
			elsif ($a1 =~ /^cache$/i)	{ $ifCacheDir= "$a2"; }
			elsif ($a1 =~ /^data$/i)	{ $dataDir   = "$a2"; }
			elsif ($a1 =~ /^watch$/i)	{ $sourceDir = "$a2"; }
			elsif ($a1 =~ /^flows?$/i)	{ $sourceDir = "$a2"; }
			elsif ($a1 =~ /^hierarchical/i) { $hierarchicalDir = 1; next; }
			else {
				$err = "invalid directory type";
			}

			if (! defined $err) {
				$a1 =~ tr/a-z/A-Z/;					# niceify the error msg

				if (! &filenameChars($a2)) {
					$err = "invalid $a1 directory";
				}
				elsif ((! -d $a2) || ($a2 !~ /^\//)) {
					$err = "invalid $a1 directory";
				}
			}
		}

		elsif ($cli =~ /^logging (\S+) (\S+?)\/?$/i) {			# logging parameters
			$a1 = $1;
			$a2 = $2;

			if ($a1 =~ /^file$/i) {
				if (! &filenameChars($a2)) {
					$err = "invalid log file name: $a2";
				}
				$newLogFile = $a2;
			}
			elsif ($a1 =~ /^level$/i) {
				if ($a2 =~ /^error$/i)		{ $logFileLevel = $LOG_ERROR; }
				elsif ($a2 =~ /^info$/i)	{ $logFileLevel = $LOG_INFO; }
				elsif ($a2 =~ /^trivia$/i)	{ $logFileLevel = $LOG_TRIVIA; }
				elsif ($a2 =~ /^debug$/i)	{ $logFileLevel = $LOG_DEBUG; }
				elsif ($a2 =~ /^superdebug$/i)	{ $logFileLevel = $LOG_SUPERDEBUG; }
				else {
					$err = "invalid logging level: $a2";
				}
			}
			elsif ($a1 =~ /^size$/i) {
				$a2 = &noUnderscores($a2);
				if ($a2 > 0) { $logFileMaxSize = $a2; }
				else { $err = "invalid logging size: $a2"; }
			}
			else {
				$err = "invalid logging keyword: $a1";
			}
		}

		elsif ($quick) {			# skip all other processing in 'quick' mode
		}

		elsif ($cli =~ /^fork\s+(\d+)$/i) {		# SMP
			$forkMax = $1 if (($1 > 1) && ($1 <= 32));
		}

		elsif ($cli =~ /^index (\S+) (\S+)\s*(.*)$/i) {			# index parameters
			$a1 = $1;
			$a2 = $2;
			$a3 = $3;

			if ($a1 =~ /^file$/i) {
				$a2 =~ s/\/$//;			# delete trailing /, if present

				if ($a3) {			$err = "syntax error"; }
				elsif (! &filenameChars($a2)) {	$err = "invalid log file name: $a2"; }
				else {				$indexFile = $a2; }
			}
			elsif ($a1 =~ /^color$/i) {
				if (! &validColor($a3)) {
					$err = "invalid color: '$a3'";
				}
				else {
					$acl_color{$a2} = &validColor($a3);
				}
			}
			elsif ($a1 =~ /^description$/i) {
				$a3 = $1 if ($a3 =~ /^[\'\"](.*)[\'\"]\s*$/);	# strip quotes
				$fileDesc{$a2} = $a3 if (length($a3) > 0);
			}
			else {
				$err = "invalid index keyword: $a1";
			}
		}

		elsif ($cli =~ /^dns (\S+) (.*)/) {				# dns parameters
			$a1 = $1;
			$a2 = $2;

			if ($a1 =~ /^servers$/i) {
				push(@dnsServers, split(/\s+/, $a2));
			}
			elsif ($a1 =~ /^timeout$/i) {
				$dnsTimeout = POSIX::ceil($a2);
			}
			elsif ($a1 =~ /^pacing$/i) {
				$dnsPacing = POSIX::ceil($a2);
			}
			else {
				$err = "invalid dns keyword: $a1";
			}
		}

		elsif ($cli =~ /^track (\S.*)/) {
TRACK:			foreach (split(/\s+/, $1)) {
				if (/^none$/i) { $trackExporters = {}; }
				elsif (/^all/i) { map { $trackExporters->{$_}=1 } @trackExporterKeys; }
				else {
					/^(-?)(.*)/;
					my $not = ($1 eq '-') ? 0 : 1;
					my $match = $2;
					foreach (@trackExporterKeys) {
						my $short = substr($_, 0, -1);
						if ($match =~ /^$short/i) { $trackExporters->{$_} = $not; next TRACK; }
					}
					$err = "invalid track keyword: $match";
					last;
				}
			}
		}

		elsif ($cli =~ /^click (\S+)/i) {
			$clickMode = $1;
			if ($1 !~ /^(loose|strict|strict-other)$/i) {
				$err = "invalid click: $1";
			}
		}

		elsif ($cli =~ /^period (\S+)/i) {
			$period = $1;
			if ((! $period) || ($period % 60)) {
				$err = "invalid period";
			}
		}

		elsif ($cli =~ /^exporter no-unknown-(exporters|interfaces)$/i) {
			$noUnknownExporters = 1;					# always
			if ($1 eq 'interfaces') { $noUnknownInterfaces = 1; }		# sometimes
		}

		elsif ($cli =~ /^snmp-session (\S+)\s*(\S*)$/i) {
			my $ssession = $1;
			$_ = $2;

			if (! &simpleChars($ssession)) {
				$err = "invalid snmp-session name";
			}
			while (1) {
				foreach (split(/\s+/)) {
					next if ($err);
					if (/^(port|localaddr|localport|version|domain|timeout|retries|maxmsgsize|community|username|authkey|authpassword|authprotocol|privkey|privpassword|privprotocol)=(\S+)$/) {
						$snmpSessions{$ssession}->{'-' . lc($1)} = $2;
					}
					else {
						$err = "invalid snmp-session line '$_'";
						last;
					}
				}
				last if (! defined ($_ = &snarfText($fh, 1)));
			}
		}

		elsif ($cli =~ /^exporter (\S+)\s+(\S+)\s*(.*)$/i) {	# exporter definition
			my $exporterName = $1;		# name
			my $exporterIP = $2;		# dotted-decimal
			my $stuff = $3;
			my $hackIP = $exporterIP;

			if (&hackACL(\$hackIP, undef, 2) =~ /^([\d\.]+)\/([\d\.]+)$/) {
				my($exp,$mask) = ($1, $2);		# integer values

				my $exporterInfo = {
					'community' => [ ],
					'snmpSessions' => [ ],
					'port' => 161,
					'version' => '2c',
					'noncisco' => 0,
					'iponly' => 0,
				};

				my @exporterTokens;
				&safepush(\@exporterTokens, split(/\s+/, $stuff));

				while ($_ = &snarfText($fh, 1)) {
					&safepush(\@exporterTokens, split(/\s+/));
				}

				foreach my $token (@exporterTokens) {

					if ($token eq '1') {				# snmp version
						$exporterInfo->{version} = '1';
					}
					elsif (($token eq '2') || ($token eq '2c') ) {	# snmp version
						$exporterInfo->{version} = '2c';
					}
					elsif ($token eq '3') {
						$err = 'SNMPv3 requires snmp-session objects. Refer to the documentation.';
						last;
					}
					elsif (($token =~ /^\d+$/) && ($1 < 65536)) {	# snmp port
						$exporterInfo->{port} = 161;
					}
					elsif ($token =~ /^non-cisco$/i) {		# non-cisco
						$exporterInfo->{noncisco} = 1;
					}
					elsif ($token =~ /^ip-only$/i) {		# only poll IP-enabled interfaces
						$exporterInfo->{iponly} = 1;
					}
					elsif ($token =~ /^nosnmp$/i) {			# no snmp
						$exporterInfo->{version} = '0';
					}
					elsif ($token =~ /^inout$/i) {			# force inout
						$exporterInout{$exp} = 1;
					}
					elsif ($token =~ /^(\d+)=(\S+?)(\:\d+|)$/) {		# hardcoded interface
						my $ifIndex = $1;
						my $ifDescr = $2;
						my $ifSpeed = ($3 =~ /(\d+)/) ? $1 : 0;

						# set globals
						${"if_$exp"}{$ifDescr} = $ifIndex;
						${"iif_$exp"}{$ifIndex} = $ifDescr;
						${"ifSpeed_$exp"}{$ifIndex} = $ifSpeed;
						$ifDescr =~ s/[^A-Z^a-z^0-9^\-]/sprintf("%%%2x",ord($&))/ge;
						${"iif_clean_$exp"}{$ifIndex} = $ifDescr;
					}
					elsif ( (exists $snmpSessions{$token}) && (! @{$exporterInfo->{community}}) ) {		# snmp session
						push(@{$exporterInfo->{snmpSession}}, $token);
					}
					elsif ( (! exists $snmpSessions{$token}) && (! @{$exporterInfo->{snmpSession}}) ) {	# snmp community
						push(@{$exporterInfo->{community}}, $token);
					}
					else {
						$err = "exporter cannot include both community and snmp-session";
						last;
					}
				}

				if ($exporterName =~ /^(auto|dns|snmp)$/i) { 		# auto-discovery
					$exporterInfo->{lifespan} = 86400 * 14;			# delete after 2 weeks unavailable
					$exporterInfo->{name} = lc($exporterName);		# describe autodiscovery mechanism
					$exporterInfo->{auto} = 1;

					if ($exporterIP eq '0.0.0.0/0') {		# handle Net::Patricia bug
						$autoExporterTrie->add_string('0.0.0.0/1', $exporterInfo);
						$autoExporterTrie->add_string('128.0.0.0/1', $exporterInfo);
					}
					else {
						$autoExporterTrie->add_string($exporterIP, $exporterInfo);
					}
				}
				elsif ($mask == 0xffffffff) {						# explicit definition
					if (exists $exporterName{$exp}) {					# duplicate
						if ($exporterIP{lc($exporterName)} ne $exp) {
							$err = "duplicate exporter '$exporterName' differs from previous";
						}
					}
					elsif (&loadInterfaces($exp, $exporterName, $exporterInfo, $LOG_DEBUG)) {
						$exporterName{$exp} = $exporterName;
						$exporterIP{lc($exporterName)} = $exp;
					}
					else {
						$err = "snmp failed to $exporterName (community string?)";
					}
				}
				else {									# error
					$err = "mask not allowed in explicit exporter definitions";
				}

			}
			else {
				$err = "invalid exporter IP '$exporterIP'";
			}
		}
		elsif ($cli =~ /^ip host-list \@(\S+)\s*(.*)$/i) {			# the start of a host list
			$grp = $1;
			$a = $2;

			if (! &simpleChars($grp)) {
				$err = "invalid character in host-list name";
			}

			$grp = "DACL_$grp";
			$available_dacl{$grp} = 0;			# no time expiration
			$groups{$grp} = [] if (! exists $groups{$grp});	# force it to be an arrayp

			# even with an error, push on the groups so that we don't generate unnecessary syntax errors
			&safepush($groups{$grp}, split(/\s+/, $a));

			while ($_ = &snarfText($fh, 1)) {
				&safepush($groups{$grp}, split(/\s+/));
			}
		}
		elsif ($cli =~ /^group (\S+)\s*(.*)$/i) {				# a group of ACLs
			$grp = $1;
			$a = $2;

			if (! &simpleChars($grp)) {
				$err = "invalid character in group name";
			}

			$groups{$grp} = [] if (! exists $groups{$grp});	# force it to be an arrayp

			# even with an error, push on the groups so that we don't generate unnecessary syntax errors
			&safepush($groups{$grp}, split(/\s+/, $a));

			while ($_ = &snarfText($fh, 1)) {
				&safepush($groups{$grp}, split(/\s+/));
			}
		}
		elsif ($cli =~ /^(if|as|protocol|port|nexthop|subnet|ip)-matrix (\S+)\s*(.*)$/i) {	# a matrix, a type of group
			$grp = $2;
			$a = $3;
			$matrixType{$grp} = lc $1;		# global

			if (! &simpleChars($grp)) {
				$err = "invalid character in matrix name";
			}

			$groups{$grp} = [] if (! exists $groups{$grp});	# force it to be an arrayp

			# even with an error, push on the groups so that we don't generate unnecessary syntax errors
			&safepush($groups{$grp}, split(/\s+/, $a));

			while ($_ = &snarfText($fh, 1)) {
				&safepush($groups{$grp}, split(/\s+/));
			}
		}
		elsif ($cli =~ /^datafile (\S+)\s+(\S+)\s*(.*)$/i) {			# a datafile line
			my ($fileType, $fileName, $fileSuffix, $filePrefix, $filePacked);

			$fileType = $1;
			$fileName = $foo = $2;
			$a = $3;							# series of ACLs to match

			$foo = "$dataDir/$foo" if ($foo !~ /^\//);		# no leading slash? prepend with dataDir
			if ($foo =~ /^(.*)(\.[^\.]{1,4})$/) {			# suffix supplied?
				$foo = $1;
				$fileSuffix = $2;
			}

			if (! &filenameChars($fileName)) {
				$err = "invalid datafile";
			}
			elsif ($fileType =~ /^rrd$/i) {				# Output this file as RRD
				$fileType = $foo_rrd;
				$fileSuffix = ".rrd" if (! defined $fileSuffix);
			}
			elsif ($fileType =~ /^packed-rrd$/i) {			# Output this file as RRD
				$fileType = $foo_rrd;
				$filePacked = 1;
				$fileSuffix = ".rrd" if (! defined $fileSuffix);
			}
			elsif ($fileType =~ /^(text|ascii)$/i)  {		# Output this file as TEXT
				$fileType = $foo_text;
				$fileSuffix = ".txt" if (! defined $fileSuffix);
			}
			elsif ($fileType =~ /^flow$/i)  {			# Output this file as NETFLOW
				$fileType = $foo_flow;
				$fileSuffix = ".flow" if (! defined $fileSuffix);
			}
			elsif ($fileType =~ /^csv$/i)  {			# Output this file as CSV
				$fileType = $foo_csv;
				$fileSuffix = ".csv" if (! defined $fileSuffix);
			}
			else {
				undef $fileType;
				$err = "invalid file type (must be rrd, text, flow, csv";
			}

			if ($foo =~ /^(.*\/)([^\/]+)$/) {
				$filePrefix = $1;
				$foo = $2;
			}

			if (! defined $err) {
				$fileOrig{$foo} = $fileName;
				$fileType{$foo} = $fileType;
				$filePrefix{$foo} = $filePrefix;
				$fileSuffix{$foo} = $fileSuffix;
				$fileFlowDir{$foo} = $sourceDir;
				$filePacked{$foo} = $filePacked;
				&safepush(\@fooOrdered, $foo);
			}

			$foos{$foo} = [] if (! exists $foos{$foo});

			# even with an error, push on the ACLs so that we don't generate unnecessary syntax errors
			&safepush($foos{$foo}, split(/\s+/, $a)) if ($a ne "");

			while ($_ = &snarfText($fh, 1)) {
				&safepush($foos{$foo}, split(/\s+/));
			}
		}
		elsif ($cli =~ /^localnexthop\s+(.*)$/i) {				# LocalNextHop definitions
			&safepush(\@t_localNextHops, split(/\s+/, $1));

			while ($_ = &snarfText($fh, 1)) {
				&safepush(\@t_localNextHops, split(/\s+/));
			}
		}

# dynamic <acl> source-ip <dynamic ACL for source-ip>
		elsif ($cli =~ /^dynamic (\S+)\s+(.*)/i) {			# dynamic lists
			undef $racl;
			$racl->{acl} = "ACL_$1";				# ACL to check
			$racl->{timeout} = 5 * 60;				# default = 5 minute timeout
			$cli = $2;

			if (! &simpleChars($racl->{acl})) {
				$err = "invalid character in ACL name";
			}

			while ($a = &hackACL(\$cli, \%dynamic_keywords)) {
				if (! defined $a) { $err = "syntax error"; last; }
				$listType  = $a;

				if ($listType == 5) {				# set the list timeout
					$a = &hackACL(\$cli,undef,undef,1,31536000);
					if (! defined $a) { $err = "syntax error"; last; }
					$racl->{timeout} = $a;
				}
				else {						# add source/dest IP to list
					# --- grab dynamic ACL
					$a = &hackACL(\$cli,'\S+',undef,undef,undef,undef);
					if (! defined $a) { $err = "syntax error"; last; }

					if ($a =~ s/\@/DACL_/) {
						if ($listType == 1)	{ $racl->{setSourceIP} = $a; }
						elsif ($listType == 2)	{ $racl->{setDestinationIP} = $a; }
						else { $err = "dynamic flows need a \%FOO variable"; last; }
						$available_dacl{$a} = 1;
						$$a = new Net::Patricia;
					}
					elsif ($a =~ s/\%/FACL_/) {
						if ($listType == 3)	{ $racl->{setFlow} = $a; }
						elsif ($listType == 4)	{ $racl->{setFlowReverse} = $a; }
						else { $err = "dynamic source/destination need a \@FOO variable"; last; }
						$available_facl{$a} = 1;
					}

					if ( (! $err) && (! &simpleChars($a)) ) {
						$err = "invalid character in ACL name";
						last;
					}
				}
			}
			&safepush(\@racls, $racl) if (! $err);				# array of dynamic ACLs
		}

		elsif ($cli =~ /^ip access-list map (\S+)/) {
			undef $foo; undef $lnh; undef $grp; undef $acl;

			$map = "MAP_$1";
			if (! &simpleChars($map)) {
				$err = "invalid character in ACL map";
			}

			while ($_ = &snarfText($fh, 1)) {
				my ($mapacl, @mapvals) = split(/\s+/);
				$map_list{$map}->{$mapacl} = [] if (! exists $map_list{$map}->{$mapacl});	# force it to be an arrayp
				push(@{$mapOrder{$map}}, $mapacl);					# preserve order	
				&safepush($map_list{$map}->{$mapacl}, @mapvals);
				foreach (@mapvals) {
					$referenced_dacl{$_} = 1 if (s/\@/DACL_/);
				}
			}
		}
		elsif ($cli =~ /^ip access-list extended (\S+)(.*)$/i) {			# a header of an ACL
			$acl = "ACL_$1";
			my $otherstuff = $2;

			if (! &simpleChars($acl)) {
				$err = "invalid character in ACL";
			}
			$acl_list{$acl} = 1;

			if ($otherstuff =~ /color (\S+)/) {
				my $color = $1;
				if (! ( $acl_color{$acl} = &validColor($color) )) {
					$err = "invalid color: '$color'";
				}
			}
			elsif ($otherstuff !~ /append/) {
				@{$acl} = ();			# force a blank array
			}

			while ($cli = &snarfText($fh, 1)) {
				if ($cli !~ /^(permit|deny) /i) {		# a line of an ACL
					$err = "syntax error";
					last;
				}

				$rule = {};			# start with an empty rule

				block: {
				# --- get permit|deny
				$a = &hackACL(\$cli, \%cisco_permit);
				if (! defined $a) { $err = "syntax error"; last; }
				$rule->{permit} = $a;

				# --- get protocol
				$a = &hackACL(\$cli, \%cisco_protocols, undef, 0, $MAXBYTE, undef, \%string_protocol);
				if (! defined $a) { $err = "syntax error"; last; }
				$rule->{protocol} = $a;

				# -- get source
				last if ($err = &getSD(\$cli, $rule, 'source'));

				# -- get destination
				last if ($err = &getSD(\$cli, $rule, 'destination'));

				# -- get ICMP type/msg code
				if ($rule->{protocol} == 1) {
					while ($a = &hackACL(\$cli, \%cisco_icmp, undef, 0, 255)) {
						if (($a >= 0) && ($a < 255)) {		# manual message type
							$a1 = $a;
							$a2 = &hackNum(\$cli, 0, 255);
							if (! defined $a2) { $err = "syntax error"; last; }
							$a = ($a1 << 8) | $a2;
						}
						$a = 0 if ($a == 0xff00);		# special hack
						push(@{$rule->{icmpMsgs}}, $a);
					}
				}

				# -- get TCP flags
				if ($rule->{protocol} == 6) {
					while ($a = &hackACL(\$cli, \%cisco_tcp_flags)) {
						if ($a > 0) {
							$rule->{tcpFlags} |= $a;
						}
						elsif ($a == -256) {
							if ( ($a = &hackACL(\$cli, \%cisco_tcp_flags)) > 0) {
								$rule->{tcpNotFlags} |= $a;
							}
							else {
								$err = 'syntax error'; last block;
							}
						}
						else {
							$rule->{tcpNotFlags} |= -$a;
						}
					}
				}

				while ($a = &hackACL(\$cli, \%cisco_optionals)) {
					if ($a == 1) {				# precedence
						$a = &hackACL(\$cli, \%cisco_precedence, undef, 0, 7, undef, \%string_tos);
						if (! defined $a) { $err = "syntax error"; last; }
						$rule->{precedence} = $a;
					}
					elsif ($a == 2) {			# tos
						$a = &hackACL(\$cli, undef, undef, 0, 255, undef, \%string_tos);
						if (! defined $a) { $err = "syntax error"; last; }
						$rule->{tos} = $a;
					}
					elsif ($a == 3) {			# bytes
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG, undef);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{bytesMatch} = $a1;
						$rule->{bytes1} = $a2;
						$rule->{bytes2} = $a3;
					}
					elsif ($a == 4) {			# packets
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG, undef);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{packetsMatch} = $a1;
						$rule->{packets1} = $a2;
						$rule->{packets2} = $a3;
					}
					elsif ($a == 5) {			# seconds
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG, undef);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{secondsMatch} = $a1;
						$rule->{seconds1} = $a2;
						$rule->{seconds2} = $a3;
					}
					elsif ($a == 6) {			# reverse
						$reverse = 1;
					}
					elsif ($a == 7) {			# next-hop
						$a = &hackACL(\$cli, undef, 2, undef, undef, undef, \%string_ip);
						if ($a =~ /^\$/) {
							$rule->{nextHopIP} = $a;
							$rule->{nextHopMask} = 0xffffffff;
						}
						elsif ($a =~ /([\d\.]+)\/?([\d\.]*)/) {
							$rule->{nextHopIP} = $1;
							$rule->{nextHopMask} = $2 || 0xffffffff;
						}
						else {
							$err = "syntax error"; last;
						}
					}
					elsif ($a == 8) {			# exporter
						$a = &hackACL(\$cli, \%exporterIP, 2, undef, undef, undef, \%string_ip);
						if ($a =~ /^\$/) {
							$rule->{exporterIP} = $a;
							$rule->{exporterMask} = 0xffffffff;
						}
						elsif ($a =~ /([\d\.]+)\/?([\d\.]*)/) {
							$rule->{exporterIP} = $1;
							$rule->{exporterMask} = $2 || 0xffffffff;
						}
						else {
							 $err = "syntax error"; last;
						}
					}
					elsif ($a == 9) {			# bps  BYTES per second
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{bpsMatch} = $a1;
						$rule->{bps1} = $a2;
						$rule->{bps2} = $a3;
					}
					elsif ($a == 10) {			# pps
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{ppsMatch} = $a1;
						$rule->{pps1} = $a2;
						$rule->{pps2} = $a3;
					}
					elsif ($a == 11) {			# packetsize
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{packetsizeMatch} = $a1;
						$rule->{packetsize1} = $a2;
						$rule->{packetsize2} = $a3;
					}
					elsif ($a == 12) {			# dscp
						$a = &hackACL(\$cli, \%cisco_dscp, undef, 0, 63, undef, \%string_tos);
						if (! defined $a) { $err = "syntax error"; last; }
						$rule->{dscp} = $a;
					}
					elsif ($a == 13) {			# flow / facl matching
						$a = &hackACL(\$cli, '\%[A-Za-z\_]+');
						if (! defined $a) { $err = "syntax error"; last; }
						$a =~ s/\%/FACL_/;
						$rule->{facl} = $a;
						$referenced_facl{$a} = 1;
					}
					elsif ($a == 14) {			# ecn
						$a = &hackACL(\$cli, \%cisco_ecn, undef, 0, 3, undef, \%string_tos);
						if (! defined $a) { $err = "syntax error"; last; }
						$rule->{ecn} = $a;
					}
					elsif (($a >= 15) && ($a <= 17)) {			# kbps / mbps / gbps
						($a1, $a2, $a3) = &getRange(\$cli, undef, 0, $MAXLONG);
						if (($a1 eq "err") || (! defined $a1)) { $err = "syntax error"; last; }
						$rule->{bpsMatch} = $a1;
						$rule->{bps1} = $a2 * 125 * (($a == 15) ? 1 : (($a == 16) ? 1_000 : 1_000_000));
						$rule->{bps2} = $a3 * 125 * (($a == 15) ? 1 : (($a == 16) ? 1_000 : 1_000_000));
					}
				}
				}	# escapable block

				if (! $err) {
					if (length($cli) > 0)  {
						$err = "syntax error";
					}
					elsif ( ((defined $rule->{sourceIf}) && ($rule->{sourceIf} !~ /^\$/)) 
						|| ((defined $rule->{destinationIf}) && ($rule->{destinationIf} !~ /^\$/))
					) {	# check interfaces
						if (! defined $rule->{exporterIP}) {
							$err = "must include an 'exporter' with interface references";
						}
						elsif ($rule->{exporterMask} != 0xffffffff) {
							$err = "host 'exporter' required for interface references";
						}
						elsif ($rule->{exporterIP} !~ /^\$/) {
							if (! ($err = &hackInterface($rule->{exporterIP}, \$rule->{sourceIf})) ) {
								$err = &hackInterface($rule->{exporterIP}, \$rule->{destinationIf});
							}
						}
					}
				}

				if ((! $err) && (! exists $rule->{facl})) {		# check lost facl references
					foreach (qw/
						sourceIP sourceIf sourceAS sourcePort1 sourcePort2
						destinationIP destinationIf destinationAS destinationPort1 destinationPort2
						exporterIP nexthopIP
						protocol dscp precedence tos
						packets1 packets2 bytes1 bytes2 seconds1 seconds2
					/) {
						if ($rule->{$_} =~ /^(\$.*)/) {
							$err = "flow reference variables like \"$1\" require a \"host \%foo\" statement";
							last;
						}
					}
				}

				if ((! $err) && (my $facl = $rule->{facl})) {		# validate facl
					my (@hashkeys, @hashvals);	# contains a hash index
					my $exp = 0;

					&hashKeyInt($rule, \@hashkeys, \@hashvals, undef, 'protocol');

					$exp = 1 if (&hashKeyInt(    $rule, \@hashkeys, \@hashvals, '$input_if',  'sourceIf'));
					&hashKeyInt(    $rule, \@hashkeys, \@hashvals, '$srcas',     'sourceAS');
					&hashKeyIP(	$rule, \@hashkeys, \@hashvals, '$srcip',     'sourceIP',      'sourceMask');
					&hashKeyMatch(	$rule, \@hashkeys, \@hashvals, '$srcport',   'sourcePort');

					$exp = 1 if (&hashKeyInt(    $rule, \@hashkeys, \@hashvals, '$output_if', 'destinationIf'));
					&hashKeyInt(    $rule, \@hashkeys, \@hashvals, '$dstas',     'destinationAS');
					&hashKeyIP(	$rule, \@hashkeys, \@hashvals, '$dstip',     'destinationIP', 'destinationMask');
					&hashKeyMatch(	$rule, \@hashkeys, \@hashvals, '$dstport',   'destinationPort');

					&hashKeyInt($rule, \@hashkeys, \@hashvals, undef, 'dscp');
					&hashKeyInt($rule, \@hashkeys, \@hashvals, undef, 'tos');
					&hashKeyInt($rule, \@hashkeys, \@hashvals, undef, 'precedence');

					if ($exp) {		# if interfaces used, be sure to key off exporter
						$rule->{exporterIP} = '$exporterip';
						$rule->{exporterMask} = 0xffffffff;
					}

					&hashKeyIP($rule, \@hashkeys, \@hashvals, '$nexthopip', 'nexthopIP', 'nexthopMask');
					&hashKeyIP($rule, \@hashkeys, \@hashvals, '$exporterip', 'exporterIP', 'exporterMask');

					my $hashkey = join(',', map { $facl_expansion{$_} || $_ } @hashkeys);
					my $hashval = join(',', map { $facl_expansion{$_} || $_ } @hashvals);
					my $ihashval = join(',', map { &flipFacl($_) } map { $facl_expansion{$_} || $_ } @hashkeys);

					if (! exists $FACL->{$facl}->{hashes}->{$hashkey}) {
						$FACL->{$facl}->{hashes}->{$hashkey} = $facl . '_' . (++$FACL->{$facl}->{count});
					}
					my $faclName = $FACL->{$facl}->{hashes}->{$hashkey};

					$rule->{facl} = '($' . $faclName . '{' . $hashval . '} >= $startime)';
					$rule->{ifacl} = '($' . $faclName . '{' . $ihashval . '} >= $startime)';
				}

				if (! $err) {
					push(@{$acl}, $rule);

					# if reverse is specified, also push on a mirror image rule.
					if ($reverse) {
						undef $newrule;

						# blindly copy over all attributes
						foreach (keys %$rule) { $newrule->{$_} = $rule->{$_}; }

						# overwrite the ones that flip
						$newrule->{sourceIP} = $rule->{destinationIP};
						$newrule->{sourceMask} = $rule->{destinationMask};
						$newrule->{sourceIf} = $rule->{destinationIf};
						$newrule->{sourceAS} = $rule->{destinationAS};
						$newrule->{sourcePortMatch} = $rule->{destinationPortMatch};
						$newrule->{sourcePort1} = $rule->{destinationPort1};
						$newrule->{sourcePort2} = $rule->{destinationPort2};
						$newrule->{sourceDACL} = $rule->{destinationDACL};

						$newrule->{destinationIP} = $rule->{sourceIP};
						$newrule->{destinationMask} = $rule->{sourceMask};
						$newrule->{destinationIf} = $rule->{sourceIf};
						$newrule->{destinationAS} = $rule->{sourceAS};
						$newrule->{destinationPortMatch} = $rule->{sourcePortMatch};
						$newrule->{destinationPort1} = $rule->{sourcePort1};
						$newrule->{destinationPort2} = $rule->{sourcePort2};
						$newrule->{destinationDACL} = $rule->{sourceDACL};

						$newrule->{facl} = $rule->{ifacl} if (exists $rule->{ifacl});

						push(@{$acl}, $newrule);
					}
				}
			}
		}
		else {
			$err = "syntax error";
		}

		if ($err) {
			if ($fname ne $errfname) {
				$errfname = $fname;
				&logit($LOG_ERROR, "[config file: $errfname]");
			}
			if ($errCount == 15) {
				&logit($LOG_ERROR, "too many errors");
			}
			elsif ($errCount < 15) {
				if ($cli ne "") {
					&logit($LOG_ERROR, "line $lineCount{$fh}: $err at/before '$cli'");
				}
				else {
					&logit($LOG_ERROR, "line $lineCount{$fh}: $err");
				}
			}
			$errCount++;
		}
	}
	close($fh);
	return $errCount;
}

sub safepush		# push args only if they don't already exist on the array
{
	my $p = shift;

	foreach my $arg (@_) {
		my $ok = 1;
		foreach (@$p) { if ($_ eq $arg) { $ok = 0; last; } }
		push(@$p, $arg) if ($ok);
	}
}

sub simpleChars
{
	return ($_[0] =~ /^[a-zA-Z0-9\_]*$/);
}

sub filenameChars
{
	return ($_[0] =~ /^[a-zA-Z0-9\_\-\/\.]*$/);
}

sub getSD
{
	my ($cli, $rule, $dir) = @_;
	my $a;

	my($MAXINT) = 2**16 - 1;

	# -- get source interface
	$a = &hackACL($cli, "[a-z\\-]+[\\d\\/\\.\\:]*\\d", undef, undef, undef, undef, \%string_if);
	$rule->{$dir . "If"} = $a if (defined $a);

	# -- get source AS
	$a = &hackACL($cli, undef, undef, 0, $MAXINT, undef, \%string_as);
	$rule->{$dir . "AS"} = $a if (($a) || ($a eq "0"));

	# -- get source IP
	$a = &hackACL($cli, \%cisco_ipaddr);
	if ($a == 1) {		# 'any'
		$rule->{$dir . "IP"} =  &composeIP(0, 0, 0, 0);
		$rule->{$dir . "Mask"} = &composeIP(0, 0, 0, 0);
	}
	elsif ($a == 2) {	# 'host x.x.x.x'
		$a = &hackACL($cli, undef, 1, undef, undef, 1, \%string_ip);		# get the IP/racl
		if (! defined $a) { return "syntax error"; }
		$rule->{$dir . "IP"} = $a;
		$rule->{$dir . "Mask"} =  &composeIP(255, 255, 255, 255 );
		$rule->{$dir . "DACL"} = ($a =~ /^DACL_/);
	}
	else {
		$a = &hackACL($cli, undef, 2, undef, undef, undef, \%string_ip);	# get the IP
		if ($a !~ /^(\d+)\/(\d+)$/) { return "syntax error"; }
					
		$rule->{$dir . "IP"} = $1;
		if ($2 ne 0xffffffff) {
			$rule->{$dir . "Mask"} = $2;
		}
		else {
			$a = &hackACL($cli, undef, 1);
			if (! defined $a) { return "syntax error"; }
			$rule->{$dir . "Mask"} = $a ^ 0xffffffff;
		}
	}

	# -- get source port information for TCP/UDP
	if (($rule->{protocol} == 6) || ($rule->{protocol} == 17) || ($rule->{protocol} =~ /^\$/)) {
		my $hash = ($rule->{protocol} == 6) ? \%cisco_tcp_services : \%cisco_udp_services;

		my ($a1, $a2, $a3) = &getRange($cli, $hash, 0, 65535, \%string_port);
		if ($a1 eq "err") { return "syntax error"; }
		elsif (defined $a1) {
			$rule->{$dir . "PortMatch"} = $a1;
			$rule->{$dir . "Port1"} = $a2;
			$rule->{$dir . "Port2"} = $a3;
		}
	}
	return;
}


# ---------------------------------------------
# for FACLs, this routines help compose a suitable hash

sub flipFacl
{
	my $x = shift;
	return $x if ($x =~ s/src/dst/);
	return $x if ($x =~ s/dst/src/);
	return $x if ($x =~ s/input/output/);
	return $x if ($x =~ s/output/input/);
	return $x;
}

sub hashKeyMatch
{
	my($rule,$keys,$vals,$def,$item) = @_;

	if (($rule->{$item . 'Match'} == 1) && ($rule->{$item . '1'} =~ /^\$/)) {
		$def = $rule->{$item . '1'} if (! defined $def);
		push(@$keys, $def);
		push(@$vals, $rule->{$item . '1'});

		delete $rule->{$item . 'Match'};
		delete $rule->{$item . '1'};
		delete $rule->{$item . '2'};
		return 1;
	}
}

sub hashKeyInt
{
	my($rule,$keys,$vals,$def,$int) = @_;

	if ($rule->{$int} =~ /^\$/) {
		$def = $rule->{$int} if (! defined $def);
		push(@$keys, $def);
		push(@$vals, $rule->{$int});

		delete $rule->{$int};
		return 1;
	}
}

# key  = how to compose the hash
# vals = how to invoke the hash for this rule

sub hashKeyIP
{
	my($rule,$keys,$vals,$def,$ip,$mask) = @_;

	if ($rule->{$ip} =~ /^\$/) {
		$def = $rule->{$ip} if (! defined $def);
		if ($rule->{$mask} == 0xffffffff) {
			push(@$keys, $def);
			push(@$vals, $rule->{$ip});
		}
		else {
			my $mask = ' & 0x' . sprintf("%08x", $rule->{$mask});
			push(@$keys, $def . $mask);
			push(@$vals, $rule->{$ip}) . $mask;
		}

		delete $rule->{$ip};
		delete $rule->{$mask};
		return 1;
	}
}

# ---------------------------------------------
# this routine supports the use of dacls for ports, but we'd never
# use them because that's just absurd. Update - 2007 - port facls
# are being implemented!
sub getRange
{
	my($cli, $hash, $min, $max, $faclS) = @_;
	my($match, $port1, $port2);

	if ($a = &hackACL($cli, \%cisco_range)) {
		$match = $a;

		if ($match == 1) {		# only allow facls if range is 'eq'
			$a = &hackACL($cli, $hash, undef, $min, $max, undef, $faclS);
		}
		else {
			$a = &hackACL($cli, $hash, undef, $min, $max, undef, undef);
		}
		return "err" if (! defined $a);
		$port1 = $a;

		if ($match == 5) {	# range!
			$a = &hackACL($cli, $hash, undef, $min, $max, undef, undef);
			return "err" if (! defined $a);
			$port2 = $a;
		}

		return ($match, $port1, $port2);
	}
	return undef;
}

# ---------------------------------------------
# parms:
#   required (1) or optional (0)
#   pointer to string to hack
#   pointer to hash of string values
#   1 if IP addresses are allowed (2 if IP/bits allowed)
#   minimum number allowed
#   maximum number allowed
#   1 if dynamic ACLs are an allowed response
#
sub hackACL
{
	my($string, $hash, $ip, $min, $max, $daclOK, $faclS) = @_;
	my($token, $t2, $v);

#	&logit($LOG_SUPERDEBUG, "hackACL: string=$$string, hash=$hash, ip=$ip, min=$min, max=$max, dacl=$daclOK, ") if ($debug);

	if ($$string =~ /^\s*(\S+)/) {
		$token = $1;

		if (defined $hash) {
			if (ref($hash) eq '') {		# not a reference, must be an exact match
				if ($token =~ /^$hash$/i) { $v = $token; }	# set boolean return value
			}
			else {
				$v = $hash->{lc($token)} if (exists $hash->{lc($token)});
			}
		}
		if ((! defined $v) && ($token =~ /^[\d\_]+$/) && (defined $min) && (defined $max)) {
			$token = &noUnderscores($token);
			$v = $token if (($token >= $min) && ($token <= $max));
		}
		if ((! defined $v) && ($ip)) {
			if ($token =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/?(\d*)$/) {
				if (($1 <= 255) && ($2 <= 255) && ($3 <= 255) && ($4 <= 255)) {
					$v = ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;
					if ($ip != 2) { undef $v if (length($5)); }
					elsif ($5 eq '0') { $v .= '/0'; }
					elsif ($5) { $v .= '/' . (0xffffffff << (32 - $5)); }
					else { $v .= '/' . 0xffffffff; }
				}
			}
		}
		if ((! defined $v) && (defined $faclS)) {
#			print "checking '$token' against (" . join(',', keys %$faclS) . ")\n";

			$v = lc($token) if (exists $faclS->{lc($token)});
		}
		if ((! defined $v) && (defined $daclOK) && ($token =~ /^[\@|\%]/)) {
			$v = $token;
			if ($v =~ s/\@/DACL_/) {
				$referenced_dacl{$v} = 1;
			}
			elsif ($v =~ s/\%/FACL_/) {
				$referenced_facl{$v} = 1;
			}
		}
	}

	if (defined $v) {
		$$string =~ s/[\s\-]*(\S+)//;
		return $v;
	}

	return undef;
}

sub hackNum
{
	my($string, $min, $max) = @_;
	my($v, $token);

	if ($$string =~ /^\s*([\d\_]+)(.*)/) {
		$token = &noUnderscores($1);
		if (($token >= $min) && ($token <= $max)) {
			$$string = $2;
			return $token;
		}
	}
	return undef;
}

sub composeIP
{
	my($x1, $x2, $x3, $x4) = @_;
	return undef if (($x1 > 255) || ($x2 > 255) || ($x3 > 255) || ($x4 > 255));
	return undef if (($x1 < 0) || ($x2 < 0) || ($x3 < 0) || ($x4 < 0));
	return ($x1 << 24) | ($x2 << 16) | ($x3 << 8) | $x4;
}

sub hackIP
{
	return undef if ($_[0] !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	return &composeIP($1,$2,$3,$4);
}

sub hackIPMask
{
	return undef if ($_[0] !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/?(\d*)$/);
	return (&composeIP($1,$2,$3,$4), ($5 || 32));
}

sub unhackIP     # integer -> dotted decimal
{
	my(@x) = ($_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
	return join(".", @x);
}

sub noUnderscores		# this subroutine really hates underscores
{
	my($x) = $_[0];
	$x =~ s/\_//g;
	return $x;
}

# -------------------------------------------------------------------
# this loads a list of all the interfaces from the device.
# it is only used if exporter commands are found in the config file.
# the results are stored in a hash specifically for this device...
#  interfaces{exporter}    e.g..  interfaces{12322}{"gigabitethernet11/0"} = 23
#
# a "clean" version of the interface name is also composed without all the special chars.
#
# if called with an undefined exporterName, this fills it in

sub hash2str
{
	my $hp = shift;
	return join($;, map { $_ . '=' . $hp->{$_} } sort keys %$hp);
}

sub str2hash
{
	my $hp = {};
	foreach (split(/$;/, shift)) { if (/^(.*)=(.*)$/) { $hp->{$1} = $2; } }
	return $hp;
}

sub snmphost		# nice print a snmpHost string
{
	return '(' . join(' ', split(/$;/, shift)) . ')';
}

sub snmperr
{
	my($method, $err, $snmpHost, @oids) = @_;
	&logit($LOG_ERROR, "<detail> Net::SNMP error with method '$method', snmpHost " . &snmphost($snmpHost) . ( (@oids) ? ", oids @oids" : "") );
	&logit($LOG_ERROR, "<detail> Net::SNMP reports '" . $err . "'");
}

sub snmpget
{
	my $snmpHost = shift;
	my $quiet = shift;
	my($session,$error) = Net::SNMP->session( %{&str2hash($snmpHost)} );
	if ($error) { &snmperr("snmpsession", $error, $snmpHost); return undef; }
	$session->translate(0);
	my @oids;
	foreach my $oidName (@_) {
		$oidName =~ /^(.*?)([\d\.]*)$/;
		my $oid = $snmpoid{$1} . $2 || do { &logit($LOG_ERROR, "Unknown SNMP OID: $oidName"); return undef; };
		push(@oids, $oid);
	}
	my $results = $session->get_request(-varbindlist => \@oids);

	if (! defined $results) {
		&snmperr("snmpget", $session->error(), $snmpHost, (map { $_[$_] . "(" . $oids[$_] . ")" } 0 .. $#oids) ) if (! $quiet);
		return undef;
	}
	return (wantarray) ? ( map { $results->{$_} } @oids ) : $results->{$oids[0]};
}

sub snmpwalk
{
	my $snmpHost = shift;
	my($session,$error) = Net::SNMP->session( %{&str2hash($snmpHost)} );
	if ($error) { &snmperr("snmpsession", $error, $snmpHost); return undef; }
	$session->translate(0);

	my $oidName = shift;
	my $oid = $snmpoid{$oidName} || do { &logit($LOG_ERROR, "Unknown SNMP OID: $oidName"); return undef; };
	my $results = $session->get_table(-baseoid => $oid);
	if (! defined $results) { &snmperr("snmpwalk", $session->error(), $snmpHost, $oidName . "($oid)"); }
	return ( map { my $x=$_; $x =~ s/^$oid\.//; $x . ':' . $results->{$_} } oid_lex_sort(keys %$results) );
}

sub loadInterfaces
{
	my($exporter, $exporterName, $hashp, $noticeLevel) = @_;
	my @snmpHosts;	# array of snmp stuff to try

	my $exporterIP = &unhackIP($exporter);		# retrieve the dotted-decimal version

	# use snmpSession variables, if they exist
	if ((exists $hashp->{snmpSession}) && (@{$hashp->{snmpSession}})) {
		foreach my $ssession (@{$hashp->{snmpSession}}) {
			next if (! exists $snmpSessions{$ssession});
			my $sh = { -hostname => $exporterIP,  };
			while ( my($k,$v) = each %{$snmpSessions{$ssession}} ) { $sh->{$k} = $v; }
			push(@snmpHosts, &hash2str($sh));
		}
	}
	elsif ((exists $hashp->{community}) && ($hashp->{version})) {
		foreach (@{$hashp->{community}}) {
			push(@snmpHosts, &hash2str( {
				-hostname => $exporterIP,
				-version => int($hashp->{version}) || 2,
				-port => int($hashp->{port}) || 161,
				-community => $_
			} ) );
		}
	}

	my $noncisco = $hashp->{noncisco};
	my $iponly = $hashp->{iponly};
	my $autoname = $hashp->{name};			# auto or dns or snmp
	my $auto = $hashp->{auto};			# whether this exporter is auto-discovered

	my $localNoSNMP = ( $noSNMP || (! @snmpHosts) );

	my($snmpHost, $snmpDead);
	my($ifIndex, $ifDescr, $ifAlias, %ifDescr, %ifAlias, %ifSpeed);

	my($oldSysName, $oldSysUpTime, $oldIfTableLastChange, $lastMajorPollTime, $lastMinorPollTime, $oldSnmpHost, $oldExporterName);
	my($sysName, $sysUpTime, $ifTableLastChange);

	my ($useCache, $saveCache, $purgeCacheFile);
	my $cacheFileAge;

	my $MAJOR_POLL_INTERVAL = 43200;		# 12 hours
	my $MINOR_POLL_INTERVAL = 3600 * 2;		# 2 hours

	my $logtag = "Exporter $exporterName($exporterIP): ";
	$ifCacheDir = $stateDir if (! defined $ifCacheDir);
	my $cacheFile = "$ifCacheDir/ifData.$exporterIP";

	# --- try to load the data from a cache file.
	if (open(IN, $cacheFile)) {
		chomp($oldSysUpTime = <IN>);
		chomp($oldIfTableLastChange = <IN>);
		chomp($lastMajorPollTime = <IN>);
		chomp($lastMinorPollTime = <IN>);
		chomp($oldSnmpHost = <IN>);
		chomp($oldSysName = <IN>);
		chomp($oldExporterName = <IN>);

		if (($auto) || ($exporterName eq $oldExporterName)) {	# auto or hardcoded name still matches
			$cacheFileAge = time - $lastMajorPollTime;	# (stat($cacheFile))[9];

			@snmpHosts = ($oldSnmpHost, grep(! /^$oldSnmpHost$/, @snmpHosts) );
			$useCache = 1;

			if ($auto) {
				$exporterName = $oldExporterName;
				$logtag = "Exporter $exporterName($exporterIP): ";
			}
		}
	}

	if ( ( ! $localNoSNMP) && ((time - $lastMinorPollTime) > $MINOR_POLL_INTERVAL) ) {
		$lastMinorPollTime = time;
		$saveCache = 1;

		my $snmpHostCount = 0;

		foreach (@snmpHosts) {
			$snmpHost = $_;
			&logit($LOG_DEBUG, "$logtag Trying snmpHost " . ++$snmpHostCount . " of " . (scalar @snmpHosts) . ": " . &snmphost($_) );

			# --- Grab the sysName, sysUpTime and ifTableLastChange via SNMP
			if ($noncisco) {
				($sysName, $sysUpTime) = &snmpget($snmpHost, 1, "sysName", "sysUpTime");
			}
			else {
				($sysName, $sysUpTime, $ifTableLastChange) = &snmpget($snmpHost, 1, "sysName", "sysUpTime", "ifTableLastChange");
			}

			last if ($sysUpTime > 0);		# community worked!
		}

		if (! $sysUpTime > 0) {		# snmp failed!
			&logit($LOG_INFO, "$logtag No working snmpHost found!");
			$snmpDead = 1;

			if ( ($auto) && (exists $hashp->{lifespan}) && ($cacheFileAge > $hashp->{lifespan}) ) {
				close(IN);
				unlink($cacheFile);
				return undef;
			}
		}
		else {
			&logit($LOG_INFO, "$logtag Primary snmpHost: " . &snmphost($snmpHost) ) if ($snmpHostCount > 1);

			if ($useCache) {			# snmp ok and cache ok
				if ( (time - $lastMajorPollTime) > $MAJOR_POLL_INTERVAL) {
					&logit($LOG_DEBUG, "$logtag 12 hours passed; forcing poll");
					undef $useCache;
				}

				if ($sysName ne $oldSysName) {
					&logit($LOG_INFO, "$logtag SNMP sysName has changed from $oldSysName to $sysName");
					undef $useCache;
					if ($auto) {
						close(IN);
						undef $exporterName;
					}
				}

				if ($snmpHost ne $oldSnmpHost) {
					&logit($LOG_DEBUG, "$logtag SNMP access has changed from $oldSnmpHost to $snmpHost");
					undef $useCache;
				}
				if ($sysUpTime < $oldSysUpTime) {
					&logit($LOG_DEBUG, "$logtag SNMP sysTime indicates a reboot");
					undef $useCache;
				}
				if ($ifTableLastChange != $oldIfTableLastChange) {
					&logit($LOG_DEBUG, "$logtag SNMP ifTableLastChange has changed");
					undef $useCache;
				}
			}
		}
	}

	if ( ($useCache) && ($oldSysUpTime == 0) ) {		# negative cache files
		$snmpDead = 1;
	}

	if ($useCache) { 		# cache exists and either the device is stable or SNMP is dead
		while ( <IN> ) {
			next if (! /\t/);
			chomp;
			my($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);
			$ifDescr{$ifIndex} = $ifDescr;
			$ifAlias{$ifIndex} = $ifAlias;
			$ifSpeed{$ifIndex} = $ifSpeed;
		}

		if (scalar keys %ifDescr) {
			&logit($noticeLevel, "$logtag Loaded " . (scalar keys %ifDescr) . " interfaces from $cacheFile") if (! $snmpDead);
			$globalLoadInterfaceCache++;
		}
	}
	close(IN);		# filehandle might not even be open; we don't care

	# --- if name is undefined, try to figure it out
	if (! defined $exporterName) {
		if ( ($autoname ne 'dns') && ($sysName =~ /^([^\.]+)/) ) {			# learn from SNMP
			$exporterName = $1 ;
		}
		elsif ( ($autoname ne 'snmp') && (&ghba($exporterIP) =~ /^([^\.]+)/) ) {	# learn from DNS
			$exporterName = $1 ;
		}
		else {
			$exporterName = $exporterIP;
			$exporterName =~ tr/./-/;
			&logit($LOG_INFO, "$logtag Could not determine device name; using $exporterName");
		}
		$logtag = "Exporter $exporterName($exporterIP): ";
		$saveCache = 1;		# true even if snmpDead=1
	}

	# --- if snmp has failed and we don't have any cached info, fail
	if ($snmpDead) {
		if (scalar keys %ifDescr == 0) {
       		 	&logit($LOG_ERROR, "$logtag doesn't respond to SNMP. Unable to collect interfaces.");
			$globalLoadInterfaceFail++;
		}
		else {
       		 	&logit($LOG_INFO, "$logtag doesn't respond to SNMP. Using cached interface list (age=" .
				sprintf("%d days, %d hours", int($cacheFileAge / 86400), int( ($cacheFileAge % 86400) / 3600 )) .
				")");
		}
	}

	elsif (scalar keys %ifDescr == 0) {		# cache didn't exist or was ignored
		if ($localNoSNMP) {
       			&logit($noticeLevel, "$logtag needs to be SNMP polled, but SNMP was disabled.") if ($noSNMP);
			$globalLoadInterfaceSkip++;
			return 1;		# spoofed answer
		}

		my ($oid, $desc, %oid2ifIndex, @ifs, $useGet);

		if ($iponly) {
			my $ifNumber = &snmpget($snmpHost, 0, "ifNumber");

			if ($ifNumber >= 20) {			# identify IP-enabled ifs from cisco devices with 20+ ifs
				foreach ( &snmpwalk($snmpHost, "ipAdEntIfIndex") ) {
					($oid, $desc) = split(':', $_, 2);
					push(@ifs, $desc);
				}

				# ratio of all interfaces to IP-enabled interfaces
				$useGet = ( int( $ifNumber / (@ifs || 1) ) > 1);
			}
		}

		if ($useGet) {		# grab IP-enabled interfaces using SNMPGET

			while (@ifs) {
				my @wifs = splice(@ifs,0,20);

				my @tifs = @wifs;
				map { $ifDescr{shift @tifs} = $_ } &snmpget($snmpHost, 0, map { "ifDescr.$_" } @wifs );

				my @tifs = @wifs;
				map { $ifAlias{shift @tifs} = $_ } &snmpget($snmpHost, 0, map { "ifAlias.$_" } @wifs );

				my @tifs = @wifs;
				map { $ifSpeed{shift @tifs} = $_ } &snmpget($snmpHost, 0, map { "ifSpeed.$_" } @wifs );
			}
		}
		else {				# grab all interfaces using SNMPWALK
			foreach ( &snmpwalk($snmpHost, "ifIndex") ) {
				($oid, $desc) = split(':', $_, 2);
				$oid2ifIndex{$oid} = $desc;
			}

			if (! %oid2ifIndex) {
				&logit($LOG_TRIVIA, "$logtag Error gathering snmp ifIndex");
				$globalLoadInterfaceFail++;
				return undef;
			}

			foreach ( &snmpwalk($snmpHost, "ifDescr") ) {
				($oid, $desc) = split(':', $_, 2);
				$ifDescr{$oid2ifIndex{$oid}} = $desc;
			}

			foreach ( &snmpwalk($snmpHost, "ifAlias") ) {
				($oid, $desc) = split(':', $_, 2);
				$ifAlias{$oid2ifIndex{$oid}} = $desc;
			}

			foreach ( &snmpwalk($snmpHost, "ifSpeed") ) {
				($oid, $desc) = split(':', $_, 2);
				$ifSpeed{$oid2ifIndex{$oid}} = $desc;
			}
		}

		$lastMajorPollTime = time;
		&logit($noticeLevel, "$logtag Loaded " . (scalar keys %ifDescr) . (($useGet) ? " IP-enabled" : "") . " interfaces from SNMP");
		if (scalar keys %ifDescr) { $globalLoadInterfaceSNMP++; } else { $globalLoadInterfaceFail++; }
		$saveCache = 1;
	}

	# --- write out a new cache file
	if ( ($saveCache) && (! $checkConfig) ) {
		open(OUT, ">$cacheFile.tmp") || &logit($LOG_ERROR, "$logtag Unable to write $cacheFile.tmp");
		print OUT <<EOT;
$sysUpTime
$ifTableLastChange
$lastMajorPollTime
$lastMinorPollTime
$snmpHost
$sysName
$exporterName
EOT

		foreach (sort {$a <=> $b} keys %ifDescr) {
			print OUT join("\t", $_, $ifDescr{$_}, $ifAlias{$_}, $ifSpeed{$_}) . "\n";
		}
		close(OUT);

		rename "$cacheFile.tmp", $cacheFile;		# single operation
	}

	# --- pack the data into data structures for flowage consumption
	foreach my $ifIndex (keys %ifDescr) {
		my $ifDescr = $ifDescr{$ifIndex};
		my $ifAlias = $ifAlias{$ifIndex};
		my $ifSpeed = $ifSpeed{$ifIndex};

		# set globals
		${"if_$exporter"}{$ifDescr} = $ifIndex;
		${"iif_$exporter"}{$ifIndex} = $ifDescr;
		${"ifAlias_$exporter"}{$ifIndex} = $ifAlias;
		${"ifSpeed_$exporter"}{$ifIndex} = $ifSpeed;
		$ifDescr =~ s/[^A-Z^a-z^0-9^\-]/sprintf("%%%2x",ord($&))/ge;
		${"iif_clean_$exporter"}{$ifIndex} = $ifDescr;
	}

	return (scalar keys %ifDescr, $exporterName) if (wantarray);
	return scalar keys %ifDescr;
}

# checks to see if an exporter exists -- is called from the wanted() subroutine!
sub checkAutoExporter
{
	my $exp = shift;
	$exporterName{$exp} = undef;		# ensure we aren't called again for this guy

	if ( my $hashp = $autoExporterTrie->match_integer($exp) ) {	# we have a match!
		&logit($LOG_INFO, "Interrogating new exporter " . &unhackIP($exp) );
		my ($count, $discoveredExporterName) = &loadInterfaces($exp, undef, $hashp, $LOG_INFO);

		if ($count) {
			&logit($LOG_INFO, "Discovered new exporter " . &unhackIP($exp) . " ($discoveredExporterName)" );
			$exporterName{$exporter} = $discoveredExporterName;
			return 1;
		}
	}
	else {
		&logit($LOG_INFO, "Skipping new exporter " . &unhackIP($exp) );
	}
	return 0;
}

# -------------------------------------------------------------------
# returns an error string or undef if successful

sub hackInterface
{
	my($exp, $ifp) = @_;
	my($ifS, $ifN);

	return undef if (! $$ifp);		# nothing to do- undef=okay!
	if ($$ifp =~ /^snmpIf(\d+)$/i) {	# user has specified an integer
		$$ifp = $1;
		return undef;
	}

	return "unknown exporter" if (! %{"if_$exp"});

	if ($$ifp =~ /^([a-z\-]+)([\d\/\.\:]+\d)$/i) { # "se0/0/2.3" -> "Serial0/0/2.3"
		$ifS = $1;			# fuzzy match on string portion
		$ifN = $2;			# exact match on numeric portion

		foreach (keys %{"if_$exp"}) {
			next if (! /^(.*\D)$ifN(.*)$/);	# skip if not exact match on last part
			my $suffix = $2;
			next if ($1 !~ /^$ifS/i);	# skip if not fuzzy match on first part

			if ($suffix ne "") {
				# begin with '-' and contain 'aal5' (atm) or 'vlan' (ethernet)
				next if ($suffix !~ /^-.*(aal5|vlan)/i);
			}

			&logit($LOG_DEBUG, "if '" . $$ifp . "' matches ifIndex '" . ${"if_$exp"}{$_} .
				"', ifDescr '" . $_ . "'") if ($debug);

			$$ifp = ${"if_$exp"}{$_};	# set snmp interface index
			return undef;
		}
	}

	return "unknown interface: $$ifp";
}

# -------------------------------------------------------------------
# logit routine
#
sub logit
{
	my($level, $msg) = @_;
	return if ($level < $logFileLevel);

	my $now = scalar localtime;
	my $fork = ($forkPID > 0) ? "[fork $forkPID] " : ($forkPID eq 'total') ? "[total] " : "";

	&logitraw("$now: $$ $fork$msg\n");
}

sub logitraw
{
	my $msg = shift;

	if ($logFile) {
		open(LOGOUT, ">>$logFile");
		print LOGOUT map { $_ } @logBuffer;
		print LOGOUT $msg;
		close(LOGOUT);
		undef @logBuffer;
	}
	elsif (! $checkConfig) {
		push(@logBuffer, $msg);
	}

	if ((! $logFile) || (-t STDOUT)) { 	#  || ($level >= $LOG_ERROR)) {
		print $msg;
	}
	return undef;
}

# -------------------------------------------------------------------
# return the RGB color code of the parameter passed, or undef
#   
sub validColor
{
	my($c) = lc($_[0]);
	$c =~ s/grey/gray/;

	if ($c =~ /^(\#|0x|\$)([0-9a-f]+)$/) {		# #00fedc
		return uc("#" . substr("000000$2", -6));
	}
	elsif ($c = $colors{$c}) {			# valid color name
		return $c;
	}
	return undef;
}

# -------------------------------------------------------------------
# this loads a hybrid of rfc 1700, cisco IOS, and system preferences as well as some
# other base variables

sub baseVariables
{
	my $sfile = "/etc/services";

	# load base services from /etc/services
	if (-f $sfile) {
		open(IN, $sfile);
		while ( <IN> ) {
			s/#.*$//;		# get rid of comments
			s/\s*$//;		# get rid of trailing spaces
			s/^\s*//;		# get rid of leading spaces

			if (/^(\S+)\s+(\d+)\/(tcp|udp)$/) {
				if ($3 eq "tcp") { $cisco_tcp_services{$1} = $2; }
				else		{ $cisco_udp_services{$1} = $2; }
			}
		}
	}

	%cisco_permit = (
		'deny' => 0,
		'permit' => 1
	);

	%cisco_range = (
		'eq' => 1,
		'neq' => 2,
		'gt' => 3,
		'lt' => 4,
		'range' => 5,
		'ge' => 6,
		'le' => 7
	);

	%cisco_ipaddr = (
		'any' => 1,
		'host' => 2
	);

	%cisco_protocols = (
		'ip' => 0,	# Any protocol
		'icmp' => 1,	# Internet Control Message
		'igmp' => 2,	# Internet Group Management
		'tcp' => 6,	# Transmission Control
		'udp' => 17,	# User Datagram
		'gre' => 47,	# Generic Route Encapsulation
		'esp' => 50,	# Encapsulation Security Payload
		'ah' => 51,	# Authentication Header
		'ipinip' => 4,	# IP-in-IP
		'eigrp' => 88,	# IGRP
		'ospf' => 89,	# OSPF
	);

	%cisco_tcp_services = (
		'bgp' => 179,		# Border Gateway Protocol (179)
		'chargen' => 19,	# Character generator (19)
		'cmd' => 514,		# Remote commands (rcmd, 514)
		'rcmd' => 514,		# Remote commands (rcmd, 514)
		'daytime' => 13,	# Daytime (13)
		'discard' => 9,		# Discard (9)
		'domain' => 53,		# Domain Name Service (53)
		'echo' => 7,		# Echo (7)
		'exec' => 512,		# Exec (rsh, 512)
		'rsh' => 512,		# Exec (rsh, 512)
		'finger' => 79,		# Finger (79)
		'ftp' => 21,		# File Transfer Protocol (21)
		'ftp-data' => 20,	# FTP data connections (used infrequently, 20)
		'gopher' => 70,		# Gopher (70)
		'hostname' => 101,	# NIC hostname server (101)
		'ident' => 113,		# Ident Protocol (113)
		'irc' => 194,		# Internet Relay Chat (194)
		'klogin' => 543,	# Kerberos login (543)
		'kshell' => 544,	# Kerberos shell (544)
		'login' => 513,		# Login (rlogin, 513)
		'lpd' => 515,		# Printer service (515)
		'nntp' => 119,		# Network News Transport Protocol (119)
		'pim-auto-rp' => 496,	# PIM Auto-RP (496)
		'pop2' => 109,		# Post Office Protocol v2 (109)
		'pop3' => 110,		# Post Office Protocol v3 (110)
		'smtp' => 25,		# Simple Mail Transport Protocol (25)
		'sunrpc' => 111,	# Sun Remote Procedure Call (111)
		'syslog' => 514,	# Syslog (514)
		'tacacs' => 49,		# TAC Access Control System (49)
		'talk' => 517,		# Talk (517)
		'telnet' => 23,		# Telnet (23)
		'time' => 37,		# Time (37)
		'uucp' => 540,		# Unix-to-Unix Copy Program (540)
		'whois' => 43,		# Nicname (43)
		'www' => 80		# World Wide Web (HTTP, 80)
	);

	%cisco_udp_services = (
		'biff' => 512,		# Biff (mail notification, comsat, 512)
		'bootpc' => 68,		# Bootstrap Protocol (BOOTP) client (68)
		'bootps' => 67,		# Bootstrap Protocol (BOOTP) server (67)
		'discard' => 9,		# Discard (9)
		'dnsix' => 195,		# DNSIX security protocol auditing (195)
		'domain' => 53,		# Domain Name Service (DNS, 53)
		'echo' => 7,		# Echo (7)
		'isakmp' => 500,	# Internet Security Association and Key Management Protocol (500)
		'mobile-ip' => 434,	# Mobile IP registration (434)
		'nameserver' => 42,	# IEN116 name service (obsolete, 42)
		'netbios-dgm' => 138,	# NetBios datagram service (138)
		'netbios-ns' => 137,	# NetBios name service (137)
		'netbios-ss' => 139,	# NetBios session service (139)
		'ntp' => 123,		# Network Time Protocol (123)
		'pim-auto-rp' => 496,	# PIM Auto-RP (496)
		'rip' => 520,		# Routing Information Protocol (router, in.routed, 520)
		'snmp' => 161,		# Simple Network Management Protocol (161)
		'snmptrap' => 162,	# SNMP Traps (162)
		'sunrpc' => 111,	# Sun Remote Procedure Call (111)
		'syslog' => 514,	# System Logger (514)
		'tacacs' => 49,		# TAC Access Control System (49)
		'talk' => 517,		# Talk (517)
		'tftp' => 69,		# Trivial File Transfer Protocol (69)
		'time' => 37,		# Time (37)
		'who' => 513,		# Who service (rwho, 513)
		'xdmcp' => 177		# X Display Manager Control Protocol (177)
	);

	%cisco_optionals = (
		'precedence' => 1,
		'tos' => 2,
		'bytes' => 3,
		'packets' => 4,
		'seconds' => 5,
		'reverse' => 6,
		'next-hop' => 7,
		'exporter' => 8,
		'bps' => 9,
		'pps' => 10,
		'packetsize' => 11,
		'dscp' => 12,
		'flow' => 13,
		'ecn' => 14,
		'kbps' => 15,
		'mbps' => 16,
		'gbps' => 17,
	);

	%cisco_icmp = (
		'administratively-prohibited' => 0x030d,
		'alternate-address' => 0x0600,
		'conversion-error' => 0x1f00,
		'dod-host-prohibited' => 0x030a,
		'dod-net-prohibited' => 0x0309,
		'echo' => 0x0800,
		'echo-reply' => 0xff00,				# special hack
		'general-parameter-problem' => 0x0c00,
		'host-isolated' => 0x0308,
		'host-precedence-unreachable' => 0x030e,
		'host-redirect' => 0x0501,
		'host-tos-redirect' => 0x0503,
		'host-tos-unreachable' => 0x030c,
		'host-unknown' => 0x0307,
		'host-unreachable' => 0x0301,
		'information-reply' => 0x1000,
		'information-request' => 0x0f00,
		'mask-reply' => 0x1200,
		'mask-request' => 0x1100,
		'mobile-redirect' => 0x2000,
		'net-redirect' => 0x0500,
		'net-tos-redirect' => 0x0502,
		'net-tos-unreachable' => 0x030b,
		'net-unreachable' => 0x0300,
		'network-unknown' => 0x0306,
		'no-room-for-option' => 0x0c02,
		'option-missing' => 0x0c01,
		'packet-too-big' => 0x0304,
		'parameter-problem' => 0x0cff,
		'port-unreachable' => 0x0303,
		'precedence-unreachable' => 0x030f,
		'protocol-unreachable' => 0x0302,
		'reassembly-timeout' => 0x0b01,
		'redirect' => 0x05ff,
		'router-advertisement' => 0x0900,
		'router-solicitation' => 0x0a00,
		'source-quench' => 0x0400,
		'source-route-failed' => 0x0305,
		'time-exceeded' => 0x0bff,
		'timestamp-reply' => 0x0e00,
		'timestamp-request' => 0x0d00,
		'traceroute' => 0x1e00,
		'ttl-exceeded' => 0x0b00,
		'unreachable' => 0x03ff
	);

	%cisco_precedence = (
		'routine' => 0,
		'priority' => 1,
		'immediate' => 2,
		'flash' => 3,
		'flash-override' => 4,
		'critical' => 5,
		'internet' => 6,
		'network' => 7
	);

	%cisco_tos = (			# unused
		'normal' => 0,
		'min-monetary-cost' => 1,
		'max-reliability' => 2,
		'max-throughput' => 4,
		'min-delay' => 8
	);

	%cisco_dscp = (
		'af11' => 0b001010,
		'af12' => 0b001100,
		'af13' => 0b001110,
		'af21' => 0b010010,
		'af22' => 0b010100,
		'af23' => 0b010110, 
		'af31' => 0b011010, 
		'af32' => 0b011100, 
		'af33' => 0b011110, 
		'af41' => 0b100010, 
		'af42' => 0b100100, 
		'af43' => 0b100110, 
		'cs1' =>  0b001000, 
		'cs2' =>  0b010000, 
		'cs3' =>  0b011000, 
		'cs4' =>  0b100000, 
		'cs5' =>  0b101000, 
		'cs6' =>  0b110000, 
		'cs7' =>  0b111000, 
		'ef' =>   0b101110,
		'default' => 0b000000
	);

	%cisco_ecn = (
		'not-ect' => 0b00,
		'ect1' =>    0b01,
		'ect0' =>    0b10,
		'ect' =>     0b111,  # signal to remap later
		'ce' =>      0b11,
	);

	%cisco_tcp_flags = (
		'fin' => 1,
		'syn' => 2,
		'rst' => 4,
		'psh' => 8,
		'ack' => 16,
		'urg' => 32,

		'not' => -256,
		'!' => -256,

		'!fin' => -1,
		'!syn' => -2,
		'!rst' => -4,
		'!psh' => -8,
		'!ack' => -16,
		'!urg' => -32,
	);

	%dynamic_keywords = (
		'source-ip' => 1,
		'destination-ip' => 2,
		'flow' => 3,
		'flow-reverse' => 4,
		'timeout' => 5,
	);

	%facl_expansion = (	# convert syntax into Cflow format
		'$tos'		=> '$tos',
		'$precedence'	=> '($tos >> 5)',
		'$dscp'		=> '($tos >> 2)',
		'$ecn'		=> '($tos & 3)',
		'$seconds'	=> '($endtime - $startime)',
		'$srcif'	=> '$input_if',
		'$dstif'	=> '$output_if',
		'$srcas'	=> '$src_as',
		'$dstas'	=> '$dst_as',
		'$srcip'	=> '$srcaddr',
		'$dstip'	=> '$dstaddr',
		'$srcport'	=> '$srcport',
		'$dstport'	=> '$dstport',
		'$exporterip'	=> '$exporter',
		'$nexthopip'	=> '$nexthop',
	);

	%string_protocol = ( map { $_ => $_ } qw/
		$protocol
	/);

	%string_port = ( map { $_ => $_ } qw/
		$srcport $dstport
	/);

	%string_ip = ( map { $_ => $_ } qw/
		$srcip $dstip
 		$exporterip $nexthopip
	/);

	%string_tos = ( map { $_ => $_ } qw/
		$tos $precedence $dscp $ecn
	/);

	%string_as = ( map { $_ => $_ } qw/
		$srcas $dstas
	/);

	%string_if = ( map { $_ => $_ } qw/
		$srcif $dstif
	/);

	%colors = (
		"aliceblue" => "#F0F8FF",
		"antiquewhite" => "#FAEBD7",
		"aqua" => "#00FFFF",
		"aquamarine" => "#7FFFD4",
		"azure" => "#F0FFFF",
		"beige" => "#F5F5DC",
		"bisque" => "#FFE4C4",
		"black" => "#000000",
		"blanchedalmond" => "#FFEBCD",
		"blue" => "#0000FF",
		"blueviolet" => "#8A2BE2",
		"brown" => "#A52A2A",
		"burlywood" => "#DEB887",
		"cadetblue" => "#5F9EA0",
		"chartreuse" => "#7FFF00",
		"chocolate" => "#D2691E",
		"coral" => "#FF7F50",
		"cornflowerblue" => "#6495ED",
		"cornsilk" => "#FFF8DC",
		"crimson" => "#DC143C",
		"cyan" => "#00FFFF",
		"darkblue" => "#00008B",
		"darkcyan" => "#008B8B",
		"darkgoldenrod" => "#B8860B",
		"darkgray" => "#A9A9A9",
		"darkgreen" => "#006400",
		"darkkhaki" => "#BDB76B",
		"darkmagenta" => "#8B008B",
		"darkolivegreen" => "#556B2F",
		"darkorange" => "#FF8C00",
		"darkorchid" => "#9932CC",
		"darkred" => "#8B0000",
		"darksalmon" => "#E9967A",
		"darkseagreen" => "#8FBC8F",
		"darkslateblue" => "#483D8B",
		"darkslategray" => "#2F4F4F",
		"darkturquoise" => "#00CED1",
		"darkviolet" => "#9400D3",
		"deeppink" => "#FF1493",
		"deepskyblue" => "#00BFFF",
		"dimgray" => "#696969",
		"dodgerblue" => "#1E90FF",
		"firebrick" => "#B22222",
		"floralwhite" => "#FFFAF0",
		"forestgreen" => "#228B22",
		"fuchsia" => "#FF00FF",
		"gainsboro" => "#DCDCDC",
		"ghostwhite" => "#F8F8FF",
		"gold" => "#FFD700",
		"goldenrod" => "#DAA520",
		"gray" => "#808080",
		"green" => "#008000",
		"greenyellow" => "#ADFF2F",
		"honeydew" => "#F0FFF0",
		"hotpink" => "#FF69B4",
		"indianred" => "#CD5C5C",
		"indigo" => "#4B0082",
		"ivory" => "#FFFFF0",
		"khaki" => "#F0E68C",
		"lavender" => "#E6E6FA",
		"lavenderblush" => "#FFF0F5",
		"lawngreen" => "#7CFC00",
		"lemonchiffon" => "#FFFACD",
		"lightblue" => "#ADD8E6",
		"lightcoral" => "#F08080",
		"lightcyan" => "#E0FFFF",
		"lightgoldenrod" => "#EEDD82",
		"lightgoldenrodyellow" => "#FAFAD2",
		"lightgreen" => "#90EE90",
		"lightgrey" => "#D3D3D3",
		"lightpink" => "#FFB6C1",
		"lightsalmon" => "#FFA07A",
		"lightseagreen" => "#20B2AA",
		"lightskyblue" => "#87CEFA",
		"lightslateblue" => "#8470FF",
		"lightslategray" => "#778899",
		"lightsteelblue" => "#B0C4DE",
		"lightyellow" => "#FFFFE0",
		"limegreen" => "#32CD32",
		"linen" => "#FAF0E6",
		"magenta" => "#FF00FF",
		"maroon" => "#800000",
		"mediumaquamarine" => "#66CDAA",
		"mediumblue" => "#0000CD",
		"mediumorchid" => "#BA55D3",
		"mediumpurple" => "#9370DB",
		"mediumseagreen" => "#3CB371",
		"mediumslateblue" => "#7B68EE",
		"mediumspringgreen" => "#00FA9A",
		"mediumturquoise" => "#48D1CC",
		"mediumvioletred" => "#C71585",
		"midnightblue" => "#191970",
		"mintcream" => "#F5FFFA",
		"mistyrose" => "#FFE4E1",
		"moccasin" => "#FFE4B5",
		"navajowhite" => "#FFDEAD",
		"navy" => "#000080",
		"oldlace" => "#FDF5E6",
		"olive" => "#808000",
		"olivedrab" => "#6B8E23",
		"orange" => "#FFA500",
		"orangered" => "#FF4500",
		"orchid" => "#DA70D6",
		"palegoldenrod" => "#EEE8AA",
		"palegreen" => "#98FB98",
		"paleturquoise" => "#AFEEEE",
		"palevioletred" => "#DB7093",
		"papayawhip" => "#FFEFD5",
		"peachpuff" => "#FFDAB9",
		"peru" => "#CD853F",
		"pink" => "#FFC0CB",
		"plum" => "#DDA0DD",
		"powderblue" => "#B0E0E6",
		"purple" => "#800080",
		"red" => "#FF0000",
		"rosybrown" => "#BC8F8F",
		"royalblue" => "#4169E1",
		"saddlebrown" => "#8B4513",
		"salmon" => "#FA8072",
		"sandybrown" => "#F4A460",
		"seagreen" => "#2E8B57",
		"seashell" => "#FFF5EE",
		"sienna" => "#A0522D",
		"silver" => "#C0C0C0",
		"skyblue" => "#87CEEB",
		"slateblue" => "#6A5ACD",
		"slategray" => "#708090",
		"snow" => "#FFFAFA",
		"springgreen" => "#00FF7F",
		"steelblue" => "#4682B4",
		"tan" => "#D2B48C",
		"teal" => "#008080",
		"thistle" => "#D8BFD8",
		"tomato" => "#FF6347",
		"turquoise" => "#40E0D0",
		"violet" => "#EE82EE",
		"violetred" => "#D02090",
		"wheat" => "#F5DEB3",
		"white" => "#FFFFFF",
		"whitesmoke" => "#F5F5F5",
		"yellow" => "#FFFF00",
		"yellowgreen" => "#9ACD32"
	);

	# create inverted hashes for services and protocols
	map { $cisco_ipprotocols{ $cisco_protocols{$_} } = $_ } keys %cisco_protocols;
}

sub bench
{
	($realtime2, undef) = POSIX::times();
	my $realtime = $realtime2 - $realtime1;
	$realtime1 = $realtime2 if (! $_[0]);

	return (($realtime) ? ($realtime / $clock_ticks) : 0)
}

sub ghba
{
	my(@octets) = split(/\./, $_[0]);

	return undef if (@octets != 4);
	return gethostbyaddr(pack( 'C4', @octets), 2);
}


# -------------------------------------------------------------------
# maintain the DNS file -- uses globals $dnsFile and %dnsTable
#
sub dnsResolver
{
	my(%dns, @ips);

	#### read the DNS file and expire entries
	open(IN, $dnsFile);
	while ( <IN> ) {
		if (/^(\S+)\s+([\d\.]+)\s+\#\s+(\d+)$/) {	# 'host ip # expiration'
			$dns{$2}->{hostname} = $1;
			$dns{$2}->{timeout} = $3;
		}
	}
	close(IN);

	#### see what needs to be done
	foreach (keys %dnsTable) {
		next if (! /^(\d+)-(\d+)-(\d+)-(\d+)$/);
		my $ip = "$1.$2.$3.$4";
		push(@ips, $ip) if ((! defined $dns{$ip}) || ($dns{$ip}->{timeout} < time));
	}
	undef %dnsTable;

	#### perform a bulk lookup
	&bulkdns(\%dns, @ips) if (@ips);

	#### write the DNS file
	open(OUT, ">$dnsFile");
	foreach (keys %dns) {
		print OUT $dns{$_}->{hostname} . "\t" . $_ . "\t# " . $dns{$_}->{timeout} . "\n";
	}
	close(OUT);

	&logit($LOG_TRIVIA, "Wrote " . (scalar keys %dns) . " entries to $dnsFile");
}

# -------------------------------------------------------------------
# perform a bulk DNS lookup -- uses globals $dnsTimeout, $dnsPacing, @dnsServers
sub bulkdns
{
	use Net::DNS;

	my($iphash, @ips) = @_;
	my($count_query) = 0;
	my($count_answer) = 0;

	my $res = Net::DNS::Resolver->new;
	my $sel = IO::Select->new;
	my $endTime = time + $dnsTimeout + 1;

	$res->nameservers(@dnsServers) if (@dnsServers);

	while (1) {
		if ((time < $endTime) && ($sel->count() <= $dnsMaxHandles) && ($_ = shift @ips)) {
			my $sock = $res->bgsend($_);
			$sel->add($sock) if ($sock);
			next if ($count_query++ % $dnsPacing);
		}

		if ( my @ready = $sel->can_read(0) ) {
			foreach my $sock (@ready) {
				$sel->remove($sock);
				if (my $ans = $res->bgread($sock)) {
					$count_answer++;
					foreach my $rr ($ans->answer) {
						# 215.12.184.136.in-addr.arpa.    86400   IN      PTR     lmig-nds-ne-01.lmig.com.
						if ($rr->string !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\S+\s+(\d+)\s+IN\s+PTR\s+(\S+)\.$/) {
							&logit($LOG_DEBUG, "Bad RR: " . $rr->string);
							next;
						}
						my $ip = "$4.$3.$2.$1";
						${$iphash}{$ip}->{timeout} = time + $5;
						${$iphash}{$ip}->{hostname} = $6;
					}
				}
			}
		}

		last if ( ((! @ips) && ($sel->count == 0)) || (time > $endTime) );
	}

	foreach my $sock ($sel->handles) {
		$sel->remove($sock);
	}

	&logit($LOG_DEBUG, "DNS resolver got $count_answer of $count_query queries");
	return $count_answer;
}

# ------------------
# RRDCACHED socket routines

sub rrdCachedOpen
{
	my $rrdcached = shift;
	my $err;

	if ($rrdcached =~ /^(unix\:|)(.*)/) {		# local UNIX SOCKET
		my $remote = $2;
		if (! -S $remote) {
			$err = "socket $remote does not exist.";
		}       
		elsif (! socket(RRDCACHED, PF_UNIX, SOCK_STREAM, 0) ) {
			$err = "could not create RRDCACHED socket";
		}
		elsif (! connect(RRDCACHED, sockaddr_un($remote)) ) {
			$err = "could not connect to UNIX SOCKET $remote";
		}
	}
	else {						# INET SOCKET
		my $proto = getprotobyname("tcp");
		my $port = getservbyname("rrdcached", "tcp") || 42217;
		my $remote = $rrdcached;
		if ($remote =~ /^(.*)\:(\d+)$/) { $remote = $1; $port = $2; }
		my $iaddr = inet_aton($remote);

		if (! $iaddr) {
			$err = "could not resolve IP address for '$remote'";
		}
		elsif ((! $proto) || (! $port)) {
			$err = "could not resolve protocol 'tcp' or port number 'rrdcached'";
		}
		elsif (! socket(RRDCACHED, PF_INET, SOCK_STREAM, $proto)) {
			$err = "could not create RRDCACHED socket";
		}
		elsif (! connect(RRDCACHED, sockaddr_in($port, $iaddr)) ) {
			$err = "could not connect to INET SOCKET $rrdcached";
		}
	}

	if (! $err) {
		$rrdCachedSocketOpen = 1;
		my $oldh = select( RRDCACHED ); $| = 1; select( $oldh );
		my $ok = 0;

		print RRDCACHED "STATS\n";
		if (&rrdCachedGet =~ /(\d+) Statistics follow/) {
			$ok = 1;
			for (1 .. $1) {
				my $x = &rrdCachedGet;
				if (! defined $x) { undef $ok; last; }
			}
		};

		if (! $ok) {
			$err = "connected, but did not receive expected results to STATS command";
		}
	}

	if ($err) {
		&logit($LOG_ERROR, "RRDCACHED: Error- $err");
		&rrdCachedClose;
		return undef;
	}

	return 1;		# good!
}

sub rrdCachedClose
{
	print RRDCACHED "QUIT\n" if ($rrdCachedSocketOpen);
	close(RRDCACHED);
	$rrdCachedSocketOpen = 0;
}

sub rrdCachedPut
{
PUTITEM: foreach (@_) {
		my $buf = $_ . "\n";
		&logit($LOG_DEBUG, "RRDCACHED: write " . length($buf) .  ": " . &hexit($buf));

		for (0 .. 1) {
			next PUTITEM if (print RRDCACHED $buf);

			&logit($LOG_INFO, "RRDCACHED: socket ($rrdcached) is down. Attempting to reconnect.");
			close(RRDCACHED);
			$rrdCachedSocketOpen = 0;

			if (! &rrdCachedOpen($rrdcached) ) {
				&logit($LOG_ERROR, "RRDCACHED: Error- socket ($rrdcached) is down and could not be reconnected to. Flowage will quit and hopefully the next run will work.");
				undef $rrdcached;
				return 0;
			}
			else {
				&logit($LOG_INFO, "RRDCACHED: Reconnected successfully.");
				next;
			}
		}

		&logit($LOG_INFO, "RRDCACHED: Error- having difficulty staying connected. Flowage will quit and hopefully the next run will work.");
		close(RRDCACHED);
		$rrdCachedSocketOpen = 0;
		undef $rrdcached;
		return 0;
	}
	return 1;
}

sub rrdCachedGet
{
	my $buf;
	return undef if (! $rrdCachedSocketOpen);

	if (! defined eval {
		local $SIG{ALRM} = sub { die; };
		alarm 1;
		$buf = <RRDCACHED>;
		&logit($LOG_DEBUG, "RRDCACHED: read " . length($buf) . ": " . &hexit($buf));
		chomp($buf);
	}) {
		return undef;
	}

	alarm 0;
	return $buf;
}

sub hexit
{
	my $buf = shift;
	$buf =~ s/([\x00-\x1f\x80-\xff])/sprintf("\\x%02x", ord($1))/ge;
	return $buf;
}

