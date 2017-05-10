#!/usr/bin/perl
# ------------------------------------------------
# render.cgi
# Craig Weinhold, CDW
#
#  v1.0   01-09-02  initial version
#  v1.01  01-14-02  added trimming of empty datapoints and graphs.
#  v1.02  01-15-02  added viewing of csv files
#  v1.03  02-13-02  added graphing style (stacked, lines, layers) and fixed a few bugs
#  v1.04  05-01-02  added support for 'Any' files for faster graphing of combined data
#  v1.05  05-09-02  added support for matrices
#  v1.10  05-10-02  matrices and groups seem to cooperate pretty well.
#  v1.11  05-16-02  added graphDir directory
#  v1.20  09-14-02  added aliases (for interfaces, and maybe other things in the future)
#  v1.21  10-09-02  fixed bug in peak detection
#  v1.22  11-03-02  added generic matrix select routine with descriptions/aliasing
#  v1.23  11-16-02  added palettes, time pull-down, better calcaliases, and better menu choices
#  v1.24  11-27-02  fixed consistent palettes
#  v1.25  11-29-02  added authorization config
#  v1.26  12-07-02  added datapoint table display
#  v1.27  12-09-02  added bandwidth line (what a mess!)
#  v1.28  02-02-03  ordered the list of files according to the index file
#  v1.29  02-06-03  fixed commafication issue in sjoin
#  v1.30  04-23-03  added support for hierarchical directories
#  v1.31  05-11-03  added manual label justification, Bits/IPs calculation
#  v1.32  06-25-03  added clickable map support
#  v1.33  08-06-03  fixed minor bug with apostrophes in descriptions
#  v1.34  10-03-03  fixed bug with aggregate tables
#  v1.35  10-29-03  fixed some cosmetic problems
#  v1.36  11-25-03  added graph month display tweak
#  v1.37  01-19-04  fixed bug with labels containing colons
#  v1.37a 04-07-05  fixed bug in menuing system ("SPLIT UP REALLY LARGE CATEGORIES")
#  v1.38  10-11-06  incorporated MAX/AVERAGE consolidations and detail reports
#  v1.39  05-12-07  added rrd 1.2 support (see attached patch)
#  v1.40  10-05-07  fixed use of $_ in foreach's that caused problems with some perl builds
#  v1.41  11-10-07  improved niceUnits and table display
#  v1.42  06-24-08  added rrd 1.3 'textalign' support and packed support
#  v1.43  08-29-08  fixed incompatibility with perl5.10
#  v1.44  10-02-09  clarified web form error messages
#  v1.45  07-27-11  perl5.10 bug fix
#  v1.46  08-30-11  matrix interfaces select the first WAN type by default (serial, multilink, etc)
#  v1.47  09-07-11  fixed bugs with speed calculation, and colon escapes with RRD >1.2
#  v1.48  02-07-12  added simple csv output of tables, cleaned up interface, added $f1/$f2 variables to calcAliases
#
# Renders flowage rrd and csv files based on an index file created by flowage.pl.
# Allows for variable selection, display characteristics, date range, etc.
# ------------------------------------------------

# use strict;  # fat chance
use RRDs;
use CGI qw(:standard :html3 -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use Time::Local;
use POSIX;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }


my $noRRDpatch = 0;					# set to 1 if running rrdtool 1.2.x and you have not applied the "noglue" patch.

my($IMAGEFORMAT) = "png";			       # png or gif format
my($IMAGESUFFIX) = "png";
my($INFOSUFFIX) = "info";

my($paletteConsistent) = "Consistent";			# keyword for consistent colors
my($paletteDefault) = "Default";			# keyword for default colors
my($showDebug) = 1;					# whether or not to show debug options
my($clickable) = 1;					# support clickable graphs or not
my($clickURL) = "adhocClick.cgi";

my $skipImage = "SKIP";
my (%skip, %skipReason);

&loadPalettes;

my $debug = 0;

$noRRDpatch = 1 if ($RRDs::VERSION >= 1.3);		# override

# --------------------------------- START OF TEST CODE ---------------------------------

if ($test) {
	&readIndex;
	$debug = 1; 
	$file = 'Interface-Services';
	@vars = &dissect($fileList{$file});			# "Interfaces" and "Services"

	foreach my $v (@vars) {					# Load the "Interfaces" variable
		push(@{$v}, &loadMatrixVals($file, $v)) if ($matrixVar{$v});
	}

	&matrixVarMenu("Interfaces");				# Generate a menu for "Interfaces"

	exit 0;
}

# --------------------------------- END OF TEST CODE ---------------------------------

my(@rrds, %build);

$| = 1;

our $quiet = param('quiet');				# print other stuff
our $simpleOutput = (param('output') eq 'csv');		# format tables for machines

print header();

print <<EOT;
<html>
<head><title>Webview Netflow Reporter</title>
</head>
<body>
EOT
print "<h2>Webview Netflow Reporter</h2>" if (! $quiet);

if (($debug) && (0)) {
	foreach (param()) {
		print "$_ = " . param($_) . "<br>\n";
	}
	foreach (keys %ENV) {
		print "$_ = $ENV{$_}<br>\n";
	}
}

&readIndex;
&houseKeeping($graphDir);

$errorText = "<font size=4 color=red>";
$noErrorText = "</font>";
$debug = 1 if (param('go') =~ /debug/i);

# &queryGraph;

if (param('go') =~ /graph & table/i) {		# generate graphs and tables for 'em
	$GLOBAL_GRAPH = 1;
	$GLOBAL_TABLE = 1;
	&graphIt;
}
elsif (param('go') =~ /detail/i) {	      # generate detailed table for 'em
	$GLOBAL_DETAIL = 1;
	&graphIt;
}
elsif (param('go') =~ /graph/i) {		# generate graphs only for 'em
	$GLOBAL_GRAPH = 1;
	&graphIt;
}
elsif (param('go') =~ /table/i) {		# generate tables only for 'em
	$GLOBAL_TABLE = 1;
	&graphIt;
}
elsif (param('go') =~ /flow/i) {		# view ascii flow data
	&flowIt;
}
elsif (param('go') =~ /link/i) {		# manipulate links
	&linkIt;
}
elsif ((param('go') =~ /select/i) || (param('select'))) { # generate a graph query
	$_ = param("file");
	if ($fileList{$_} =~ /\.rrd$/)	{ &queryGraph; }
	else				{ &queryFlow; }
}
else {						# generate a file query
	&queryFile;
}

print <<EOT;
</body>
</html>
EOT

exit 0;

sub linkIt
{
	my (%aliases, %descriptions);
	my $var = 'Interfaces';
	my $file = 'Summary';

	push(@{$var}, &loadMatrixVals($file, $var)) if ($matrixVar{$var});

	&calcDescriptions($var, \%descriptions);
	&calcAliases($var, \%descriptions, \%aliases);

	my $base = param('base');
	my $aliases = param('aliases');

	if ($base && $aliases) {
		my @aliases = map { s/[,;]//g } split(/\s+/, $aliases);
		$base = s/s$var=[^;]+;//g;
		$base .= map { exists $aliases{$_} ? "s$var=" . $aliases{$_} . ";" : "" } @aliases;

		print "Full link: $base" . p . "\n";
	}

        print 'Base link:', textfield(-name=>'base', -maxlength=>80), p
		"Enter one or more aliases below:", p,
		textarea(-name=>'aliases', -rows=>8, -cols=>40), p,
		submit(-name=>'go', -value=>'Create quick link'), hr
		font({-size=>'-1'},
			u('Available aliases:'), br,
			map { $_ . br . "\n" } sort { &paddedCmp($aliases{$a}, $aliases{$b}) }  keys %aliases
		);
}

# --------------------------------------------------------------------------------
# generate a query screen where we ask the person what they want to do

sub queryFile
{
	my(@files) = @fileOrdered;
	my(@rrd_files, @text_files);

	if (@files == 0) {
		print "<h3>No Flowage data sets are available to work on.<h3>\n";
		return;
	}
	elsif (@files == 1) {
		$_ = pop @files;
		param(-name=>'file', -value=>$_);
		if ($fileList{$_} =~ /\.rrd$/)	{ &queryGraph; }
		else				{ &queryFlow; }
		return;
	}

	foreach (@files) {
		if ($fileList{$_} =~ /\.rrd$/)	{ push(@rrd_files, $_); }
		else				{ push(@text_files, $_); }
	}

	print start_form,
		"<table border=0>",
		"<tr><td colspan=3>";
#		"<b><font size=+1>Select a set of files to work with:</font></b>";

	if (@rrd_files > 0) {
		print "<tr><td><td colspan=2><b>View historical flow graphs</b>\n",
			"<tr><td><td><td>",
			radio_group(-name=>'file',
				-values=>[@rrd_files],
				-linebreak=>true,
				-labels=>\%fileDesc),
			"\n";
	}

	if (@text_files > 0) {
		print "<tr><td><td colspan=2><b>View historical flow data</b>\n",
			"<tr><td><td><td>",
			radio_group(-name=>'file',
				-values=>[@text_files],
				-linebreak=>true,
				-labels=>\%fileDesc,
				-default=>'-'),
			"\n";
	}

	print "</table>",
		submit(-name=>'go', -value=>'Select'),
		end_form,
		"\n";

        print <<EOT;		# use for MOTD
EOT
}

sub queryTable
{
	print "not implemented", br;
}

sub tableIt
{
	print "not implemented", br;
}

# --------------------------------------------------------------------------------
# given a file name template, this extracts all the variables within it

sub dissect
{
	my($dissect) = $_[0];
	my(@vars, $s1);

	while ($dissect =~ s/\[(packed=|)(\%?)([^]]+)\]/$1/) {
		push(@vars, $3);
		$someMatrixVar = $matrixVar{$3} = 1 if ($2 eq "%");
	}

	return @vars;
}

# --------------------------------------------------------------------------------
# generate a query screen where we ask the person what they want to do

sub queryFlow
{
	my($file) = param('file');
	my(@vars) = &dissect($fileList{$file});
	my($indent) = " &nbsp; &nbsp; ";
	my($matrixDescrBox) = 0;			# display matrix description box?

	my($bg) = "gray";
	my($fg) = "#d0d0d0";

	my(%viewLabels) = (
		"0" => "all data",
		"1000" => "newest 1,000 lines",
		"5000" => "newest 5,000 lines",
		"10000" => "newest 10,000 lines",
		"-1000" => "oldest 1,000 lines",
		"-5000" => "oldest 5,000 lines",
		"-10000" => "oldest 10,000 lines"
	);

	my(%fontLabels) = (
		"1" => "microscopic",
		"2" => "small",
		"3" => "normal"
	);

	&textFlowVars;					# load column info into global variables
	foreach my $v (@vars) {
		push(@{$v}, &loadMatrixVals($file, $v)) if ($matrixVar{$v});
	}

	print start_form,
		hidden(-name=>"file", -value=>$file)
		;

	print "<table border=1 bgcolor=$fg>",
		"<td colspan=3 bgcolor=$bg><b>Variable Selection</b>";

	foreach (@vars) {
		print "<tr><td align=right bgcolor=$bg><b>$_</b>: ",
			"<td>";

		if ($matrixVar{$_}) {			# matrix variable
			&matrixVarMenu($_);
			$matrixDescrBox = 1;
		}
		else {
			# display listbox with all subordinate variables (e.g., ftp, icmp, telnet)
			print popup_menu(-name=>"s$_",
				-values=>[@$_]),
				"\n";
		}
	}

	print "<tr><tr><td colspan=3 bgcolor=$bg><b>Display</b>\n";

	print "<tr><td align=right bgcolor=$bg><b>View</b>:",
		"<td>";

	print popup_menu(-name=>'lines',
		-values=>[sort {$a <=> $b} keys %viewLabels],
		-labels=>\%viewLabels,
		-default=>"1000");			# newest 1000 lines

	print "<tr><td align=right bgcolor=$bg><b>Font Size</b>:",
		"<td>",
		popup_menu(-name=>'font',
			-values=>[sort {$b <=> $a} keys %fontLabels],
			-default=>"3",
			-labels=>\%fontLabels);

	print "<tr><td valign=top align=right bgcolor=$bg><b>Fields to Display</b>:",
		"<td>",
		&checkboxTable(
			3, 4, 4,
			checkbox_group(-name=>'fields',
				-values=>[@fields],
				-default=>[@dispFields],
				-labels=>\%colHeading
			)
		);

	if ($matrixDescrBox) {
		print "<tr><td align=right bgcolor=$bg>&nbsp;" .
			"<td colspan=" . $colspan . " align=center bgcolor=gray>",
			textfield(-name=>"aliasdescr",
				-size=>50);
	}

	print "<tr><td colspan=3 align=center bgcolor=$bg>", 
		submit(-name=>'go', -value=>'View Flows');

	print " &nbsp; &nbsp; ", 
		submit(-name=>'go', -value=>'Debug Flows') if ($showDebug);

	print "</table>",
		end_form;
}

# --------------------------------------------------------------------------------
# given a continuous checkbox string, returns a table. The number of items in each row is
# determined by the values passed.
sub checkboxTable
{
	my($col, @colsPerRow);
	my($c) = "<table><tr>";

	while ($_[0] !~ /checkbox/i) {
		push(@colsPerRow, shift @_);
	}

	while ($_ = shift @_) {
		$col = shift @colsPerRow || 99 if (! $col);
		$c .= "<td>$_</td>";
		$c .= "<tr>" if (--$col == 0);
	}
	$c .= "</table>";
	return $c;
}

# --------------------------------------------------------------------------------
# define global arrays and hashes for display of text flows
#  @fields, @dispFields, %colWidth, %colheading, %colSort

sub textFlowVars
{
	@fields = (				# order of fields in file
		"time", "exporter", "nexthop",
		"srcif", "srcas", "srcip", "srcport",
		"dstif", "dstas", "dstip", "dstport",
		"protocol", "packets", "bytes"
	);

	if (! (@dispFields = param('fields')) ) {
		@dispFields = (				# order to display on screen
			"time", "protocol", "srcif", "srcip",
			"srcport", "dstif", "dstip", "dstport",
			"nexthop", "packets", "bytes"
		);
	}

	%colWidth = (				# column widths
		"time" => 15, "exporter" => 15, "nexthop" => 15,
		"srcif" => 11, "srcas" => 5, "srcip" => 15, "srcport" => 5,
		"dstif" => 11, "dstas" => 5, "dstip" => 15, "dstport" => 5,
		"protocol" => 5, "packets" => 6, "bytes" => 9
	);

	%colHeading = (				# column headings
		"time" => "Time", "exporter" => "Exporter", "nexthop" => "Next-hop",
		"srcif" => "sInterface", "srcas" => "sAS", "srcip" => "sIP", "srcport" => "sPort",
		"dstif" => "dInterface", "dstas" => "dAS", "dstip" => "dIP", "dstport" => "dPort",
		"protocol" => "Prot", "packets" => "Pkts", "bytes" => "Bytes"
	);

	%colSort = (				# algorithm for sorting each field
		"time" => "sortInt", "exporter" => "sortIP", "nexthop" => "sortIP",
		"srcif" => "sortStr", "srcas" => "sortInt", "srcip" => "sortIP", "srcport" => "sortInt",
		"dstif" => "sortStr", "dstas" => "sortInt", "dstip" => "sortIP", "dstport" => "sortInt",
		"protocol" => "sortInt", "packets" => "sortIntR", "bytes" => "sortIntR"
	);
}

# --------------------------------------------------------------------------------
# print out the flows as ASCII columns

sub flowIt
{
	my($file) = param('file');			# set of data
	my($fontSize) = param('font') || "3";		# size of text
	my($lines) = param('lines');			# bounds of data
	my($sortby) = param('sortby');

	my($fName) = $fileList{$file};
	my(@vars) = &dissect($fName);			# subordinate variables
	my(%dispFieldsIndex);

	&textFlowVars;					# load column info into global variables
	foreach my $v (@vars) {
		push(@{$v}, &loadMatrixVals($file, $v)) if ($matrixVar{$v});
	}

	# create an index from $dispFields{field} to the column number in the file
	# note that some columns will not be displayed
	foreach (@dispFields) {
		for ($i=0; $i < @fields; $i++) {
			if ($_ eq $fields[$i]) {
				$dispFieldIndex{$_} = $i;
				last;
			}
		}
	}

	Delete('sortby');			# remove the sortby parameter
	my($myself) = self_url;			# generate a url pointing at me with all variables intact

	foreach (@vars) {
		$fName =~ s/\[\%?$_\]/&matrixExpand(param("s$_"))/e;
	}

	my($count) = 0;
	my($oldestLines) = (($lines < 0) ? abs($lines) : 100_000);
	my($newestLines) = (($lines > 0) ? $lines : 100_000);

	print "reading $fName<br>\n" if ($debug);
	open(IN, "$fName.old");
	while ( <IN> ) {
		last if (@stuff >= $oldestLines);
		shift @stuff if ($count++ > $newestLines);
		push(@stuff, $_);
	}
	close(IN);

	open(IN, $fName);
	while ( <IN> ) {
		last if (@stuff >= $oldestLines);
		shift @stuff if ($count++ > $newestLines);
		push(@stuff, $_);
	}
	close(IN);

#	print "lines $lines, oldest $oldestLines, newest $newestLines, total $count<p>\n";

	print "<a href=", url(-relative=>1), ">Back</a><p>\n";

	if ($table) {
		print "<table border=1>",
		"<tr><td colspan=3>",
		"<td colspan=4 align=center><b>Source</b>",
		"<td colspan=4 align=center><b>Destination</b>",
		"<td colspan=3>\n",
		"<tr>";

		foreach (sort {$a <=> $b} keys %fields) {
			print "<td align=center><b>",
				"<a href=$myself&sortby=" . int($_) . ">",
				$fields{$_},
				"</a></b>";
		}
	}
	else {
		print "<font size=$fontSize><pre>";
		foreach (@dispFields) {
			my $c = $colWidth{$_};
			print "<a href=\"$myself&sortby=$_\">" .
				"<u>" . sprintf("%$c.$c" . "s", $colHeading{$_}) . "</u>" .
				"</a> ";
		}
		print "\n";
	}

	# the $hack variable must be a global...
	undef $hack;

	for (my $i=0; $i < @fields; $i++) {
		if ($fields[$i] eq $sortby) {
			$hack = "^" . ("[^,]*," x $i) . "([^,]*)";		# global
			last;
		}
	}
	if (! defined $hack) {
		$hack = "^([^,]*)";				# default = by time
		$sortby = $fields[0];
	}

	eval "\@stuff = sort $colSort{$sortby} \@stuff";

	foreach (@stuff) {
		my($timestamp, @hackedFields, @hackedFields2);

		chomp;
		( $timestamp, @hackedFields ) = split(/,/);
		unshift @hackedFields, POSIX::strftime("%b %d %H:%M:%S", localtime($timestamp));

		foreach (@dispFields) {
			if (/if$/) {
				push(@hackedFields2,
					&hackInterface($hackedFields[$dispFieldIndex{$_}],
						$colWidth{$_})
				);
			}
			else {
				push(@hackedFields2, $hackedFields[$dispFieldIndex{$_}]);
			}
		}

		if ($table) {
			print "<tr>";
			foreach (@hackedFields2) { print "<td>$_"; }
		}
		else {

			foreach (@dispFields) {
				my $c = $colWidth{$_};
				printf "%$c.$c" . "s ", shift @hackedFields2;
			}
			print "\n";
		}
	}

	print "</table>\n" if ($table);
}

sub hackInterface
{
	my($if, $width) = @_;

	$if =~ s/\-.*//;
	if ($if =~ (/^([a-z]+)([\d\/\.\:]+)$/i)) {
		return substr($1, 0, $width - length($2)) . $2;
	}
	return $if;
}

sub sortInt
{
	$a1 = $1 if ($a =~ /$hack/);
	$b1 = $1 if ($b =~ /$hack/);
	return ($a1 <=> $b1);
}

sub sortIntR
{
	$a1 = $1 if ($a =~ /$hack/);
	$b1 = $1 if ($b =~ /$hack/);
	return ($b1 <=> $a1);
}

sub sortIP
{
	$a1 = $1 if ($a =~ /$hack/);
	$b1 = $1 if ($b =~ /$hack/);
	"$a1#$b1" =~ /^(\d+)\D(\d+)\D(\d+)\D(\d+)#(\d+)\D(\d+)\D(\d+)\D(\d+)$/;
	return ($1 <=> $5) || ($2 <=> $6) || ($3 <=> $7) || ($4 <=> $8);
}

sub sortStr
{
	$a1 = $1 if ($a =~ /$hack/);
	$b1 = $1 if ($b =~ /$hack/);
	return ($a1 cmp $b1);
}

# --------------------------------------------------------------------------------
# generate a query screen where we ask the person what they want to do

sub queryGraph
{
	my($file, @vars, @vals);
	my(%radiodefault);
	my(%inoutLabels) = (
		'combined' => 'combine in and out',
		'distinct' => '+out/-in',
		'in' => 'in only',
		'out' => 'out only'
	);
	my(%radioLabels) = (
		'separate' => 'separate graphs',
		'combine' => 'combine elements',
		'graph' => 'use for datapoints'
	);
	my($matrixDescrBox) = 0;			# display matrix description box?
	my($spacer) = " &nbsp; ";

	$file = param('file');

	@vars = &dissect($fileList{$file});

	select STDERR; $| = 1; select STDOUT;

	foreach my $v (@vars) {
		$radiodefault{$v} = "separate";
		push(@{$v}, &loadMatrixVals($file, $v)) if ($matrixVar{$v});

		# if the first/only value begins with an underscore then this is a matrix count file
		$matrixCount{$v} = $1 if ($$v[0] =~ /^_(.*)/);
	}
	$radiodefault{$vars[$#vars]} = "graph";

	my $bg = "gray";
	my $fg = "#d0d0d0";
	my $colspan = @vars - ( (%matrixCount) ? (scalar keys %matrixCount) : 0 );	# accomodate perl5.10 quirk; fixed by perl5.12
	my $tdwidth;		# = "width=200" unless ($colspan == 1);

	print start_form,
		"<table border=1 bgcolor=$fg>\n",
		hidden(-name=>"file", -value=>$file),
		"\n";

	if (%matrixCount) {
		print hidden(-name=>'dp', -default=>'Flows');

		print "<tr><td align=right bgcolor=$bg><b>Datapoints:</b><td colspan=$colspan align=left>",
			"All unique <b>" . join("/", values %matrixCount) . "</b> " ,
				(scalar keys %matrixCount > 1) ?  "combinations" : "values";
	}
	else {
		print "<tr><td align=right bgcolor=$bg><b>Datapoints:</b><td colspan=$colspan align=left>",
			checkbox_group(-name=>'dp',
				-values=>['Bits', 'Packets', 'Flows', 'IPs', 'Bits/IPs'],
				-default=>'Bits'),
			"\n";
	}

	print "<tr><td align=right bgcolor=$bg><b>Data trim:</b><td colspan=$colspan align=left>",
		popup_menu(-name=>'trimSource',
			-values=>['source trim',
				'utilization > 90%',
				'utilization > 80%',
				'utilization > 50%',
				'utilization > 30%',
				'utilization > 20%',
				'utilization > 10%',
				'utilization < 30%',
				'utilization < 20%',
				'utilization < 10%',
				'utilization < 5%',
			],
			-default=>'source trim'),
		$spacer,
		popup_menu(-name=>'trimItems',
			-values=>['data trim',
				'top 2%',
				'top 10%',
				'top 25%',
				'top 50%',
				'bottom 50%',
				'bottom 25%',
				'bottom 10%',
				'bottom 2%',
			],
			-default=>'data trim'),
		$spacer,
		checkbox(-name=>'trimEmpty',
			-checked=>1,
			-label=>'skip empty values'),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Order:&nbsp;</b> ",
		popup_menu(-name=>'trimOrder',
			-values=>['original', 'reverse', 'by average', 'by peak'],
			-default=>'by average'),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Consolidation:&nbsp;</b> ",
			radio_group(-name=>'cf',
			-values=>['max', 'avg'],
			-default=>'avg',
			-labels=>{ 'max' => 'Max', 'avg' => 'Average' }
		),
		"\n";

	print "<tr><td align=right bgcolor=$bg><b>Rendering:</b><td colspan=$colspan align=left>",
		radio_group(-name=>'io',
			-values=>[sort keys %inoutLabels],
			-default=>'distinct',
			-labels=>\%inoutLabels),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Palette:&nbsp;</b> ",
		popup_menu(-name=>'palette',
			-values=>\@palettes),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Tabe Format:&nbsp;</b> ",
		popup_menu(-name=>'output',
			-values=>['web', 'csv']),

		"\n";

	my %styleLabels = (
		'thin' => 'thin line',
		'thick' => 'thick line'
	);

	print "<tr><td align=right bgcolor=$bg><b>Graph:</b><td colspan=$colspan align=left>",
		radio_group(-name=>'size',
			-values=>['tiny', 'small', 'medium', 'large', 'huge'],
			-default=>'medium'),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Style:&nbsp;</b> ",
		radio_group(-name=>'style',
			-values=>['stack', 'layer', 'thin', 'thick'],
			-labels=>\%styleLabels,
			-default=>'stack'),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; DataRes:&nbsp;</b> ",
		popup_menu(-name=>'step',
			-values=>['auto', '3600', '86400'],
			-labels=>{'3600'=>'1-hour', '86400'=>'1-day'},
			-default=>'auto',
		),

		"\n";

	print "<tr><td align=right bgcolor=$bg><b>Date:</b><td colspan=$colspan align=left>",
		textfield(-name=>'date',
			-size=>12,
			-default=>undef,
			-maxsize=>12,
			-onfocus=>'if (this.value=="") this.value="' . POSIX::strftime("%m/%d/%Y", localtime()) . '"'
		),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Time:&nbsp;</b> ",
		popup_menu(-name=>'time',
			-values=>[undef, qw/12am 1am 2am 3am 4am 5am 6am 7am 8am 9am 10am 11am
				12pm 1pm 2pm 3pm 4pm 5pm 6pm 7pm 8pm 9pm 10pm 11pm/],
			-default=>undef,
			# lc(int(POSIX::strftime("%k", localtime())) . POSIX::strftime("%p", localtime()))
		),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Duration:&nbsp;</b>" .
		popup_menu(-name=>'dur',
			-values=>['1-Hour', '2-Hour', '4-Hour', '9-Hour', 'Day','5-Day', '72-Hour', '120-Hour', 'Week', '2-Week', 'Month', '7-Week', '3-Month', '6-Month', 'Year'],
			-default=>'Day'),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Iterations:&nbsp;</b>" .
		textfield(-name=>'iterations', -size=>6),

		$spacer, "<b style=\"background-color:$bg\">&nbsp; Period:&nbsp;</b> " .
		popup_menu(-name=>'period',
			-values=>['', 'Hours', 'Days', 'Weeks'],
			-default=>''),
		"\n";
			
	print "<tr><td rowspan=2 valign=top align=right bgcolor=$bg><b>Variables:</b>";

	foreach (@vars) {
		next if ($matrixCount{$_});
		print "<td $tdwidth align=center bgcolor=gray><b>$_</b>\n";
	}

	print "<tr>";
	foreach (@vars) {
		if ($matrixCount{$_}) {
			print hidden(-name=>"s$_", -default=>"_" . $matrixCount{$_}),
				hidden(-name=>"v$_", -default=>$radiodefault{$_}), 
				"\n";
			next;
		}

		# display radios for 'separate', 'combine', 'graph'
		my @graphopts = (%matrixCount) ?
				[ 'separate','combine' ] :
				[ 'separate','combine','graph' ];

		print "<td $tdwidth>",
			radio_group(-name=>"v$_",
				-values=>@graphopts,
				-default=>$radiodefault{$_},
				-labels=>\%radioLabels,
				-linebreak=>true),
			"\n";

		if ($matrixVar{$_}) {			# matrix variable
			&matrixVarMenu($_);				# slow
			$matrixDescrBox = 1;
		}
		else {
			# display listbox with all subordinate variables (e.g., ftp, icmp, telnet)
			print scrolling_list(-name=>"s$_",
				-values=>["all", @$_],
				-default=>'all',
				-size=>7,
				-multiple=>true,
#				-width=>140,
				-style=>"width: 100%")
			;
		}
	}

	if ($matrixDescrBox) {
		Delete('descr');
		print "<tr><td align=right bgcolor=$bg>&nbsp;" .
			"<td colspan=" . $colspan . " align=center bgcolor=gray>",
			textfield(-name=>'aliasdescr',
				-size=>90,
				-default=>'');
	}

	print "<tr><td colspan=" . ($colspan + 1) . " align=center bgcolor=$bg>",
		submit(-name=>'go', -value=>'Graph');

	print " &nbsp; &nbsp; ", 
		submit(-name=>'go', -value=>'Table');

	print " &nbsp; &nbsp; ", 
		submit(-name=>'go', -value=>'Graph & Table');

	print " &nbsp; &nbsp; ",
		submit(-name=>'go', -value=>'Detail');

	print " &nbsp; &nbsp; ", 
		submit(-name=>'go', -value=>'Debug Graph & Table') if ($showDebug);

	print " &nbsp; &nbsp; ", 
		button(-name=>'Home', -onClick=>"top.location=\"$rootDirURL\"");

	print "</table>",
		end_form,
		"\n";
}

sub ipmask		# return ip and subnetmask given something like '192.168.15.0/24'
{
	if ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/?(\d*)$/) {		# IP or subnet mask
		my $bits = (($5 > 0) || ($5 eq "0")) ? $5 : 32;
		my $mask = ($bits) ? (0xffffffff << (32 - $bits)) : 0;
		my $ip = (($1 << 24) | ($2 << 16) | ($3 << 8) | $4) & $mask;

		return (wantarray ? ($ip, $mask) : $ip);
	}
	return undef;
}

# --------------------------------------------------------------------------------
# given a value's precomputed ip, int, and desc values, this compares those with
# a 'check' value. If it matches, 'target' is returned.

sub calcCheck
{
	my($target, $check, $valueIp, $valueInt, @valueDesc) = @_;
	my ($checkIp, $checkMask) = &ipmask($check);

	# IP or subnet mask
	return ($target || 1) if ((defined $checkIp) && (defined $valueIp) && ($checkIp == ($valueIp & $checkMask)));

	# Integer range
	return ($target || 1) if (($check =~ /^(\d+)-(\d+)$/) && (defined $valueInt) && ($valueInt >= $1) && ($valueInt <= $2));

	# Integer value
	return ($target || 1) if (($check =~ /^(\d+)$/) && (defined $valueInt) && ($valuIint == $1));

	# Regular expression
	my ($f1, $f2) = ($1, $2) if ($valueDesc[1] =~ /^(\S+)#(.*)$/);
	my ($f3, $f4, $f5, $f6, $f7, $f8, $f9) = @valueDesc;

	foreach (@valueDesc) {
		next if (! /$check/i);

		return 1 if (! defined $target);

		eval '$target = "' . $target . '";';
		return $target;
	}

	return undef;
}

sub calcSimpleCheck
{
	my($value, $check, $descriptions) = @_;
	my $valueIp = &ipmask($value);
	my $valueInt = $value if ($value =~ /^\d+$/);
	my $valueDesc = $descriptions->{$value} || $value;
	return &calcCheck(undef, $check, $valueIp, $valueInt, $descriptions->{$value}, $value);
}

# --------------------------------------------------------------------------------
# Computes all the aliases for a given variable and returns them in a hash.
# An alias is a shortcut for one or more variables. 

sub calcAliases
{
	my($v, $descriptions, $aliases) = @_;
	my(%aliasList);

	return 0 if (! @{$Aliases{$v}});			# no Alias transforms? quit now!

	my $file = param('file');
	my $fCache = "$graphDir/$file-$v-alias.cache";
#	if ( (-f $fCache) && ((stat($fCache))[9] >= (time - 7200)) ) {
#		open(CACHE, $fCache);
#		while ( <CACHE> ) { chomp; $aliases->{$1} = $2 if (/^([^\t]+)\t(.*)/); }
#		close(CACHE);
#		return (scalar keys %$aliases);
#	}

VALUE:	foreach my $value (@$v) {				# for every value

		my $matchedOnce = 0;
		my $matchFirst = 1;
		my $valueIp = &ipmask($value);
		my $valueInt = $value if ($value =~ /^\d+$/);

		foreach my $descx (@{$Aliases{$v}}) {			# for every alias transform
			my ($target, @exps) = split(/\t/, $descx);

			if (! @exps) {		# no expressions? maybe a directive
				if ($target =~ /^match=(any|first)$/i) {
					$matchFirst = ($1 =~ /first/i);
					next VALUE if (($matchFirst) && ($matchedOnce));
				}
				# there may be errors here, but just ignore them.

				next;
			}

			my @check;
			push(@check, $descriptions->{$value});

			if (lc($exps[0]) eq "description-only") {	# check description only
				shift @exps;
			}
			else {						# check description AND value
				push(@check, $value);
				push(@check, $value . '|' . $descriptions->{$value});
			}

			foreach (@exps) {		# for each expression (often 1)
				my $alias;
				if (defined ($alias = &calcCheck($target, $_, $valueIp, $valueInt, @check))) {
					$aliasList{$alias}->{$value} = 1;
					$matchedOnce = 1;
					next VALUE if ($matchFirst);
				}
			}
		}
	}

	# populate alias hash
	foreach (keys %aliasList) {
		$aliases->{'+' . join(",", sort {$a cmp $b} keys %{$aliasList{$_}}) . '+'} = $_;
	}

	if (@$v >= 100) {			# for big ones, save a cache
		open(CACHE, ">$fCache");
		foreach (keys %$aliases) { print CACHE "$_\t$aliases->{$_}\n"; }
		close(CACHE);
	}

	if ($debug >= 2) {
		print "<b>CalcAliases '$v'</b><br>\n";

		foreach (sort {$a cmp $b} keys %$aliases) {
			print "$_ -> ", $aliases->{$_}, "<br>\n";
		}
	}

	return (scalar keys %$aliases);
}

# --------------------------------------------------------------------------------
# keeps a running speed tally. pass it a pointer to a speed counter, a variable type,
# and one or more interfaces/aliases
#   &calcSpeed(\$speed, $v, @vals);

sub calcSpeed
{
	my($curSpeed, $v, @vals) = @_;
	return 0 if (! defined $$curSpeed);

	if (! defined $GLOBAL_SpeedHash{$v}) {		# haven't extracted speed info yet
#		print "v = $v<br>\n";		# 0930-ALBUQUERQUE#Serial0/0
#		print "\@vals = @vals<br>\n";

		foreach (@{$Speeds{$v}}) {
			my($targetSpeed, @matrixVars) = split(/\t/);
			next if (! $targetSpeed);

			foreach (@matrixVars) {
				push (@{$GLOBAL_SpeedHash{$v}->{$_}}, $targetSpeed);
			}
		}

		if (! defined $GLOBAL_SpeedHash{$v}) {	# still no speed info available
			$$curSpeed = undef;
			return 0;
		}
	}

	my(@myVals);
	foreach (@vals) {
		if (/^\+([^\+]+)\+$/) { push(@myVals, split(/,/, $1)); }
		else { push(@myVals, $_); }
	}

	foreach (@myVals) {
		foreach (@{$GLOBAL_SpeedHash{$v}->{$_}}) { $$curSpeed += $_; }	# add speed info
	}

	return 1;
}

# --------------------------------------------------------------------------------
# if an authorization file is provided for a matrix, use it...
# returns 1 if authorization was overlayed, or 0 if not (no auth)

sub calcAuthorization
{
	my($v, $descriptions) = @_;
	my(@authExps, @newv);

	return 0 if (! @{$Authorization{$v}});		# no Authorization transforms? quit now!

	foreach my $descx (@{$Authorization{$v}}) {
		my ($ttype, @exps) = split(/\t/, $descx);
		next if ($ttype !~ /^(.*?)=(.*)$/);
		# $1 probably is REMOTE_NAME or REMOTE_ADDR

		if (&calcSimpleCheck($ENV{$1}, $2, undef)) {
			print "Authorization '$ttype' success<br>\n" if ($debug);
			push(@authExps, @exps);
			last;
		}
	}

VALUE:	foreach my $value (@$v) {
		foreach my $check (@authExps) {
			if (&calcSimpleCheck($value, $check, $descriptions)) {
				push(@newv, $value);
				next VALUE;
			}
		}
	}

	@{$v} = @newv;					# use new list of approved variables
	return 1;
}

# --------------------------------------------------------------------------------
# Computes all the descriptions for a given variable and returns them in a hash
# Each item has exactly one description.

sub calcDescriptions
{
	my($v, $descriptions) = @_;
	my(%descList);

	return 0 if (! @{$Descriptions{$v}});			# no Description transforms? quit now!

	# there is no @$v ... $v = 'Interfaces'

	# populate one-to-one hash
	foreach my $descx (@{$Descriptions{$v}}) {		# for every description transform
		my ($target, @exps) = split(/\t/, $descx);
		foreach (@exps) {					# for each expression (often 1)
			$descList{$_} = $target;
		}
	}

	# assign available descriptions to each value
	foreach my $value (@$v) {				# for every value
		if (defined (my $dl = $descList{$value}) ) {
			$descriptions->{$value} = $dl;
		}
		elsif ($value =~ /(.*)\/\d+$/) {		# handle subnets matching ip addresses
			if (defined (my $dl = $descList{$1}) ) {
				$descriptions->{$value} = $dl;
			}
		}
	}

	if ($debug >= 2) {
		print "<b>CalcDescriptions '$v'</b><br>\n";

		foreach (sort {$a cmp $b} keys %$descriptions) {
			print "$_ -> " . $descriptions->{$_} . "<br>\n";
		}
	}

	return (scalar keys %$descriptions);
}

# --------------------------------------------------------------------------------
# given a variable and a list of aliased items, this returns the alias name.

sub hackAliasName
{
	my($v, $alias) = @_;
	my(%aliases, %descriptions);

	if (&calcDescriptions($v, \%descriptions)) {
		&calcAliases($v, \%descriptions, \%aliases);
	}

	my $x = $aliases{$alias} || $alias;
	$x =~ s/^\s+//g;
	$x =~ s/\s+$//g;
	return $x;
}

# --------------------------------------------------------------------------------
# Given a matrix variable, this displays a nice UI for selection.
# Matrix variables can have hundreds or thousands of values.
#
# The popup_menu selects major items, such as Aliases, individual routers,
# all routers, etc. A change to this pull-down invokes a form submit to
# populate the scrolling_list with data. These large categories can be
# broken up into multiple items if they contain too many values. (E.g., 
# "Aliases ARB to DES", "Aliases DEN to KCM", etc).
#
# The scrolling_list contains the items available based on the first pull-down.
# As one tabs through it, the descriptions are displayed in a text box.
#
# Each value may have a description. For router interfaces, the descriptions
# are taken from the router config. For IPs, ASNs, Ports, etc, the descriptions
# can be read from a description file supplied in flowage.cfg (and written to
# the index file).
#
# Each value may be summarized by an alias. I.e., an alias can refer to one or
# more matrix values. Aliases are based on the description if available, or the
# value itself if not. Alias definitions are read from an alias file supplied in
# flowage.cfg (and written to the index file). Aliases can be regular expressions,
# subnets, or integer/integer-ranges.
#
# Basic flow
#   calcDescriptions
#   calcAliases
#   divvyPopup
#   generate code, with javascript descriptions and submits

sub matrixVarMenu
{
	my($var) = $_[0];
	my(%descriptions, %aliases, %labels);		# hash pointers
	my(@menuItems, %menuOpts);

	print "matrixVarMenu for variable $var\n" if ($debug);

	# COMPUTE DESCRIPTIONS

	&calcDescriptions($var, \%descriptions);

	# RUN AUTHORIZATION FILTER

	if ((&calcAuthorization($var, \%descriptions)) && (! @{$var})) {
		print <<EOT;
<h3>You aren't authorized for any variables of type '$var'</h3>
EOT
		return;
	}

	# CREATE A MAJOR CATEGORY FOR ALIASES

	if (&calcAliases($var, \%descriptions, \%aliases)) {
		push(@menuItems, "Aliases");
		$menuOpts{"Aliases"}->{items} = [sort { &paddedCmp($aliases{$a}, $aliases{$b}) }  keys %aliases];
		$menuOpts{"Aliases"}->{labels} = \%aliases;
	}

	# MAJOR CATEGORIES FOR EACH ROUTER (if this is an interface variable)

	if (grep(/\#/, @$var) == @$var) {			# is this variable an interface variable?
		my %routerifs;

		foreach (@$var) {
			if (/^([^#]+)#?(.*)$/) {
				push(@{$routerifs{$1}}, $_);		# add to menu
				$labels{$_} = &ifDispName($2);
			}
		}

		foreach (sort byRouterName keys %routerifs) {
			push(@menuItems, $_);
			$menuOpts{$_}->{items} = $routerifs{$_};
			$menuOpts{$_}->{descriptions} = \%descriptions;
			$menuOpts{$_}->{labels} = \%labels;
		}
	}
	else {			# OTHERWISE, A MAJOR CATEGORY FOR WHATEVER IT IS
		push(@menuItems, $var);
		$menuOpts{$var}->{items} = [@$var];
		$menuOpts{$var}->{descriptions} = \%descriptions;
	}

	# SPLIT UP REALLY LARGE CATEGORIES

	my $CONST_maxSubs = 700;	# how many items per menu, max
	my $CONST_overflowFudge = 3;	# if fewer than this items remain, stick them on the menu anyway
	my $CONST_minOwnItem = 600;	# if X items begin the same, they get their own submenu

	my $beforeCount = @menuItems;

	foreach my $MI (@menuItems) {
		my $items = {};
		my @itemnames;

		my(@items, @subitems);
		my(@batch, @runningBatch, $lastPrefix, $identicalCounter);

		# first pass, items that begin with the same first word are considered to be the same.
		# if there are enough of them ($CONST_minOwnItem), they get an entry of their own,
		# regardless of if they have $CONST_MaxSubs or not.

		foreach (@{$menuOpts{$MI}->{items}}, 'CArTm@N') {
			my $label = ${$menuOpts{$MI}->{labels}}{$_} || $_;
			my $prefix = $1 if ($label =~ /^([\w\.]+)/);

			if ($prefix eq $lastPrefix) {
				$identicalCounter++;
			}
			else {
				if ($identicalCounter >= $CONST_minOwnItem) {
					if (@runningBatch) {
						$items->{$MI} = [@runningBatch];
						undef @runningBatch;
					}
					$items->{"$MI: $lastPrefix"} = [@batch];
				}
				else {
					push(@runningBatch, @batch);
				}

				undef @batch;
				$identicalCounter = 0;
				$lastPrefix = $prefix;
			}
			push(@batch, $_);
		}
		$items->{$MI} = [@runningBatch] if (@runningBatch);

		# second pass, chop up the array of arrays into menu items
		my($segmentingThisGuy);

		foreach (sort keys %$items) {
			my @items = @{$items->{$_}};
			my $itemNew = $_;
			my $segmentingThisGuy = 0;

			while (@items) {
				my @subitems = splice(@items, 0, $CONST_maxSubs);
				push(@subitems, splice(@items)) if (@items < $CONST_overflowFudge);

				# if this guy still has remaining entries, we need to segment him... 

				if (@items) { $segmentingThisGuy = 1; }

				if ($segmentingThisGuy) {
					my($itemFirst, $itemLast);

					$itemFirst = ${$menuOpts{$MI}->{labels}}{$subitems[0]} || $subitems[0];
					if ($#subitems) {
						$itemLast = ${$menuOpts{$MI}->{labels}}{$subitems[$#subitems]} ||
							$subitems[$#subitems];

						# trim $itemLast to 'unique' characters.
						my(@first) = split(/(\W)/, $itemFirst);
						my(@last) = split(/(\W)/, $itemLast);
						my $chunk;
						for (my $i=0; $i<@first; $i++) {
							$chunk=$i;
							last if ($first[$i] ne $last[$i]);
						}
					 	$itemLast = " to " . join("", splice(@last, $chunk));
					}
					$itemNew = "$MI: " . $itemFirst . $itemLast;
				}

				push(@newMenuItems, $itemNew);
				$menuOpts{$itemNew}->{items} = [@subitems];
				$menuOpts{$itemNew}->{descriptions} = $menuOpts{$MI}->{descriptions};
				$menuOpts{$itemNew}->{labels} = $menuOpts{$MI}->{labels};
			}
		}
	}

	@menuItems = @newMenuItems;

	if (@menuItems != $beforeCount) {
		# MAJOR CATEGORY FOR ALL VALUES (MAY BE HUGE! -- user loads at own risk)

		$v = $var;
		push(@menuItems, $v);
		$menuOpts{$v}->{items} = [@$var];
		$menuOpts{$v}->{descriptions} = \%descriptions;
	}

	if (($debug) && (0)) {
		foreach $item (@menuItems) {
			print "item $item\n";

			foreach (@{$menuOpts{$item}->{items}}) {
				print "\titem=$_\n";
				print "\t\t desc=" . ${$menuOpts{$item}->{descriptions}}{$_} . "\n";
				print "\t\tlabel=" . ${$menuOpts{$item}->{labels}}{$_} . "\n";
			}
		}
		print "<p>\n";
	}

	$curCategory = param("cat$var") || $menuItems[0];
	print hidden(-name=>'select', -value=>'1');

	# JAVASCRIPT to display alias/interface description
	print <<EOT;
<script language='javascript'>
function changed_$var( e ) {
	var rtrif = e.options[e.selectedIndex].value;
	var desc;
EOT

	print "\tswitch( rtrif ) {\n";

	foreach my $item (@{$menuOpts{$curCategory}->{items}}) {
		my $desc = ${$menuOpts{$curCategory}->{descriptions}}{$item};
		if (($item =~ /^\+(.*)\+$/) && (! $desc)) {
			$desc = $1;
			$desc =~ s/,/, /g;
		}
		$desc =~ s/'/\\'/g;

		next if (! $desc);

		print "\tcase '$item':\n";
		print "\t\tdesc = '$desc';\n";
		print "\t\tbreak;\n";
	}

	print <<EOT;
	default:
		desc = rtrif;
	}

	e.form.aliasdescr.value = desc;
}
</script>
EOT

	if ($mode) {		# single entry, for text selection

		print popup_menu(-name=>"cat$var",
			-values=>[@menuItems],
			-onChange=>"this.form.submit();"),
			" &nbsp; &nbsp; ";

		print popup_menu(-name=>"s$var",
			-values=>$menuOpts{$curCategory}->{items},
			-labels=>$menuOpts{$curCategory}->{labels},
			-onChange=>"return changed_$var(this)"),
			"\n";
	}
	else {			# multiple entry, for graphing

		my $default;

		foreach (@{$menuOpts{$curCategory}->{items}}) {
			if ($menuOpts{$curCategory}->{labels}->{$_} =~ /(Serial|POS|Multilink|MFR|ATM)/) {
				$default = $_; last;
			}
		}

		print popup_menu(-name=>"cat$var",
			-values=>( [@menuItems] ),
			-onChange=>"this.form.submit();",
#			-style=>"font-weight: bold",
#			-width=>120
			), "<br>\n";

		print scrolling_list(-name=>"s$var",
			-values=>$menuOpts{$curCategory}->{items},
			-labels=>$menuOpts{$curCategory}->{labels},
			-default=>$default,
			-size=>6,
			-multiple=>true,
			-style=>"width: 100%; font-family:courier",
			-override=>1,
			-onChange=>"return changed_$var(this)"
			), "\n";
	}
}

# --------------------------------------------------------------------------------
# sort, but put Other last

sub otherSort
{
	return 1 if ($a eq "Other");
	return -1 if ($b eq "Other");
	return $a cmp $b;
}

sub byRouterName
{
	if ($a =~ /^\d/) {
		if ($b =~ /^\d/) {
			my($a1,$b1) = ($a,$b);
			$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
			$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
			return (lc($a1) cmp lc($b1));
		}
		return 1;
	}
	elsif ($b =~ /^\d/) {
		return -1;
	}
	return (lc($a) cmp lc($b));
}


# --------------------------------------------------------------------------------
# read in index file
#
# /home/weinhold/data/Routers.[Routers].csv
# /home/weinhold/data/Services.[Services].csv
# /home/weinhold/data/Test.[Routers].[Networks].[Services].rrd    Two T3 links between AAL and LB
# /home/weinhold/data/Badboys.txt

sub readIndex
{
	my($reading, $subreading);

	open(IN, $indexFile);
	while ( <IN> ) {
		chomp;

		if (/^\s*\[([^\]]+)\]\s*$/) {		# bracketed section
			$reading = $1;			#   the variable in the brackets
			undef $subreading;
			undef $dummyColorCounter;

			if ($reading =~ /^(Speeds|Authorization|Descriptions|Aliases)=(.*)/) {
				$reading = $1;
				$subreading = $2;
				print "reading $reading, sub $subreading<br>\n" if ($debug);
			}
			else {
				print "reading $reading<br>\n" if ($debug);
			}
		}
		elsif (/^\s*(\S+)\s*(.*?)\s*$/) {	# stuff
			if (defined $subreading) {
		#		print "reading $reading, subreading $subreading, $_<br>\n";
				push(@{${$reading}{$subreading}}, (-f $_) ? &readSubFile($_) : $2 . "\t" . &cleanMatrix($1) );
			}
			else {
				push(@{$reading}, $1);		# for the correct ordering
				${$reading}{$1} = $2 || (($reading !~ /files/i) ? &dummyColor : undef);
			}
		}
	}
	close(IN);

	# /opt/netflow/rrds/summary/Summary.[%Interfaces].[SummaryServices].rrd

	foreach (@files) {				# this SHOULD be one of the variables read above
		next if (! /\.(rrd|csv)$/);		# skip all but .csv and .rrd files

		if (/(.*)\/([^\/\.]+)[^\/]+$/) {		# Summary
			my $stem = $2;
			push(@fileOrdered, $stem);
			$fileDesc{$stem} = $files{$_};	# if a description is available
			my $fc = $capture{$_};

			if (-d "$1\/$stem") {		# hierarchical view
				s/\./\//g;			# convert dots to slashes
				s/\/(\w*)$/\.$1/;		# return file extension
			}

			if (s/\[packed=([^\]]+)\]/[$1]/) {		# get rid of packed, but note that it's there.
				$filePacked{$stem} = $1;
			}

			$fileCapture{$stem} = $fc;		# capture file associated with this file
			$fileList{$stem} = $_;
			$fileReal{$stem} = $_;

		}
	}
}

our $MYCOMMENTS = <<EOT;

So this render.cgi with packed rrd files is proving to be a bit difficult. A lot of
the recursion logic in render is based on manipualting the filename. As a result, I'm
leaning towards letting the logic do its thing. E.g.,

/network1/netflow/rrds/AgencyApps.[%AgencySubnets].[AgencyServices].rrd

/network1/netflow/rrds/AgencyApps/10-24-16-0_24/Internet.rrd

And then converting "10-24-16-0_24/Internet.rrd" into packed index 4 of 10-24-16-0_24.rrd

EOT

sub dummyColor
{
	$whichPalette = (param('palette') || $palettes[0]) if (! defined $whichPalette);

#	return sprintf("#%02x%02x%02x", rand(256), rand(256), rand(256));

	return ${$paletteValues{$whichPalette}}[$dummyColorCounter++ % @{$paletteValues{$whichPalette}}];
}

sub loadPalettes
{
	my($palette);

	open(IN, $paletteFile);
	while ( <IN> ) {
		chomp;
		if (/^\[([^\]]+)\]/) {
			$palette = $1;
			push(@palettes, $palette);
		}
		else {
			foreach (split(/\s+/)) {
				push(@{$paletteValues{$palette}}, $_) if (/^\#[0-9a-f]{6}$/i);
			}
		}
	}
	close(IN);

	# define a default palette if none exists

	if (! defined $paletteValues{$paletteDefault}) {
		unshift(@palettes, $paletteDefault);

		push(@{$paletteValues{$paletteDefault}}, qw/
#FF8C00 #FF0000 #00FA9A #800000 #0000FF #008000 #008080 #808000 #FF4500
#FF00FF #000080 #008B8B #FFD700 #9400D3 #00CED1 #7FFF00 #0000CD #FFFF00
#7CFC00 #800080 #8B0000 #00008B #006400 #4B0082 #FFA500 #8B008B #191970
#228B22 #8B4513 #B22222 #DC143C #B8860B #A52A2A #2F4F4F #556B2F #32CD32
#6B8E23 #C71585 #2E8B57 #A0522D #483D8B #D2691E #FF1493 #D02090 #20B2AA
#1E90FF #DAA520 #696969 #3CB371 #8A2BE2 #4169E1 #9932CC #9ACD32 #4682B4
#CD853F #CD5C5C #FF6347 #6A5ACD #708090 #ADFF2F #808080 #5F9EA0 #778899
#FF7F50 #40E0D0 #7B68EE #48D1CC #BA55D3 #6495ED #66CDAA #DB7093 #9370DB
#FA8072 #BDB76B #8470FF #F4A460 #8FBC8F #BC8F8F #F08080 #E9967A #FF69B4
#A9A9A9 #90EE90 #FFA07A #DA70D6 #D2B48C #DEB887 #98FB98 #87CEEB #EEDD82
#7FFFD4 #87CEFA #C0C0C0 #EE82EE #B0C4DE #F0E68C #DDA0DD #ADD8E6 #D8BFD8
#FFB6C1 #B0E0E6 #EEE8AA #D3D3D3 #F5DEB3 #FFDEAD #AFEEEE #FFC0CB #FFDAB9
#FFE4B5 #FFE4C4 #FFE4E1 #E6E6FA
			/
		);
	}

	# define a special 'Consistent' palette to preserve datapoint/color relationships
	# on 'separate' graphs.

	push(@palettes, $paletteConsistent);
	$paletteValues{$paletteConsistent} = $paletteValues{$paletteDefault};
}

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

	my($fName) = $_[0];
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

		print "target=$target<br>values=" . join(", ", @{$targetCache{$target}}) . "<br>\n" if ($debug);
	}

	return @stuff;
}

# --------------------------------------------------------------------------------
# generate one or more graphs, based on the param variables

sub graphIt
{
	my($file) = param('file');			# set of data
	my(@vars) = &dissect($fileList{$file});		# subordinate variables
	my(@datapoints) = param('dp');			# Bits &| Packets &| Flows &| IPs
	my($iterations) = param('iterations') || 1;
	my($duration, $start, $size, $period, $step);
	my($v, $graphvar, @separate, @combine);

	foreach my $v (@vars) {
		push(@{$v}, &loadMatrixVals($file, $v)) if ($matrixVar{$v});
		$matrixCount{$v} = $1 if ($$v[0] =~ /^_(.*)/);
	}

	if (param('dur') =~ /(\d+)-week/i) {	$duration = 86400 * 7 * $1; }
	elsif (param('dur') =~ /week/i) {	$duration = 86400 * 7; }
	elsif (param('dur') =~ /(\d+)-month/i) {$duration = 86400 * 30 * $1; }
	elsif (param('dur') =~ /month/i) {	$duration = 86400 * 31; }
	elsif (param('dur') =~ /year/i) {	$duration = 86400 * 365; }
	elsif (param('dur') =~ /(\d+)-hour/i) {	$duration = 3600 * $1; }
	elsif (param('dur') =~ /(\d+)-min/i) {  $duration = 60 * $1; }
	else {					$duration = 86400; }		# default=day

	if (! ($start = param('start')) ) {
		$start = &hackDate(param('date') . " " . param('time'));		# grab the date

#		if ( (! $start) || (! param('time')) || (($start + $duration) > time) )  {		# adjust the date

		if ( (! $start) || (($start + $duration) > time) )  {		# adjust the date
			$start = time - $duration - 600;
		}
	}
	if (my $end = param('end')) {			# if absolute end
		$duration = $end - $start;		#    calculate relative end
	}

#	print "start = $start (" . (scalar localtime($start)) . ")<br>\n";

	if (param('step') =~ /^(\d+)$/) {	$step = $1;		}

	if (param('size') eq "tiny") {		$size = "200x100";	}
	elsif (param('size') eq "small") {	$size = "400x150";	}
	elsif (param('size') eq "large") {	$size = "1000x350";	}
	elsif (param('size') eq "huge") {	$size = "1200x600";	}
	else {					$size = "800x200";	}	# medium

	if (param('period') =~ /hours/i) {	$period = 3600; }
	elsif (param('period') =~ /days/i) {	$period = 86400; }
	elsif (param('period') =~ /weeks/i) {	$period = 86400 * 7; }
	else { $iterations = 1; }

	foreach (@vars) {				# protocols, locations, what-not...
		my $v = param("v$_");

		print "parm $_ = $v<br>\n" if ($debug);
		if ($v eq "combine")		{ push(@combine, $_); }
		elsif ($v eq "separate")	{ push(@separate, $_); }
		elsif ($v eq "graph") {
			if (! defined $graphvar)	{ $graphvar = $_; }
			else {
				print $errorText . "ERROR: Only one variable can be used for the datapoints." . $noErrorText;
				print "<p>Click <b>back</b> and try again.\n";
				return;
			}
		}
		else {
			print $errorText . "ERROR: Invalid parameter $_ = $v" . $noErrorText;
			print "<p>Click <b>back</b> and try again.\n";
			return;
		}
	}

	# bomb out if there's not at least one group
	if (! defined $graphvar) {
		print $errorText . "ERROR: One variable must be selected for the datapoints." . $noErrorText;
		print "<p>Click <b>back</b> and try again.\n";
		return;
	}

	param('palette', $paletteConsistent) if ((param('palette') eq $paletteDefault) && (@separate));

	# grab the full self-url for later
	Delete('aliasdescr');
	$myself = self_url;
	
	$| = 1;

	undef %skip;
	undef %skipReason;

	while ($iterations--) {
		undef @rrd_head;				# a global

		push(@rrd_head, "--alt-autoscale-max");
		push(@rrd_head, "-s $start");

		# the following line may fix the nasty chunky bug that rears its head constantly...
		push(@rrd_head, "-e " . ($start + $duration));	# if (($start + $duration + 3600 * 4) < time);

		$size =~ /(\d+)x(\d+)/;
		push(@rrd_head, "-w $1");
		push(@rrd_head, "-h $2");
		# push(@rrd_head, "-S $step") if ($step);

		push(@rrd_head, "-x", 'DAY:1:WEEK:1:WEEK:1:0:%x') if (($duration > (21 * 86400)) && ($duration < (365 * 86400)) );
		push(@rrd_head, "TEXTALIGN:left") if ($RRDs::VERSION >= 1.3);

		$GLOBAL_START = $start;
#		$GLOBAL_FIRSTGRAPH = 0;

		print "Graphs begin at " . scalar localtime($start) . "<p><center>\n"
			if (($GLOBAL_GRAPH) && (! $quiet));

		&graphRecursively(0, $file, $graphvar, $start, \@separate, \@combine, \@datapoints, $step);
		print "</center>\n" if ($GLOBAL_GRAPH);

		$start -= $period;
	}

	if (%skip) {
		my @reasons = sort {$skipReason{$b} <=> $skipReason{$a}} keys %skipReason;
		print "Skipped " . (scalar keys %skip) . " items because of " .
			join(', ', splice(@reasons, 0, -1), "or " . splice(@reasons)) . "<br>\n";
	}

	if (! $GLOBAL_GRAPH) {
		print (($simpleOutput) ? "</pre>" : "</table>");

		if (@noDataMsg) {
			my %noDataHash;
			map { $noDataHash{$_}=1 } @noDataMsg;

			print "<br>Some data is missing for the following:<br>\n";
			foreach (sort keys %noDataHash) {
				print " &nbsp; &nbsp; <i>$_</i><br>\n";
			}
		}
	}

	if (! $quiet) {
		print <<EOT;
<br>
To conveniently regenerate this page, save <a href="$myself">this link</a>.
<p>
EOT
		print button(-name=>'Back', -onClick=>'history.go(-1)'),
			' &nbsp; &nbsp; ',
			button(-name=>'Home', -onClick=>'top.location=".."');
	}
}

# note that 
#  %build and %rrds are two globals

# --------------------------------------------------------------------------------
# &graphRecursively is called by graphIt, but may call itself. It iterates through all
# values of the $separateIndex variable. It may also call &combineRecursively.

sub graphRecursively
{
	my($separateIndex, $stem, $graphvar, $start, $separate, $combine, $datapoints, $step) = @_;
	my($var, $fn, $rpn, $vn, @vns, @tvns, $graphBy, $datapointCounter);
	my(@rrd, @rrd2);
	my($label, $first, @separateLabel, @combineLabel);
	my($render) = param('io');			# how to render in/out data
	my($xsize, $ysize, $results);
	my($style1, $style2);				# line style for first and additional data points
	my($speed) = 0;
	my($packed) = $filePacked{$stem};

	my $cf = (param('cf') =~ /avg/) ? 'AVERAGE' : 'MAX';

	if (param('style') =~ /stack/i) {
		$style1 = "AREA"; $style2 = "STACK";
	}
	elsif (param('style') =~ /layer/i) {
		$style1 = "AREA"; $style2 = "AREA";
	}
	elsif (param('style') =~ /thin/i) {
		$style1 = "LINE1"; $style2 = "LINE1";
	}
	elsif (param('style') =~ /thick/i) {
		$style1 = "LINE3"; $style2 = "LINE3";
	}

	if ($separateIndex <= $#$separate) {		# we are processing @separate
		$var = $separate->[$separateIndex];		# var = locations, protocols, etc

		foreach (&varKeys($var)) {
			$build{$var} = $_;
			my @sepSave = param('s' . $var);
			param('s' . $var, $_);
			&graphRecursively($separateIndex + 1, $stem, $graphvar, $start, $separate, $combine, $datapoints, $step);
			param('s' . $var, @sepSave);
		}
		return;
	}

	#we have a filled up %build global hash

#	print "build = " . join(', ', map { "$_ -> $build{$_}" } keys %build) . "; separate = @$separate<br>\n"; #

	foreach $dp (@$datapoints) {				# bits, flows, packets, IPs, bits/IPs
		param('dp', $dp);

		my ($dp1, $dp2);
		if ($dp =~ /^(\w+)\/(\w+)$/) {			# divide one datapoint into another
			$dp1 = $1; $dp2 = $2;
		}

		undef @separateLabel;
		undef @combineLabel;
		undef $speed if ($dp !~ /^bits$/i);

		$fn = $fileList{$stem};

		foreach my $x (@$separate) {				# fill in the name, where possible
			# $_ = Interfaces  $build = the interface itself or an alias
			&calcSpeed(\$speed, $x, $build{$x});

			$fn =~ s/\[\%?$x\]/&matrixExpand($build{$x})/e;
			# $fn = /network1/netflow/rrds/AgencyApps/10-39-167-0_24/[AgencyServices].rrd

			if ($build{$x} =~ /\+/) { 	# use ALIAS name
				push(@separateLabel, ((@$separate > 1) ? "$x=" : "") . &hackAliasName($x, $build{$x}));
			}
			else {				# use item name
				push(@separateLabel, ((@$separate > 1) ? "$x=" : "") . &ifDispName($build{$x}));
			}
		}

		undef %rrds;		# list of real files will be filled up in combineRecursively
		&combineRecursively(0, $fn, \$speed, $graphvar, $combine);

		print "Combined speed = " . ($speed || "undef") . "<br>\n" if ($debug);

		undef $first;
		undef $first2;
		undef @rrd;				# filled up in the loop below
		undef @rrd2;				# also filled up below
		push(@rrd, @rrd_head);

		# compute the width of the widest label
		my ($labelMaxWidth, %labelGraphBy);
		foreach $graphBy (&varKeys($graphvar)) {
			if (%matrixCount) {			# label is blank for simple counters
				$labelGraphBy = "";
			}
			elsif ($graphBy =~ /^\+/) {			# label is an ALIAS
				$labelGraphBy = &hackAliasName($graphvar, $graphBy);
			}
			else {						# label is simple
				$labelGraphBy = $graphBy;
				$labelGraphBy =~ s/#/, /;
				$labelGraphBy =~ s/\-aal5 layer//;
				$labelGraphBy =~ s/\:/\\\:/g;		# escape the colons
			}
			$labelGraphBy{$graphBy} = $labelGraphBy;
			$labelMaxWidth = length($labelGraphBy) if (length($labelGraphBy) > $labelMaxWidth);
		}

		# pad the labels to the proper width
		foreach (keys %labelGraphBy) {
			$labelGraphBy{$_} = sprintf('%-' . $labelMaxWidth . '.' . $labelMaxWidth . 's', $labelGraphBy{$_}) . (($noRRDpatch) ? ' ' : ' \J');
		}

		# if only one datapoint and in quiet mode, turn off labels
		my $nolabel = ( (&varKeys($graphvar) == 1)  && ($quiet));

		# if graphVar is 'all', then varKeys returns all values here.
#		print STDERR "graphvar $graphvar values " , join(', ', &varKeys($graphvar)) . "\n";

		my @keys = &varKeys($graphvar);
		@keys = reverse @keys if (param('trimOrder') =~ /reverse/i);

		foreach $graphBy (@keys) { 		# &varKeys($graphvar)) {
			my $label = ($nolabel) ? '' : $labelGraphBy{$graphBy};

			undef @vns;

			# --- experimental code below

			foreach (@{$rrds{$graphBy}}) {		# /network1/netflow/rrds/AgencyApps/10-39-167-0_24/Exchange.rrd
				my(@aliasedItems);

				&expandAliases($_, \@aliasedItems);		# generate all permutations

				foreach my $lfn (@aliasedItems) {
					my $prefix = '';		# packed prefix

					# if the rrd is packed, figure out the datapoint prefix and the real file name
					if ($packed) {
						$lfn =~ s/\/([^\/]+)\.rrd$/\.rrd/;		# strip packed var
						my $needle = $1;
						my $count=0;

						foreach (@$packed) {
							if ($_ eq $needle) { $prefix = "$count-"; last; }
							$count++;
						}
					}

					if (! -f $lfn) {		# no RRD? no data...
						print "file missing: $lfn<br>\n" if ($debug);
						next;
					}
					print "file exists: $lfn<br>\n" if ($debug);

					my $stepsuffix = ":step=$step" if ($step);
					if ($render ne "out") {
						$vn = &counter("in");
						if (defined $dp1) {		# math
							my $vna = $vn . "a";
							my $vnb = $vn . "b";

							push(@vns, join(",", $vna, "UN", "0", $vna, "IF", $vnb, "UN", "0", $vnb, "IF", "1", "MAX", '/'));
							push(@rrd, "DEF:$vna=$lfn:$prefix$dp1-in:$cf$stepsuffix");
							push(@rrd, "DEF:$vnb=$lfn:$prefix$dp2-in:$cf$stepsuffix");
						}
						else {
							push(@vns, "$vn,UN,0,$vn,IF");		# this rpn converts NaN to 0
							push(@rrd, "DEF:$vn=$lfn:$prefix$dp-in:$cf$stepsuffix");
						}
					}

					if ($render ne "in") {
						$vn = &counter("out");
						if (defined $dp1) {		# math
							my $vna = $vn . "a";
							my $vnb = $vn . "b";

							push(@vns, join(",", $vna, "UN", "0", $vna, "IF", $vnb, "UN", "0", $vnb, "IF", "1", "MAX", '/'));
							push(@rrd, "DEF:$vna=$lfn:$prefix$dp1-out:$cf$stepsuffix");
							push(@rrd, "DEF:$vnb=$lfn:$prefix$dp2-in:$cf$stepsuffix");		# always should be 'in' to make results sensible
						}
						else {
							push(@vns, "$vn,UN,0,$vn,IF");
							push(@rrd, "DEF:$vn=$lfn:$prefix$dp-out:$cf$stepsuffix");
						}
					}
				}
			}

			if (! @vns) {		# must be no rrds...
				print "not graphing $graphBy due to missing files<br>\n" if ($debug);
				next;
			}

			$datapointCounter++;
			if ($render ne "distinct") {				# in, out, or combine
				$rpn = join(",", @vns) . (",+" x $#vns);
				$vn = &counter("cdef");
				push(@rrd, "CDEF:$vn=$rpn");
				push(@rrd, ((! $first++) ? $style1 : $style2) .
					":$vn" .
					($$graphvar{$graphBy} || &dummyColor) .
					(($quiet) ? undef : ":$label") );
			}
			else {							# distinct -in and +out
				my $tc;		# temp color
				@tvns = grep(/in\d+/, @vns);

				$rpn = "0," . join(",", @tvns) . (",+" x $#tvns) . ",-";
				$vn = &counter("cdef");
				push(@rrd, "CDEF:$vn" . "_minus=$rpn");
				push(@rrd, ((! $first++) ? $style1 : $style2) .
					":$vn" . "_minus" .
					($$graphvar{$graphBy} || ($tc = &dummyColor)) .
					(($quiet) ? undef : ":$label") );

				@tvns = grep(/out\d+/, @vns);

				$rpn = join(",", @tvns) . (",+" x $#tvns);
				push(@rrd2, "CDEF:$vn" . "_plus=$rpn");
				push(@rrd2, ((! $first2++) ? $style1 : $style2) .
					":$vn" . "_plus" .
					($$graphvar{$graphBy} || $tc) .
					(($quiet) ? undef : ":$label") );

				# note: this @rrd2 stuff gets added to @rrd when we're all done
			}
		}

		# generate labels for combined elements... these may end up being too wide to display.

		foreach my $x (@$combine) {
			if ( (scalar &varKeys($x)) < 0 ) {		# all elements
				push(@combineLabel, "all $x");
			}
			else {
				my($vk, @vks);
				foreach $vk (&varKeys($x)) {
					if ($vk =~ /\+/) {		# an ALIASed item
						push(@vks, &hackAliasName($x, $vk));
					}
					else {				# a non-ALIASed item
						push(@vks, &ifDispName($vk));
					}
				}

				if (@$combine == 1) {				# only one thing being combined
				#	push(@combineLabel, join(", ", @vks) );
					push(@combineLabel, sjoin(@vks) );
				}
				elsif (@vks == 1) {				# one element
					push(@combineLabel, "$x=" . join(",", map { "\"$_\"" } @vks) );
				}
				else {						# > one element
					push(@combineLabel, "$x=(" . join(", ", map { "\"$_\"" } @vks) . ")");
				}
			}
		}

		if (! ($label = param('title')) ) {
			$label = $graphvar;
			if (@combineLabel > 0) { $label .= " on " . sjoin(@combineLabel); }	# where
			if (@separateLabel > 0) { $label .= " on " . sjoin(@separateLabel); } 	# across
		}

		my $tLabel;
		if (! %matrixCount) {
			if (defined $dp1) {
				$tLabel = "$dp1/sec per $dp2";
				chop $tLabel if ($tLabel =~ /s$/);
			}
			elsif ($dp ne "IPs") {
				$tLabel = "$dp/sec";
			}
			else {
				$tLabel = $dp;
			}
		}

		if ($render =~ /combine/i) {
			unshift(@rrd, "-v total $tLabel");
		}
		elsif ($render =~ /^(in|out)$/) {
			unshift(@rrd, "-v $render" . "put $tLabel");
		}
		else {
			unshift(@rrd, "-v in (-)  $tLabel  out (+)");
			push(@rrd, "HRULE:0#000000");
		}

		unshift(@rrd, "-t $label");

		push(@rrd, @rrd2);

		if (! $datapointCounter) {
			push(@noDataMsg, $label);
			return undef;
		}

#		if ($RRDs::VERSION >= 1.2) {
#			push(@rrd, 'COMMENT: \l');
#		}

		if (($speed) || ($start)) {
			push(@rrd, "COMMENT:\\s");
			push(@rrd, "COMMENT:\\s");
			push(@rrd, "COMMENT:\\s");

			if ($speed > 0) {			# we have a speed to plot
				push(@rrd, "HRULE:$speed#C00000");
				push(@rrd, "HRULE:-$speed#C00000") if ($render =~ /distinct/i);
				push(@rrd, "COMMENT:Bandwidth line at " . &niceUnits($speed, 1, 'TGMK'));
			}

			if (defined $start) {
				push(@rrd, "COMMENT:Graph begins " . strftime("%a %d-%b-%Y %H:%M", localtime($start)));
			}
		}

		# do the RRD 1.2 compatibility routine here
		&rrd2compatible(\@rrd) if ($RRDs::VERSION >= 1.2);

		# set the appropriate parms for a linkback url
		Delete(qw/date time iterations/);
		param('start', $start);

		my ($img, $results, $xsize, $ysize);

		if ( (param('trimEmpty') =~ /on/i) || (param('trimItems') !~ /data trim/i) ||
			(param('trimSource') !~ /source trim/i) ||
			(param('trimOrder') !~ /(original|reverse)/i) || $GLOBAL_TABLE ) {

			# use the intelligent grapher...
			($img, $results, $xsize, $ysize) = &intelligentGrapher($label, $fileCapture{$stem}, $speed, $packed, \@rrd);

			if (! defined $img) {
				$skip{$label} = 1;
				$skipReason{"no data in range"}++;
			}
			elsif ($img eq $skipImage) {
				$skip{$label} = 1;
				$skipReason{$results}++;
				undef $img;
			}
		}
		else {	# otherwise, use the simple grapher...
			if ($debug) {
				print "<pre>$label\n";
				foreach (@rrd) { print "$_\n"; }
				print "</pre>";
			}

			&stripDuplicateLegends(\@rrd);

			if ($GLOBAL_DETAIL) {	   # generate an xport
				&getDetail(@rrd);
			}
			else {				# generate a graph (even if we don't display it)
				$img = &counter("image-$$-") . "." . $IMAGESUFFIX;

				my $myself = self_url;

				open(OUT, ">$graphDir$img.$INFOSUFFIX");
				print OUT "$RRDs::VERSION\n";
				print OUT $fileCapture{$stem} . "\n";
				print OUT "$myself\n";
				print OUT "$packed\n";

				foreach (@rrd) { print OUT "$_\n"; }
				close(OUT);

				(undef, $xsize, $ysize) = RRDs::graph($graphDir . $img, "-a" . uc($IMAGEFORMAT), @rrd);

				my $err=RRDs::error;
				if ($err) {
					print $errorText . "Error generating graph <u>$label</u>:<p>RRD ERROR: $err" .
						$noErrorText . "<p>";
					undef $img;
				}
			}
		}

#		param('s' . $graphvar, @graphvarSave);

		if (defined $img) {
			if ($GLOBAL_GRAPH) {
				if (($clickable) && (! $quiet)) {
					print <<EOT;
<form action="$clickURL" method=post target="_blank">
<input type=hidden name=img value="$img">
<input type=image src="$graphDirURL$img" border=0>
</form>
EOT
				}
				else {
					print <<EOT;
<img ismap src="$graphDirURL$img" alt="Graph of $label" height=$ysize width=$xsize>
EOT
					print "<br>";
				}
			}

			if ($results) {		# text results, to be displayed in a table
				my(%rHash, %rKeys, @rOrder, @rkOrder);

				# results look like:
				#     CommercialMarkets Maximum 8870.401600

				foreach (@$results) {
#					next if (! /^\s*(\S+)(\s+\\J|)\s+(\S+).*?([\-\d\.]+)$/);
					next if (! /^\s*(\S.*?)(\s+\\J|)\s+(Maximum|Average).*?([\-\d\.]+)$/);

					push(@rOrder, $1) if (! defined $rHash{$1});
					push(@{$rHash{$1}->{$3}}, $4);

					if (! defined $rKeys{$3}) { push(@rkOrder, $3); $rKeys{$3} = 1; }
				}

			#	my $font = "<font size=2>";
			#	my $nofont = "</font>";
				my $dcol = "<td width=25>";		# between categories
				my $scol = "<td width=15>";		# between in/out
				my $prefix, $hprefix;

				if (($simpleOutput) || (! $GLOBAL_GRAPH)) {		# no graphing? Print out some header info
					my $label;

					if (@combineLabel > 0) {
						$label = sjoin(@combineLabel);
						$label =~ s/[^=]+=//;
					}

					if (@separateLabel > 0) {
						my $label2 .= sjoin(@separateLabel);
						$label2 =~ s/[^=]+=//;
						$label = ((defined $label) ? ($label . " and " . $label2) : $label2);
					}

					if ($simpleOutput) {
						$prefix = join(',', scalar localtime($GLOBAL_START), '"' . $label . '"', $speed);
						undef $hprefix;
					}
					else {
						$prefix = "<td>" . scalar localtime($GLOBAL_START) . $scol . 
							"<td>" . $label . $scol . "<td>" . $speed . $scol;
						$hprefix = "<td><td><td><td><td><td>";
					}
				}

				if (($GLOBAL_GRAPH) || (! $GLOBAL_FIRSTGRAPH)) {
					if ($simpleOutput) {
						print "<pre style='font-size:8pt;'>";
						print join(',', qw/start label speed datapoint max-in max-out avg-in avg-out/) . "\n";
					}
					else {
						print "<table cellspacing=0 cellpadding=0 ",
							"style='font-size: 10; font-family: sans-serif'>";

						# display table header
						my $colspan = " colspan=" . (($render eq "distinct") ? "3" : "1");

						print "<tr>$hprefix<td>";
						foreach (@rkOrder) { print "$dcol<th$colspan align=center>$_"; }
						if ($render eq "distinct") {
							print "\n<tr>$hprefix<td>";
							foreach (@rkOrder) {
								print $dcol, "<td align=center><i>in</i>",
									$scol, "<td align=center><i>out</i>";
							}
						}
					}

					$GLOBAL_FIRSTGRAPH = 1;
				}

				my $units='';
				my $digits=2;
				my $commafy=0;
				if (! $simpleOutput) {
					my $r = $rOrder[$#rOrder];			# smalllest val
					my $k = $rkOrder[$#rkOrder];			# average
					my $v = abs($rHash{$r}->{$k}->[0]);		# bps

					if ($v < 1_000_000) { $units = 'K'; $digits = 0;}
					elsif ($v < 1_000_000_000) { $units = 'M'; }
					elsif ($v < 1_000_000_000_000) { $units = 'G'; }
					$commafy=1;
				}

				# display table data
				foreach my $r (@rOrder) {
					if ($simpleOutput) {
						print join(",", $prefix, '"' . $r . '"');
						foreach my $k (@rkOrder) {	# Average | Maximum
							print join(",", undef, map { abs($_) } sort @{$rHash{$r}->{$k}});
						}
						print "\n";
					}
					else {
						print "\n<tr>$prefix<td>$r";
						foreach my $k (@rkOrder) {		# Average | Maximum
							foreach my $v (sort @{$rHash{$r}->{$k}}) {	# sort because first val is negative
								print "<td><td align=right>" . &niceUnits(abs($v), $digits, $units, $commafy);
							}
						}
					}
				}
				if ($GLOBAL_GRAPH) {
					print "</table>" if (! $simpleOutput);
					print "</pre>" if ($simpleOutput);
				}
			}

			print "<hr>\n" if (($GLOBAL_GRAPH) && (! $quiet));;
		}

#		foreach $graphBy (@$graph) {
#			print "<font color=" . $$graphvar{$graphBy} . ">$graphBy &nbsp; ";
#		}
	}
}

sub expandAliases
{
	my($key, $arrayp) = @_;

	if ($key =~ /^(.*?)\+([^\+]+)\+(.*)/) {	# AN ALIAS IN USE
		my ($pre, $post) = ($1, $3);

		foreach my $val (split(/,/, $2)) {
			&expandAliases($pre . &matrixExpand($val) . $post, $arrayp);
		}
	}
	else {					# NO ALIAS IN USE
		push(@$arrayp, $key);
	}
}

sub niceUnits
{
	my($v, $digits, $suffixes, $commafy) = @_;

	my(%units) = (
		1_000_000_000_000 => 'T',
		1_000_000_000 => 'G',
		1_000_000 => 'M',
		1_000 => 'K',
		0 => ''
	);

	foreach (sort {$b <=> $a} keys %units) {
		if ($v >= $_) {
			$si = $units{$_};
			next if (($suffixes !~ /$si/i) && ($si ne ""));

			$digits = 1 if (($_ >= 1_000_000) && (! defined $digits));
			$v = (($_) ? ($v / $_) : $v);

			my $x = ($digits) ? sprintf("%.0" . $digits . "f", $v) : sprintf("%.f", $v);
			$x = &commafy($x) if ($commafy);
			return $x . $si;
		}
	}
}

# --------------------------------------------------------------------------------
# &combineRecursively builds arrays of datapoint values that are to be combined.
# It may call itself.

sub combineRecursively
{
	my($combineIndex, $file, $speed, $graphvar, $combine) = @_;	# $combine is a pointer
	my($var, $fn);

	if ($combineIndex <= $#$combine) {		# we are processing @combine
		$var = $$combine[$combineIndex];
		print "combining var=$var file=$file graphvar=$graphvar<br>\n" if ($debug);

		if ((scalar &varKeys($var) == -1) && (! $someMatrixVar)) {
			# for simple groups (no matrices at all in use), there is a shortcut
			# to 'Any' so that the values don't have to be combined.

			$fn = $file;
			$fn =~ s/\[$var\]/Any/;
			&combineRecursively($combineIndex + 1, $fn, $speed, $graphvar, $combine);

			$fn = $file;
			$fn =~ s/\[\%?$var\]/Other/;
			&combineRecursively($combineIndex + 1, $fn, $speed, $graphvar, $combine);
		}
		else {					# just a few variables are selected
			foreach (&varKeys($var)) {
				&calcSpeed($speed, $var, $_);
				$fn = $file;
				$fn =~ s/\[\%?$var\]/&matrixExpand($_)/e;
				&combineRecursively($combineIndex + 1, $fn, $speed, $graphvar, $combine);
			}
		}
		return;
	}

	# we have filled out $fn except for the actual data thing to be graphed
	foreach (&varKeys($graphvar)) {
		$fn = $file;
		$fn =~ s/\[\%?$graphvar\]/&matrixExpand($_)/e;
		push (@{$rrds{$_}}, $fn);
	}
}

# --------------------------------------------------------------------------------
# "intelligent" graphing routine. First uses RRD to compute averages for each item
# that has been selected for graphing. Only those values that the user wants to
# see are recomposed into a second RRD call that generates the graph.

sub intelligentGrapher
{
	my($label, $capfile, $speed, $packed, $rrd) = @_;
	my($results, %cdefVal, %cdefOrder, %cdefCombine, %defDependencies);
	my(@prrd, @prrdGraph, @cdefs, @text);
	my($x, $img, $err, $results, $xsize, $ysize);

	# trim unused datapoints, reorder the datapoints, and do other manipulations.

	# (1) get rid of rrd commands that create graphs...
	push(@prrd, grep(! /^(AREA|STACK|HRULE|VRULE|LINE|GPRINT|COMMENT)/, @$rrd));

	# (2) grab the CDEFS and generate a command to print their averages (and other things)...
	foreach ( @prrd ) {
		if (/^CDEF:([^\=]+)\=(.*)/) {
			my $cdef = $1;
			my $rpn = $2;

			push(@cdefs, $cdef);

			# go through the RPN for this CDEF and mark all the DEF's as being
			# dependent to the CDEF. As CDEF's are removed, if it is found that
			# a DEF is no longer needed, it won't be generated. 

			foreach (split(/,/, $rpn)) {		# "0,in0001,-"
				next if (! /^[a-z]+\d+[ab]?$/);		# skip non-expressions
				$defDependencies{$_}->{$cdef} = 1;
			}

			if (param('trimOrder') =~ /peak/i) {			# display peak
				push(@prrd, "PRINT:$cdef:" . (($cdef =~ /minus/) ? "MIN" : "MAX") . ":%lf");
			}
			else {							# display average
				push(@prrd, "PRINT:$cdef:AVERAGE:%lf");
			}
		}
	}

	# (3) have RRD generate all the averages values...
	($results, undef, undef) = RRDs::graph("-", @prrd);

	if ($debug) {
		print "<pre><b>intelligentGrapher trimming</b>\n";
		foreach (@prrd) { print "$_\n"; }
		print "</pre>";
	}

	my $err=RRDs::error;
	if ($err) { print $errorText . "Error generating graph <u>$label</u>:<p>RRD ERROR: $err" .
		$noErrorText . "<p>"; return undef; }

	# (4) put the values into a hash (combining plus/minus, if necessary)...
	my $cdefTotalNeg = 0;
	my $cdefTotalPos = 0;
	foreach (@cdefs) {
		if (/^(.*)_(plus|minus)$/) {		# if we have separate plus/minus values,
			$_ = $1;			# we combine their values for the purpose of sorting
			$cdefCombine{$_} = 1;
		}

		$x = shift @$results;
		$x = 0 if ($x eq "nan");
		$cdefVal{$_} += abs($x);
		print "$_ = $x<br>\n" if ($debug);

		if ($x < 0) { $cdefTotalNeg += abs($x); } else { $cdefTotalPos += $x; }
	}
	my $cdefMax = ($cdefTotalPos > $cdefTotalNeg) ? $cdefTotalPos : $cdefTotalNeg;
	my $util = ($speed) ? int(100 * $cdefMax / $speed) : undef;

	# (4.5) source trim, if user has selected...
	if ( (param('trimSource') =~ /([<>])\s*(\d+)/i) && ($speed) && ($cdefMax) ) {
		my $ok = ($1 eq '>') ? ($util > $2) : ($util < $2);
		print "<!-- $label - speed=$speed cdefMax=$cdefMax util=$util ok=$ok -->\n";

		if (! $ok) {
			print "$label - utilization $util is not $1 $2<br>\n" if ($debug);
			return ($skipImage, "utilization trim");
		}
	}

	# (5) trim zero values, if user has selected...
	if (param('trimEmpty') =~ /on/i) {
		foreach (keys %cdefVal) {
			delete $cdefVal{$_} if ($cdefVal{$_} == 0);
		}
	}

	# (6) restrict data to top/bottom X %, if the user has selected...
	if (param('trimItems') =~ /(top|bottom) (\d+)/) {
		my $top = ($1 eq "top");
		my $perc = $2;
 		my @cdefsort = sort { $cdefVal{$b} <=> $cdefVal{$a} } keys %cdefVal;

		my $total = @cdefsort;
		my $toKill = int($total * $perc / 100);

		if ($toKill) {
			if ($top) {	splice(@cdefsort, 0, $toKill); }	# top X percent
			else {		splice(@cdefsort, - $toKill); }		# bottom X percent
			foreach (@cdefsort) { delete $cdefVal{$_}; }		# remove them
		}
	}

	if (scalar keys %cdefVal == 0) {			# nothing left to graph!
		push(@noDataMsg, $label);
		return undef;
	}

	# (7) re-sort data, if the user has selected
	if (param('trimOrder') !~ /(original|reverse)/i) {		# sort by average/peak
		print "sorting data<br>\n" if ($debug);
		my $count = 1;
		foreach (sort { $cdefVal{$b} <=> $cdefVal{$a} } keys %cdefVal) {
			print " &nbsp; $_<br>\n" if ($debug);
			if ($cdefCombine{$_}) {
				$cdefOrder{$_ . "_plus"} = $cdefOrder{$_ . "_minus"} = $count++;
			}
			else {
				$cdefOrder{$_} = $count++;
			}
		}
	}

	# (8) reexpand values that were consolidated from split plus/minus...
	foreach (keys %cdefVal) {
		if ($cdefCombine{$_}) {
			$cdefVal{$_ . "_plus"} = $cdefVal{$_ . "_minus"} = delete $cdefVal{$_};
		}
	}

	# (9) go through the %defDependencies tree and find out if there are any DEF's we can kill...
	foreach my $def (keys %defDependencies) {
		foreach my $cdef (keys %{$defDependencies{$def}}) {
			# if the cdef is gone, delete the key...
			delete $defDependencies{$def}->{$cdef} if (! defined $cdefVal{$cdef});
		}

		# if all keys are gone, then delete the definition...
		delete $defDependencies{$def} if (scalar keys %{$defDependencies{$def}} == 0);
	}

	# the hash %cdefVal now contains a complete list of the CDEFs we want to keep
	# the hash %defDependencies now contains a complete list of the DEFs we need to keep

	# (10) make another pass through the original @rrd data, trimming DEF's, CDEF's, and graphing commands...
	my $graphCount = 0;
	undef @prrd;
	foreach (@$rrd) {
		if (/^DEF:([^\=]+)=/) {						# def definitions
			push(@prrd, $_) if (defined $defDependencies{$1});
		}
		elsif (/^CDEF:([^\=]+)=/) {					# cdef definitions
			push(@prrd, $_) if (defined $cdefVal{$1});
		}
		elsif (/^(AREA|STACK|LINE\d)\:([^\:\#]+)([^\:]*)(\:?.*?)$/) {	# data graphing commands
			push(@{$prrdGraph[$graphCount]}, $_) if (defined $cdefVal{$2});
		}
		elsif (/^(HRULE|VRULE|GPRINT|COMMENT)/) {			# other graphing stuff
			$graphCount++;
			push(@{$prrdGraph[$graphCount++]}, $_);
			if ((/Bandwidth line at/) && ($util)) {
				push(@{$prrdGraph[$graphCount++]}, "COMMENT:Utilization " . int($util) . '%' );
			}
		}
		else {								# other rrd commands
			push(@prrd, $_);
		}
	}

	# (11) sort/clean the @prrdGraph arrays and add them to @prrd.
	for (my $i=0; $i<=$graphCount; $i++) {
		my @stuff = @{$prrdGraph[$i]};	# grab a section of the array

		if ($debug) {
			print "<pre><b>hacking chunk $i</b>\n";
			foreach (@stuff) { print "$_\n"; }
			print "</pre>";
		}

		@stuff = sort {					# sort the data according to cdefOrder...
			my $a1 = $2 if ($a =~ /^(AREA|STACK|LINE\d)\:([^\:\#]+)/);
			my $b1 = $2 if ($b =~ /^(AREA|STACK|LINE\d)\:([^\:\#]+)/);
			$cdefOrder{$a1} <=> $cdefOrder{$b1}
		} @stuff if (%cdefOrder);

		if (grep(/STACK/, @stuff)) {			# if STACK'd, ensure only one 'AREA'
			my $lineType = "AREA";
			foreach (@stuff) {
				s/^(AREA|STACK)/$lineType/;
				$lineType = "STACK";
			}
		}

		if ($debug) {
			print "<pre><b>results of hacking chunk $i</b>\n";
			foreach (@stuff) { print "$_\n"; }
			print "</pre>";
		}

		push(@prrd, @stuff);

 		if ($GLOBAL_TABLE) {
			foreach (@stuff) {
				if (/^(AREA|STACK|LINE\d)\:([^\#]+)[^\:]+\:(.*)/) {
					my($cdef, $label) = ($2, $3);
					my $pMax = ($cdef =~ /minus/) ? "MIN" : "MAX";
					push(@text,
						"PRINT:$cdef:$pMax:$label Maximum %lf",
						"PRINT:$cdef:AVERAGE:$label Average %lf"
#						"PRINT:$cdef:LAST:$label Last %lf"
					);
				}
			}
		}
	}

	# (12) strip the duplicate legends...
	&stripDuplicateLegends(\@prrd);

	&rewriteColors(\@prrd) if (param('palette') ne $paletteConsistent);

	# (13) do some corrections for RRDs 1.2
	# this was moved to the initial RRD grapher
	# &rrd2compatible(\@prrd, \@text) if ($RRDs::VERSION >= 1.2);

	# (14) create the graph...
	if ($GLOBAL_DETAIL) {	   # generate an xport
		&getDetail(@prrd);		      # @text left out -- unnecessary
		return undef;
	}

	my $myself = self_url;

	$img = &counter("image-$$-") . "." . $IMAGESUFFIX;		# image filename
	open(OUT, ">$graphDir$img.$INFOSUFFIX");
	print OUT "$RRDs::VERSION\n";
	print OUT "$capfile\n";
	print OUT "$myself\n";
	print OUT "$packed\n";
	foreach (@prrd, @text) { print OUT "$_\n"; }
	close(OUT);

	($results, $xsize, $ysize) =
			RRDs::graph($graphDir . $img,
				"-a" . uc($IMAGEFORMAT),
				@prrd, @text);	# create it

	if ($debug) {
		print "<pre><b>intelligentGrapher graphing</b>\n";
		foreach (@prrd, @text) { print "$_\n"; }
		print "</pre>";

		print "<pre><b>results</b>\n";
		foreach (@$results) { print "$_\n"; }
		print "</pre>";
	}

	$err=RRDs::error;
	if ($err) { print $errorText . "Error generating graph <u>$label</u>:<p>RRD ERROR: $err" .
		$noErrorText . "<p>"; return undef; }

	# (15) return the graph...
	return (wantarray) ? ($img, ((@$results) ? $results : undef), $xsize, $ysize) : $img;
}

# --------------------------------------------------------------------------------
# groom into an rrd 1.2 compatible format

sub rrd2compatible
{
	my $rrd = shift;

	if ($debug) {
		print "rrd 1.2 compatibility<br>\n";
	}

	foreach (@$rrd) {
		s/^(AREA|STACK|LINE)(\S*?\:\S+?\:)(.*)/"$1$2" . &escapeColon($3)/e;
		s/^(COMMENT:)(.*)/$1 . &escapeColon($2)/e;
	}
}

sub escapeColon
{
	my $x = shift;
	$x =~ s/\:/\\\:/g;
	return $x;
}


# --------------------------------------------------------------------------------
# rewrite the color choices

sub rewriteColors
{
	my($rrd) = $_[0];
	my(%colorWheel);
	$dummyColorCounter = 0;			# reset global

	if ($debug) {
		print "<pre><b>results of colorWrite</b>\n";
	}

	foreach (@$rrd) {
		if (/^(AREA|STACK|LINE\d)\:([^\:\#]+)([^\:]*)(\:?.*?)$/) {
			print "before: $_\n" if ($debug);

			my($shape, $cdef, $color, $label) = ($1, $2, $3, $4);
			$majorcdef = $1 if ($cdef =~ /^([^\_]+)/);		# strip _plus _minus
			print "  cdef: $cdef ($majorcdef)\n" if ($debug);

			$colorWheel{$majorcdef} = &dummyColor if (! defined $colorWheel{$majorcdef});

			$_ = $shape . ':' . $cdef . $colorWheel{$majorcdef} . $label;
			print " after: $_\n" if ($debug);
		}
	}

	if ($debug) {
		print "</pre>";
	}
}

# --------------------------------------------------------------------------------
# When multiple legends for the same thing are found, they are removed. This is
# done as a separate operation to avoid headaches with the intelligentGrapher's
# trimming function.

sub stripDuplicateLegends
{
	my($rrd) = $_[0];
	my(%legends);

	foreach (@$rrd) {
		if (/^(AREA|STACK|LINE\d)\:([^\:\#]+)([^\:]*)(\:?.*?)$/) {
			my($graph, $dp, $color, $legend) = ($1, $2, $3, $4);
			$_ = "$graph:$dp$color" if ($legends{$legend});
			$legends{$legend} = 1;
		}
	}
}

# --------------------------------------------------------------------------------
# generate tabular data for entire rrd file

sub getDetail
{
	my(@rrd);
	my %labels;

	print b('original'), "<p>" if ($debug);

	foreach (@_) {
		print "$_<br>\n" if ($debug);

		if (/^(DEF|CDEF|-s|-e)/) {	# verbatim
			push(@rrd, $_);
		}
		elsif (/^-w (.*)/) {		# transpose -w to -m
			push(@rrd, "-m $1");
		}
		elsif (/^-t (.*)/) {		# title
			print h3($1);
		}
		elsif (/^(AREA|STACK|LINE\d+):(cdef\d+)(\_?\w*)\#[0-9A-F]{6,6}\:\s*([^\\]+)/) {
			$labels{"$2$3"} = $4;
			$labels{"$2_minus"} = "$4<br>in";
			$labels{"$2_plus"} = "$4<br>out";

			push(@rrd, "XPORT:$2$3:" . $labels{"$2$3"});
		}
		elsif (/^(AREA|STACK|LINE\d+):(\w+)\#[0-9A-F]{6,6}$/) {
			push(@rrd, "XPORT:$2:" . $labels{$2});
		}
	}

	if ($debug) {
		print b('xport-friendly'), "<p>";
		foreach (@rrd) {
			print $_, "<br>\n";
		}
	}

	my ($start, $end, $step, $columns, $names, $table) = RRDs::xport(@rrd);

	$err=RRDs::error;
	if ($err) { print $errorText . "RRD ERROR: $err" .  $noErrorText . "<p>"; return undef; }

	print "<table border=1 cellspacing=0 cellpadding=3" .
		" style='font-size: 8pt; font-family: sans-serif'>",
		Tr( map { th( b( $_ ) ) } "Time", (@$names) ), "\n";;

	my $now = $start;
	foreach (@$table) {
		print Tr( map { td( {-align=>right}, $_ ) }
			POSIX::strftime("%b&nbsp;%d&nbsp;%H:%M:%S", localtime($now)),
			map { sprintf("%.02f", abs($_)) } @$_
		), "\n";
		$now += $step;
	}
	print "</table>";
}

# --------------------------------------------------------------------------------
# delete image files that are over 10 minutes old

sub houseKeeping
{
	my($dir) = $_[0] || ".";
	my(@files);
	my($cutoff) = time - 3600;			# 3600 seconds ago

	opendir(DIR, $dir);
	@files = grep (/^image-\d+-\d+.$IMAGEFORMAT/, readdir(DIR));
	closedir(DIR);

	foreach (@files) {
		unlink("$dir/$_") if ( (stat("$dir/$_"))[9] < $cutoff);
	}
}

# --------------------------------------------------------------------------------
# graphing support subroutine- returns a sorted list of the keys under each variable

sub varKeys
{
	my($var) = $_[0];
	my(@stuff);

	# expand aliases (they begin and end with a '+' and are comma-separated)

	if ($aliasExpander) {
		foreach (param("s$var")) {
			if (/^\+(.*)\+$/) {
				push(@stuff, split(",", $1));
			}
			else {
				push(@stuff, $_);
			}
		}
	}
	else {
		push(@stuff, param("s$var"));
	}

	if (wantarray) {		# they want a list of variables
		if (grep(/^all$/, @stuff)) {		# all variables
			@stuff = @$var;
		}
#		elsif (grep(/^un-other$/, @stuff)) {	# all but 'Other'
#			@stuff = grep(! /^Other$/, @$var);
#		}
		return @stuff;
	}

	return -1 if (grep(/^(all|un-other)$/, @stuff)); 	# return -1 if all keys are used
	return scalar @stuff;
}

# --------------------------------------------------------------------------------
# graphing support subroutine- smart join (w, x, y and z)

sub sjoin
{
	my $stem;
	my @joins;

	foreach (@_) {
		if (/^(.*?)#(.*)$/) {
			if ($1 eq $stem) { push(@joins, $2); }
			else { $stem = $1; push(@joins, "$1 $2"); }
		}
		else { push(@joins, $_); }
	}

	my($x) = join("\~ ", @joins);
	$x =~ s/\~ ([^\~]+)$/ and $1/;
	$x =~ s/\~/,/g;
	return $x;
}

# --------------------------------------------------------------------------------
# graphing support subroutine- increments and returns variable counters

sub counter
{
	my($var) = $_[0];
	return sprintf("$var%04d", ++${"Counter_$var"});
}

# --------------------------------------------------------------------------------
# convert a date param into a real unixtime stamp

sub hackDate
{
	my($yy, $mm, $dd, $h, $m, $s, $pm);

	return $_[0] if ($_[0] =~ /^\d+$/);
	return (time - 300) if (! $_[0]);

	foreach (split(/\s+/, $_[0])) {
		if (/^(\d+)[\-\/](\d+)[\-\/](\d+)$/) {
			if ($1 > 12)	{ $yy = $1; $mm = $2 - 1; $dd = $3; }
			else		{ $yy = $3; $mm = $1 - 1; $dd = $2; }
		}
		elsif (/^(\d+)\:(\d+)\:(\d+)(am|pm|)$/i) {
			$h = $1; $m = $2; $s = $3; $pm = $4;
		}
		elsif (/^(\d+)\:(\d+)(am|pm|)$/i) {
			$h = $1; $m = $2; $s = 0; $pm = $3;
		}
		elsif (/^(\d+)(am|pm|)$/i) {
			$h = $1; $m = $0; $s = 0; $pm = $2;
		}
		elsif (/^(am|pm)$/) {
			$pm = $1;
		}
	}

	if ($pm =~ /(am|pm)/i) {	# am/pm specified ?
		$h = ($h % 12) + (($pm =~ /pm/i) ? 12 : 0);
	}

	return (($yy) ? timelocal($s, $m, $h, $dd, $mm, $yy) : undef);
}

# --------------------------------------------------------------------------------
# given a matrix variable, return a sorted list of its values
# --------------------------------------------------------------------------------
sub loadMatrixVals
{
	my($file, $matrix) = @_;
	my($fDir, $fMatch, $fStem, $fCache, %values, %xvalues);

	return undef if ($fileReal{$file} !~ /^(.*)\/([^\[]*)([\/\.]\[.*)$/);
	$fDir = $1; $fStem = $2; $fMatch = $3;

	$fMatch = $fStem . $fMatch;		# AgencyApps/[%AgencySubnets]/[AgencyServices].rrd

	$fMatch =~ s/\[\%$matrix\]/([^\.]*)/;	# AgencyApps/([^.]*)/[AgencyServices].rrd

	if ($filePacked{$file}) {
		$fMatch =~ s/\/\[$filePacked{$file}\]//;	# strip packed variable from file stem
	}

	$fMatch =~ s/[\.\/]\[[^\]]*\]/[\.\/][^\.\/]*/g;	# AgencyApps/([^.]*)[./][^./]*.rrd

	$fMatch =~ s/\.\[[^\]]*\]/\.[^\.]*/g;		# AgencyApps/([^.]*)[./][^./]*.rrd

	$fCache = "$graphDir/$file-$matrix.cache";

	if ((stat($fCache))[9] >= (time - 3600)) {	# use cache file
		open(CACHE, $fCache);
		while ( <CACHE> ) { chomp; $values{$_} = 1; }
		close(CACHE);
	}
	else {						# load from directory structure
		if ($fMatch =~ /\//) {				# no dots?  hierarchical
			$fMatch =~ s/\//\\\//g;
#			print "find $fDir/$fStem -name *\.rrd -print<br>\n";
			if ($debug) {
				print "fMatch $fMatch", br, "\n";
				print "find $fDir/$fStem -name *\.rrd -print |", br, "\n";
			}

			open(DIRWALK, "find $fDir/$fStem -name *\.rrd -print |");
			while ( <DIRWALK> ) {
				chomp;
				if (/$fMatch/) { $values{$1} = 1; }
			}
			close(DIRWALK);
		}
		else {						# all files in one directory
			opendir(DIR, $fDir);
			while ($_ = readdir(DIR)) {
				$values{$1} = 1 if (/$fMatch/);
			}
			closedir(DIR);
		}

		if (keys %values) {			# update cache file
			open(CACHE, ">$fCache");
			foreach (keys %values) { print CACHE $_, "\n"; }
			close(CACHE);
		}
	}

	foreach my $v (keys %values) {
		my $x = &cleanMatrix($v);
		$matrixXlate{$x} = $v;
		$xvalues{$x} = 1;
	}

	print "loaded " . (scalar keys %xvalues) . " matrixVals<br>\n" if ($debug);
	return (sort byMatrix keys %xvalues);
}

# --------------------------------------------------------------------------------
# given an ugly piece of a filename, return a better-looking string 
sub cleanMatrix
{
	$_ = $_[0];
	$_ =~ s/%([0-9a-f][0-9a-f])/chr(hex "0x$1")/eg;	# convert %xx back to ascii character

	if (/^(\d+)-(\d+)-(\d+)-(\d+)_(\d+)$/) {	# 192-168-1-0_24 -> 192.168.1.0/24
		return "$1.$2.$3.$4/$5";
	}
	elsif (/^(\d+)-(\d+)-(\d+)-(\d+)$/) {		# 192-168-1-4 -> 192.168.1.4
		return "$1.$2.$3.$4";
	}
	
	return $_;
}

# --------------------------------------------------------------------------------
# given a nice filename, return an ugly one
sub unCleanMatrix
{
	my $foo = $_[0];
	$foo =~ s/[^A-Z^a-z^0-9^\-^\#]/sprintf("%%%2x",ord($&))/ge;
	return $foo;
}

sub byMatrix
{
	# IP or subnet
	if ("$a|$b" =~ /^(\d+)\D(\d+)\D(\d+)\D(\d+)\D?(\d*)\|(\d+)\D(\d+)\D(\d+)\D(\d+)\D?(\d*)$/) {
		return ($1 <=> $6) || ($2 <=> $7) || ($3 <=> $8) || ($4 <=> $9) || ($5 <=> $10);
	}

	if ("$a|$b" =~ /^([^#]+)#(\D+)(\d+)\D?(\d*)\D?(\d*)\D?(\d*)\|([^#]+)#(\D+)(\d+)\D?(\d*)\D?(\d*)\D?(\d*)$/) {
		# 1, router    2, interface type  3-6, numbers

		return (lc $1 cmp lc $7) || (lc $2 cmp lc $8) || ($3 <=> $9) || ($4 <=> $10) || ($5 <=> $11) || ($6 <=> $12);
	}

	return ($a <=> $b) if ("$a$b" =~ /^\d+$/);
	return lc $a cmp lc $b;
}


sub matrixExpand
{
	return $matrixXlate{$_[0]} || $_[0];
}

sub commafy
{
	local $_ = $_[0];

	return $_ if (! /^\d+\.?\d*$/);
	$_ = sprintf("%.02f", $_) if (/\./);
	while (s/^(\d+)(\d{3})/$1,$2/) {}
	return $_;
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

sub paddedCmp
{
	my($a1,$b1) = @_;
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

# strip unwanted garbage from item name. This routine is called for all items, but it (hopefully) only will match
# interface

sub ifDispName
{
	my $x = shift;
	$x =~ s/-aal5 layer//;			# strip -aal
	$x =~ s/-802.1Q vLAN subif//;		# strip -802.1Q
	return $x;
}

