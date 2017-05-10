#!/usr/bin/perl

# ------------------------------------------------
# adhoc.cgi
# Craig Weinhold, Berbee Information Networks Corp
#
#  v2.0   4-02-13  merged adhocForm and adhocResults (no more frames)
#                  added freeform filter, connection reports, calendar for date/time entry
#  v2.01  4-09-13  fixed drill-down and dns display bugs
#
# version history for adhocForm.cgi
#  v1.0   3-01-02  initial version
#  v1.1  10-22-02  changed from liveForm to adhocForm, using flow-report/flow-print as engines
#  v1.2   6-26-03  added ACL filtering and variable flow directories
#  v1.21  6-28-03  added clickable map support
#  v1.22 11-07-03  fixed bug when switching from active to other flows.
#  v1.23  2-05-04  fixed javascript errors
#  v1.24  8-03-04  added dst IP reports and added <nobr> blocks
#  v1.25  4-24-07  added flow/QoS reports, increased accuracy of clickTime, cleaned for strict
#  v1.26  2-22-08  changed calendar to support old day select method, too
#  v1.27  5-01-08  added ASN filtering
#  v1.28  7-10-08  added device/interface popup
#  v1.29  9-20-10  fixed clickFilter persistence across source directory changes
#  v1.30  1-01-12  added support for hierarchical capture directories
#  v1.31  4-03-12  adjusted timestamp analysis to allow overlap
#
# version history for adhocResults.cgi
#  v1.0   10-18-02  initial version (modification of liveResults)
#  v1.01  11-13-02  now does good 'or' clauses with ports and ip addresses
#  v1.02  12-05-02  added DNS resolution and CSV support
#  v1.03  05-29-03  added compound IPs/ports, javascript progress report
#  v1.04  06-26-03  added ACL filtering
#  v1.05  06-27-03  added interface filtering (to support clickable maps)
#  v1.06  08-07-03  added tcp/udp/icmp transform
#  v1.07  02-05-04  fixed javascript error in statusClose()
#  v1.08  08-03-04  added src/dst IP reports and improved output formatting
#  v1.08b 08-04-04  status bar looks better and works with excel/csv output
#  v1.09  08-11-04  eliminated redundant matches that were triggering a flow-tools bug
#  v1.10  07-13-06  changed to use flow-export instead of flow-print
#  v1.11  07-28-06  improved efficiency of perl ACLs (wvFlowCat)
#  v1.12  04-01-07  added qos/flow reports and filters, made 'strict' compliant
#  v1.13  04-30-07  added direct excel spreadsheets with Spreadsheet:WriteExcel
#  v1.14  05-11-07  fixed port matches.
#  v1.15  07-10-08  added device/port output
#  v1.16  07-16-08  minor interface cleanup
#  v1.17  09-20-10  added 'any' interface filters (i.e., filter on exporter only)
#  v1.18  09-09-11  added support for category markup, added better status bar and formatting
#  v1.19  02-07-12  added support for nested directories
#  v1.20  03-16-12  added better exporter reporting; fixed bug in ACL lookup (could confuse ACLs before)
#  v1.21  08-06-12  added 'bps' calculations for eligible traffic (tcp/udp with L4 info)
#  v1.22  10-01-12  fixed display bug with ip-protocol

#
# Presents a form for the adhoc query tool.
# ------------------------------------------------

use Time::Local;
use POSIX;
use Socket;
use CGI qw(:standard :html3 -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use Net::Patricia;
use Storable;
use IO::Handle;
use strict;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $SHOW_ASN = 0;			# set to 1 to show ASN filter options

our $FILEBOXSIZE = 5;			# how many lines to show of flow files in multiple-select

our $sizeOfOneFlow = 17.293728;		# size on disk (assumes compression; used to estimate processing rate)

our $helpURL = "adhocFlow-help.html";
our $filterURL = "getFilter.cgi?field=";

our $datefmtYuck = "%Y-%m-%d %H:%i";
our $datefmt = "%Y-%m-%d %H:%M";

our %acls;
our %fh;

&readIndex;

our %reportTypeFields = (
	# RAW
	'exp' => 'Exporters & interfaces',
	'routing' => 'Routing',
	'asn' => 'ASN',

	# CONNECTION
	'simple' => 'Simple',
	'multihop' => 'Multihop (detail)',

	# FLOW
	'ip' => 'IP',
	'src' => 'Src',
	'dst' => 'Dst',
	'port' => 'Port',
	'peer' => 'Peers',
	'flow' => 'Flows',

	# OTHER
	'exporter' => 'Exporters',
	'bgp' => 'BGP ASN',			# duplicate

	# MENU
	'raw' => 'Raw',
	'connection' => 'Connection',
	'flow' => 'Flow',
	'other' => 'Other',
);

our %reportTypeHtml =  (
	'raw' =>  join('',
		nobr( font( {-size=>'2'},
		checkbox_group(-name=>'reportRaw', -values=>[qw/exp/], -labels=>\%reportTypeFields ), br,
		checkbox_group(-name=>'reportRaw', -values=>[qw/routing asn/], -labels=>\%reportTypeFields ),
		) )
	),

	'connection' =>  join('',
		nobr( font( {-size=>'2'},
		radio_group(-name=>'reportConn', -values=>['simple'], -labels=>\%reportTypeFields, -default=>'simple' ), br,
		radio_group(-name=>'reportConn', -values=>['multihop'], -labels=>\%reportTypeFields, -default=>undef ),
		) )
	),

	'flow' => join('',
		nobr( font( {-size=>'2'},
		radio_group(-name=>'reportFlow', -values=>[qw/ip src dst port/], -labels=>\%reportTypeFields, -default=>undef, -onChange=>'check();' ), br,
		radio_group(-name=>'reportFlow', -values=>[qw/peer flow/], -labels=>\%reportTypeFields, -default=>'flow', -onChange=>'check();' ),
		checkbox(-name=>'totals', -label=>'w/ totals'),
		) )
	),

	'other' => join('',
		nobr( font( {-size=>'2'},
		radio_group(-name=>'reportFlow', -values=>[qw/exporter/], -labels=>\%reportTypeFields, -default=>'exporter', -onChange=>'check();' ), br,
		radio_group(-name=>'reportFlow', -values=>[qw/bgp/], -labels=>\%reportTypeFields, -default=>undef, -onChange=>'check();' ), br,
		) )
	),
);

our $statusWindowHeight = 150;
our $statusWindowWidth = 500;

our $STYLE = <<EOT;
<!--
A:link { text-decoration: underline; color: black; }
A:visited { text-decoration: underline; color: black; }
A:hover {text-decoration: underline; }

span.overlay { color: #888; font-size: 8px; position:absolute; left: 50px; top: 4px; font-family:monospace; }

#results {
        font-family: sans-serif;
        font-size: 8pt;
        empty-cells: show;
	border-collapse:collapse;
}

tr.d0 td {
}

tr.d1 td {
	background-color: #f0f0ff;
}

.d0 {
}

.d1 {
	background-color: #f0f0ff;
}

.ascii {
        white-space: pre;
        font-family: monospace;
        font-size: 8pt;
}
-->
EOT

our $JSCRIPT = <<EOT;
var filterWindow1;
var filterWindow2;
var helpWindow;
var ifWindow;
var lastRtype;

function ifScreen()
{
	if ((typeof ifWindow == "undefined") || (ifWindow.closed)) {
		ifWindow = window.open("adhocIf.cgi", "", "toolbar=yes,location=yes,directories=no,menubar=yes,resizable=yes,scrollbars=yes,width=640,height=480");
	}
	else {
		ifWindow.focus();
	}
}

function helpScreen()
{
    helpWindow = window.open("$helpURL");
}

function getFilter1()
{
	if ((typeof filterWindow1 == "undefined") || (filterWindow1.closed)) {
		filterWindow1 = window.open("$filterURL" + "ip1", "getFilter1", "width=600,height=500,resizable,scrollbars");
	}
	else {
		filterWindow1.focus();
	}
}

function getFilter2()
{
	if ((typeof filterWindow2 == "undefined") || (filterWindow2.closed)) {
		filterWindow2 = window.open("$filterURL" + "ip2", "getFilter2", "width=600,height=500,resizable,scrollbars");
	}
	else {
		filterWindow2.focus();
	}
}

function byebye()
{
	if ((typeof filterWindow1 != "undefined") && (! filterWindow1.closed)) {
		filterWindow1.close();
	}

	if ((typeof filterWindow2 != "undefined") && (! filterWindow2.closed)) {
		filterWindow2.close();
	}

	if ((typeof ifWindow != "undefined") && (! ifWindow.closed)) {
		ifWindow.close();
	}

	if ((typeof helpWindow != "undefined") && (! helpWindow.closed)) {
		helpWindow.close();
	}

	if ((typeof statusWindow != "undefined") && (! statusWindow.closed)) {
		statusWindow.close();
	}
}

function check( )
{
	qcheck();

	var rtype = document.forms['inputForm'].elements['rtype'];
	var sortby = document.forms['inputForm'].elements['sortby'];
	var checked;

	for (var j=0; j<sortby.length; j++) {
		if (sortby[j].checked) { checked = sortby[j].value; break; }
	}

	if (rtype.value != lastRtype) {
		lastRtype = rtype.value;
		var rtypecode = document.getElementById('rtypecode');

		var sbNormal = document.getElementById('sbNormal');
		var sbCount = document.getElementById('sbCount');
		var sbDuration = document.getElementById('sbDuration');
		var sbChronological = document.getElementById('sbChronological');

		switch (rtype.value)
		{
			case 'raw':
				rtypecode.innerHTML = '$reportTypeHtml{raw}';
				sbNormal.style.display = 'none';
				sbCount.style.display = 'none';
				sbDuration.style.display = 'none';
				sbChronological.style.display = '';
				checked = 'time';
				break;

			case 'connection':
				rtypecode.innerHTML = '$reportTypeHtml{connection}';
				sbNormal.style.display = '';
				sbCount.style.display = 'none';
				sbDuration.style.display = '';
				sbChronological.style.display = '';
				if (checked == 'count') { checked = 'octets'; }
				break;

			case 'flow':
				rtypecode.innerHTML = '$reportTypeHtml{flow}';
				sbNormal.style.display = '';
				sbCount.style.display = '';
				sbDuration.style.display = 'none';
				sbChronological.style.display = 'none';
				if ((checked == 'duration') || (checked == 'time')) { checked = 'octets'; }
				break;

			case 'other':
				rtypecode.innerHTML = '$reportTypeHtml{other}';
				sbNormal.style.display = '';
				sbCount.style.display = 'none';
				sbDuration.style.display = 'none';
				sbChronological.style.display = 'none';
				if ((checked == 'count') || (checked == 'duration') || (checked == 'time')) { checked = 'octets'; }
				break;
		}
	}

	if (rtype.value == 'flow') {
		var reportFlow = document.forms['inputForm'].elements['reportFlow'];
		var countOK = 0;
		for (var i=0; i<reportFlow.length; i++) {
			if (reportFlow[i].checked) {
				if (reportFlow[i].value.match(/^(src|dst)\$/)) { countOK=1; break; }
			}
		}

		for (var j=0; j<sortby.length; j++) {
			if (sortby[j].value=='count') { 
				if (countOK) {
					sortby[j].disabled=0;
				}
				else {
					if (sortby[j].checked) { checked = 'octets'; }
					sortby[j].disabled=1;
				}
			}
		}
	}

	for (var j=0; j<sortby.length; j++) {
		sortby[j].checked = (sortby[j].value == checked);
	}
}

function qcheckBlur()		// navigate away from qualifier text entry
{
	var qtext = document.getElementById('qtext');
	var qmenu = document.getElementById('qmenu');
	var qval  = document.forms['inputForm'].elements['qval'];

	if (qval.value.match(/^\s*\$/)) {		// empty value; return to menu
		qtext.style.display='none';
		qmenu.style.display='';
		document.forms['inputForm'].elements['qtype'].selectedIndex=0;
	}
}

function qcheck()
{
	var qmenu = document.getElementById('qmenu');
	var qtext = document.getElementById('qtext');
	var qval  = document.forms['inputForm'].elements['qval'];
	var qoverlay = document.getElementById('qoverlay');

	if (qmenu.style.display=='') {		// qualifier menu is displayed
		if (document.forms['inputForm'].elements['qtype'].selectedIndex == 0) return;

		var v=document.forms['inputForm'].elements['qtype'].value;
		qoverlay.innerHTML=v;
		qoverlay.style.left = 98 - (v.length * 6);
		qtext.style.display='';
		qmenu.style.display='none';
	}
}

function statusOpen()
{
	if ((typeof statusWindow == "undefined") || (statusWindow.closed)) {
		statusWindow = window.open("", "status", "width=$statusWindowWidth,height=$statusWindowHeight");
	}
	else {
		statusWindow.focus();
	}

	statusWindow.document.open();
	statusWindow.document.write('<html><head><title>Report Progress</title></head><body bgcolor="#f0f0ff"><table style="height: 100%; width: 100%; font-size: 12pt; font-face: bold;"><tr valign=middle><td align=center id="status">');
	statusWindow.document.write('</td></tr></table></body></html>');
	statusWindow.document.close();
}

function statusClose()
{
	if ((typeof statusWindow != "undefined") && (! statusWindow.closed)) {
		statusWindow.close();
	}
}

function status( x )
{
	statusWindow.document.getElementById("status").innerHTML = x;
}
EOT

# figure out directories

our @flowDirs = ( sort { $a cmp $b } grep ( ! /^$flowDirArchive$/, keys %flowDirs) );
our $srcdir = param('srcdir') || $flowDirs[0];
our $oldsrcdir = param('oldsrcdir') || $srcdir;

if (! exists $flowDirs{$srcdir}) {
	$srcdir = $flowDirs[0];
	param('srcdir', $srcdir);
}

# figure out available files
our $availFlowFiles = {};
our $sizeFlowFiles = {};

my $calInitJSCRIPT = &readAllFlowFiles( $flowDirs{$srcdir} );
$JSCRIPT .= $calInitJSCRIPT;

# --- if adhoc was called with clickable information, prepopulate fields

our ($clickItem, $clickFoo, $clickGroup, $clickFilter);
our ($defIfCount);

$clickItem = param('item');
$clickFoo = param('foo');
$clickGroup = param('group');
$clickFilter = param('filter');

if ($clickFilter !~ /\:/) {
	my($ip1, $ip2);
	($ip1, $ip2, undef) = split(/;/, $clickFilter);

	param('ip1', $ip1);
	param('ip2', $ip2);
	undef $clickFilter;
}
else {
	param('ifs', $clickFilter) if ($srcdir eq $oldsrcdir);
}

if (my $tIfs = param('ifs')) {
	my $ifCount = ($tIfs =~ tr/,/,/);
	$defIfCount = ($ifCount + 1) . ' interface' . ((! $ifCount) ? 's' : '');
}
else {
	$defIfCount = "choose interfaces";
}

# --- if adhocForm was called with clickable information, force an immediate report

my $onLoad = 'check(); calinit(); statusClose(); timepopulate();';

if (defined $clickItem) {		# immediate response
	param('rtype', 'flow');
	param('reportFlow', 'flow');
	param('go', 'Run Report');
	param('acl', $clickItem);
}

# --- display header info...

print header(),
	start_html(
		-title=>'Webview Ad Hoc Query Tool',

		-script=>[
			{ -src=>'cal/dhtmlxcalendar.js', },
			{ -type=>'text/javascript', -code=>$JSCRIPT, },
		],
		-style=>[
			{ -src=>'cal/dhtmlxcalendar.css' },
			{ -src=>'cal/skins/dhtmlxcalendar_dhx_skyblue.css' },
			{ -code=>$STYLE, },
		],
		-onUnload=>'byebye();',
#		-onLoad=>$onLoad,
	);

#foreach (param()) {
#	print "$_: " . join(', ', param($_)) . "<br>\n";
#}

&showForm;

print <<EOT;
<script type="text/javascript">
$onLoad;
</script>
EOT

print hr;

# ------------------------------------------------
#		START OF RESULTS GLOBALS
# ------------------------------------------------

our($dnsTimeout) = 5;
our($dnsPacing) = 10;

our($trackStatus) = 1;			   # enable status bar
our($delayBeforeStatusWindow) = 2;	       # after 5 seconds
our($startTime) = time;

our (@myFilter, @bigOrs);		# globals

our($debug) = 0;

our(%subnetMasks) = (
	0, 0x00000000, 1, 0x80000000, 2, 0xC0000000, 3, 0xE0000000,
	4, 0xF0000000, 5, 0xF8000000, 6, 0xFC000000, 7, 0xFE000000,
	8, 0xFF000000, 9, 0xFF800000, 10, 0xFFC00000, 11, 0xFFE00000,
	12, 0xFFF00000, 13, 0xFFF80000, 14, 0xFFFC0000, 15, 0xFFFE0000,
	16, 0xFFFF0000, 17, 0xFFFF8000, 18, 0xFFFFC000, 19, 0xFFFFE000,
	20, 0xFFFFF000, 21, 0xFFFFF800, 22, 0xFFFFFC00, 23, 0xFFFFFE00,
	24, 0xFFFFFF00, 25, 0xFFFFFF80, 26, 0xFFFFFFC0, 27, 0xFFFFFFE0,
	28, 0xFFFFFFF0, 29, 0xFFFFFFF8, 30, 0xFFFFFFFC, 31, 0xFFFFFFFE,
	32, 0xFFFFFFFF
);

our ($globalIfs, $globalExpnames, $globalExp);

our(%protocols) = (
	'icmp' => 1,
	'igmp' => 2,
	'tcp' => 6,
	'udp' => 17,
	'rsvp' => 46,
	'gre' => 47,
	'esp' => 50,
	'ah' => 51,
	'eigrp' => 88,
	'ospf' => 89,
	'etherip' => 97,
	'ipip' => 94,
	'pim' => 103,
	'ipcomp' => 108,
	'vrrp' =>  112,
	'l2tp' => 115,
	'isis' =>   124,
	'sctp' => 132,
);

our %iprotocols;

map { $iprotocols{$protocols{$_}} = $_ } keys %protocols;

our(%tosMasks) = (
	"0" => "0x00/0xfc",
	"not 0" => "!0x00/0xfc",
	"ef" => "0xb8/0xfc",

	"af11" => "0x28/0xfc", "af12" => "0x30/0xfc", "af13" => "0x38/0xfc",
	"af21" => "0x48/0xfc", "af22" => "0x50/0xfc", "af23" => "0x58/0xfc",
	"af31" => "0x68/0xfc", "af32" => "0x70/0xfc", "af33" => "0x78/0xfc",
	"af41" => "0x88/0xfc", "af42" => "0x90/0xfc", "af43" => "0x98/0xfc",

	"cs1" => "0x20/0xfc", "cs2" => "0x40/0xfc", "cs3" => "0x60/0xfc",
	"cs4" => "0x80/0xfc", "cs5" => "0xa0/0xfc", "cs6" => "0xc0/0xfc", "cs7" => "0xe0/0xfc",

	"prec 0" => "0x00/0xe0", "prec 1" => "0x20/0xe0", "prec 2" => "0x40/0xe0", "prec 3" => "0x60/0xe0",
	"prec 4" => "0x80/0xe0", "prec 5" => "0xa0/0xe0", "prec 6" => "0xc0/0xe0", "prec 7" => "0xe0/0xe0",
);

our($GLOBAL_PROTOCOL, $GLOBAL_OCTETS, $GLOBAL_DURATION);
our($FMT_ASCII, $FMT_TABLE, $FMT_CSV) = (1, 2, 3);

our(%outputFormat) = (
	'ascii' => $FMT_ASCII,
	'table' => $FMT_TABLE,
	'csv' => $FMT_CSV,
	'excel' => $FMT_CSV,
);

our (%tableStart) = (
	$FMT_TABLE => "<table id=\"results\" border=1 cellpadding=2 cellspacing=0>",
	$FMT_ASCII => "<div class=\"ascii\">"
);

our(%tableEnd) = (
	$FMT_TABLE => "</table>",
	$FMT_ASCII => "</div>"
);

our(%tableRowEven) = (
	$FMT_TABLE => "<tr class=\"d0\">",
	$FMT_ASCII => "<span class=\"d0\">"
);

our(%tableRowOdd) = (
	$FMT_TABLE => "<tr class=\"d1\">",
	$FMT_ASCII => "<span class=\"d1\">"
);

our(%tableRowEnd) = (
	$FMT_TABLE => "</tr>\n",
	$FMT_ASCII => "\n</span>",
	$FMT_CSV => "\n",
);

our(%tableHeaderRowStart) = (
	$FMT_TABLE => "<span class=\"header\">",
	$FMT_ASCII => "<b>",
);

our(%tableHeaderRowEnd) = (
	$FMT_TABLE => "</span>",
	$FMT_ASCII => "</b>",
);


our $IFWIDTH = 14;
our %packedIfs;

our $LOG_DEBUG = 1;
our $LOG_INFO = 2;
our $LOG_TRIVIA = 3;

our $catEnable = 0;
our $dnsEnable = 0;
our $dnsHostOnly;

if (param('dns') =~ /(i?p?\+?)(host|fqdn)/) {
	$dnsHostOnly = ($2 eq "host");
	$dnsEnable = ($1 ne "") ? 1 : 2;		# 2 for clobber IP, 1 for add to IP
}
if (param('cat') =~ /yes/i) {
	$catEnable = 1;
}

our $nameTrie = &loadDaclMaps;

our $outputFmt = $outputFormat{param('output')} || $FMT_TABLE;

# ------------------------------------------------
#		END OF RESULTS GLOBALS
# ------------------------------------------------


if ( param('go') eq 'Run Report' ) {
	if (my $err = &mainReport) {
		print h3($err);
	}

}

&houseKeeping;

print end_html;

exit 0;


# ------------------------------------------------
# ADHOC FORM subroutine
# ------------------------------------------------

sub showForm 
{
	my($bg) = "gray";
	my($fg) = "#d0d0d0";
	my($font) = '<font size=2>';
	my($nofont) = '</font>';

	my($headerStyle) = "font-weight: bold; font-size: 10pt;";
	my($iheaderStyle) = "background-color: gray; font-style: italic; font-weight: bold; font-size: 10pt;";
	my($pheaderStyle) = "background-color: gray; font-style: italic; font-weight: bold; font-size: 9pt;";

	my($bfont) = "<span style=\"$headerStyle\">";
	my($bnofont) = '</span>';

	my($ifont) = "<span style=\"$iheaderStyle\">";
	my($inofont) = '</span>';

	my(%fileLabels) = (
		'active' => '%s',
	);

	my($spacer) = " &nbsp; ";
	my(@flowFiles);

	my @dirs;
	foreach ( @flowDirs ) {
		push(@dirs, $_);
		$fileLabels{$_} = sprintf($fileLabels{'active'}, $_);
	}
#	push(@dirs, $flowDirArchive);
#	push(@dirs, ($srcdir eq $flowDirArchive) ? 'delete' : "copy/$srcdir");

	print start_form(-name=>'inputForm', -method=>'post'),

		# only include the clickFilter if the user is in the originally clicked-into srcdir
		hidden(-name=>'ifs', -default=>(($srcdir eq $oldsrcdir) ? $clickFilter : "") ),
		hidden(-name=>'oldsrcdir', -default=>$oldsrcdir),

		( (defined $clickItem) ? (
			hidden(-name=>'group', -default=>"$clickGroup"),
			hidden(-name=>'foo', -default=>"$clickFoo"),
		) : ''),

		"<table border=0 bgcolor=#FFFFFF>",

			Tr( {-bgcolor=>$bg},
				td( {-align=>'center', -rowspan=>5},
					font( {-size=>5}, b( join('', "Webview", br, "Ad hoc", br, "Query", br, "Tool") ) ) ),

				td( {-align=>'center', -width=>'180px'},
					$ifont, "Report", $inofont ),

				td( {-align=>'center', -colspan=>2},
					$ifont, "Filter on any/all of these fields", $bnofont, $spacer, $spacer, $spacer, $spacer,

					font( {-size=>'2'},
						a( {-id=>'ifSelect', -href=>'javascript:ifScreen()'}, $defIfCount),
					),
				),


				td( {-align=>'center', -colspan=>1}, 
					$ifont, "Sort by", $inofont ),

				td( {-align=>'center', -colspan=>2}, 
					$ifont, "Source flow data ", $inofont, $spacer,

					popup_menu(-name=>'srcdir',
						-style=>$pheaderStyle,
#						-onChange=>"form.target='formFrame'; form.action='adhocForm.cgi'; this.form.submit();",
						-onChange=>"this.form.submit();",
						-values=>\@dirs,
						-labels=>\%fileLabels
					) ),

				td( {-align=>'center', -rowspan=>5},
					"&nbsp;" ),

			),

			"\n",

			Tr( {-bgcolor=>$fg},
				td( {-align=>'center'},
					font( {-size=>'1'}, 'Type: ' ),
					popup_menu(-name=>'rtype',
						-values=>[qw/raw connection flow other/],
						-labels=>\%reportTypeFields,
						-default=>'flow',
						-onChange=>'check();' )
				),

				td( {-colspan=>2, -valign=>'center'},
					"<nobr>",
					table({-border=>0}, Tr(

					td( popup_menu(-name=>'proto',
						-values=>['Proto', 'tcp', 'udp', 'icmp', 'vpn', 'other'],
						-default=>'Proto'
					) ),

					td( popup_menu(-name=>'tos',
						-values=>['ToS',
							"0", "not 0", "ef", "af11", "af12", "af13", "af21", "af22", "af23",
							"af31", "af32", "af33", "af41", "af42", "af43", "cs1", "cs2", "cs3",
							"cs4", "cs5", "cs6", "cs7", "prec 0", "prec 1", "prec 2", "prec 3",
							"prec 4", "prec 5", "prec 6", "prec 7"],
						-default=>'ToS',
					)),

					td( ( (defined $clickItem) ?
						popup_menu(-name=>'acl',
							-values=>['--- ACL ---', (sort byUnderscored keys %acls), 'Other'],
							-default=>$clickItem
						) :
						popup_menu(-name=>'acl',
							-values=>['--- ACL ---', (sort byUnderscored keys %acls) ],
						)
					) ),

					td( {-style=>'width:100px; height:24px;'},
						span({-id=>'qmenu'},
							popup_menu(-name=>'qtype',
								-values=>['Qualifier', 'bytes', 'packets', 'pps', 'bps', 'tos', 'protocol', 'nexthop', 'tcp_flags'],
								-default=>'Qualifier',
								-onchange=>'qcheck();',
								-style=>'width:100%',
							),
						),

						span({-id=>'qtext', -style=>'display:none; position:relative;'},
							textfield(-name=>'qval', -size=>12, -onBlur=>'qcheckBlur();'),
							span({-id=>'qoverlay', -style=>'font-size:8px; color:#888; position:absolute; left:90px; top:4px; font-family:monospace;' }, ),
						),
					)
					) ),

					"</nobr>"
				),

				td( {-rowspan=>'3'},
					font( {-size=>'2'},
					"<nobr>",
					span({-id=>'sbNormal'},
						radio_group(-name=>'sortby',
							-values=>['octets', 'packets', 'flows'],
							-labels=>{'octets'=>'bytes'},
							-linebreak=>1,
							-default=>'octets')
					),

					span({-style=>"display:none", -id=>'sbCount'},
						radio_group(-name=>'sortby',
							-values=>['count'],
							-labels=>{'count' => 'peers'},
							-linebreak=>1,
							-default=>undef)
					),

					span({-style=>"display:none", -id=>'sbDuration'},
						radio_group(-name=>'sortby',
							-values=>['duration'],
							-linebreak=>1,
							-default=>undef)
					),

					span({-style=>"display:none", -id=>'sbChronological'},
						radio_group(-name=>'sortby',
							-values=>['time'],
							-linebreak=>1,
							-default=>undef)
					),

					"</nobr>"
				) ),

				td( {-colspan=>2, -rowspan=>3, -valign=>'center', -align=>'left'},
					font( {-size=>'2'},
						radio_group(-name=>'last',
							-values=>[qw/5 15 60/],
							-labels=>{5 => '5-min', 15 => '15-min', 60 => '60-min'},
							-onChange=>'timepopulate();',
						),

						radio_group(-name=>'last',
							-values=>[0],
							-labels=>{0 => 'custom'},
							-onChange=>'timepopulate();',
						),

						table( {-border=>0},
							Tr( td({-align=>'right'}, 'start:'), td( textfield(-name=>'time1', -size=>14, -id=>'cal1') ) ),
							Tr( td({-align=>'right'}, 'end:'), td( textfield(-name=>'time2', -size=>14, -id=>'cal2') ) ),
						),
					)
				),
			),
			"\n",

			Tr( {-bgcolor=>$fg},

				td( {-rowspan=>'2'}, div({-id=>'rtypecode'} ),
				),

				td( {-valign=>'center', -align=>'right'},
					"<nobr>",
					font( {-size=>'1'},
						checkbox_group(-name=>'ip1dir',
							-values=>['Src', 'Dst'],
							-defaults=>['Src', 'Dst']),
					),

					font( {-size=>'2'},
						( ($SHOW_ASN)  ?
							"&nbsp;" .
							a( {-href=>'javascript:getFilter2();'}, "ASN:") .
							textfield(-name=>'asn1', -size=>5)
							: ""
						),

						"&nbsp;",
						a( {-href=>'javascript:getFilter2();'}, "IP:"),
						textfield(-name=>'ip1', -size=>24),

						"port:",
						textfield(-name=>'port1', -size=>12),
					),
					"</nobr>",
				),
			),
			"\n",

			Tr( {-bgcolor=>$fg},
				td( {-valign=>'center', -align=>'right'},
					"<nobr>",
					font( {-size=>'1'},
						checkbox_group(-name=>'ip2dir',
							-values=>['Src', 'Dst'],
							-defaults=>['Src', 'Dst']
						),
					),

					font( {-size=>'2'},

						( ($SHOW_ASN)  ?
							"&nbsp;" .
							a( {-href=>'javascript:getFilter2();'}, "ASN:") .
							textfield(-name=>'asn2', -size=>5)
							: ""
						),

						"&nbsp;",
						a( {-href=>'javascript:getFilter2();'}, "IP:"),
						textfield(-name=>'ip2', -size=>24),

						"port:",
						textfield(-name=>'port2', -size=>12),
					),
					"</nobr>",
				),

			),
			"\n",

			Tr( {-bgcolor=>$bg},
				td( {-align=>'center', -colspan=>8},

					submit(-name=>'go', -value=>'Run Report'),
					$spacer,

					button(-value=>'Help', -onClick=>'helpScreen();'),
					$spacer,

					button(-value=>'Home', -onClick=>"top.location=\"$rootDirURL\""),
					$spacer,

					$ifont, "Output: ", $inofont,
					radio_group(-name=>'output',
						-values=>['table', 'ascii', 'csv', 'excel'],
						-default=>'table'),

					$spacer,
					$ifont, "Lines: ", $inofont,
					popup_menu(-name=>'lines',
						-values=>['20', '50', '100', '500', '2000', '5000', 'all'],
						-default=>'100'),

					$spacer,
					$ifont, "DNS: ", $inofont,
					popup_menu(-name=>'dns',
						-values=>['none', 'host', 'ip+host', 'fqdn', 'ip+fqdn'],
						-default=>'ip+fqdn'),

					$spacer,
					$ifont, "Category: ", $inofont,
					popup_menu(-name=>'cat',
						-values=>['no', 'yes'],
						-default=>'yes'),
				),
				end_form,
			),
			"\n",

		"</table>";
}

# --------------------------------------------------------------------------------
# read in index file -- just for the list of ACL's

sub readIndex
{
	my($reading);

	open(IN, $indexFile);
	while ( <IN> ) {
		chomp;

		if (/^\s*\[([^\]]+)\]\s*$/) {		# bracketed section
			$reading = $1;			#   the variable in the brackets
		}
		elsif ($reading =~ /ACLs/i) {
			if (/^(ACL_)(\S+)\t(.*)/) {		# only grab "clean" ACLs
				$acls{$2} = 1;
			}
		}
	}
	close(IN);
}

# --------------------------------------------------------------------------------
# recursively look for flow capture files

sub readRecursiveDir
{
	my ($dir, $files) = @_;
	opendir(DIR, $dir); my @tfiles = readdir(DIR); closedir(DIR);

	foreach (@tfiles) {
		if (/^ft-v05/) { push(@$files, "$dir/$_"); }
		elsif ( (! /^\./) && (-d "$dir/$_") ) { &readRecursiveDir("$dir/$_", $files); }
	}
}

# --------------------------------------------------------------------------------
# read all flow files and generate a javascript calendar of valid dates

sub readAllFlowFiles
{
	my $rootdir = shift;
	my $cachefile = $rootdir;
	$cachefile =~ tr/\//./;
	$cachefile = $tempDir . '/' . $cachefile . '.cache';
	my $maxcacheage = 300;

	if (-f $cachefile) {
		my $cachefileage = (stat($cachefile))[9];
		my $rootdirage = (stat($rootdir))[9];

		if ( ($cachefileage >= $rootdirage) && ($cachefileage > (time - $maxcacheage)) ) {
			# load cache
			open(IN, $cachefile);
			while ( <IN> ) {
				if (/^(\d+),(\d+),(\S+)/) {
					$availFlowFiles->{$1} = $3;
					$sizeFlowFiles->{$1} = $2;
				}
			}
			close(IN);
		}
	}

	if (! %$availFlowFiles) {
		my @files;
		&readRecursiveDir($rootdir, \@files);

		foreach ( @files) {
			next if (! /ft-v05.(\d{4})-(\d\d)-(\d\d)\.(\d\d)(\d\d)(\d\d)/);
			$availFlowFiles->{ timelocal( $6, $5, $4, $3, $2 - 1, $1 - 1900 ) } = $_;
		}

		open(OUT, ">$cachefile.tmp");
		foreach ( sort { $a <=> $b} keys %$availFlowFiles ) {
			print OUT $_ . "," . (-s $availFlowFiles->{$_}) . "," . $availFlowFiles->{$_} . "\n";
		}
		close(OUT);
		my $err = `mv -f $cachefile.tmp $cachefile`;
	}

	# prepare calendar structure
	my @times = sort {$a <=> $b} keys %$availFlowFiles;
	my $last = $times[$#times];
	my $cutoff = $last - 365 * 86400;		# only go back one year, max.

	# figure out calendar
	my (@first, @last, %last1, %last2);
	my @insensitive;

	foreach (@times) {
		next if ($_ < $cutoff);
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($_);
		if (! @first) {
		 	@first = ($year + 1900, $mon, $mday);
		}
		@last = ($year + 1900, $mon, $mday);
	}
	# it'd be nice to calculate @insensitive dates within this range. something for the future...

	$last1{5} = $last; $last2{5} = $last + 300;
	$last1{15} = $last - 600; $last2{15} = $last + 300;
	$last1{60} = $last - 3300; $last2{60} = $last + 300;

	map { $last1{$_} = POSIX::strftime($datefmt, localtime($last1{$_})) } keys %last1;
	map { $last2{$_} = POSIX::strftime($datefmt, localtime($last2{$_})) } keys %last2;

	my $sfirst = join(',', @first);
	my $slast = join(',', @last);

	# generate calendar initialization jscript
	my $jscript = <<EOT;
// $last
function calinit()
{
	var mycals = new dhtmlXCalendarObject(["cal1","cal2"]);
	mycals.setWeekStartDay(7);
	mycals.setDateFormat("$datefmtYuck");
//	mycals.setPosition('right');
	mycals.setSensitiveRange(new Date($sfirst), new Date($slast));
//	mycals.setInsensitiveDays(new Date(2013,02,20));
}

function timepopulate( )
{
	var last = document.forms['inputForm'].elements['last'];
	var time1 = document.forms['inputForm'].elements['time1'];
	var time2 = document.forms['inputForm'].elements['time2'];
	var checked;

	for (var j=0; j<last.length; j++) {
		if (last[j].checked) { checked = last[j].value; break; }
	}

	time1.disabled = (checked != 0);
	time2.disabled = (checked != 0);

	if (checked == 5) { time1.value='$last1{5}'; time2.value='$last2{5}'; }
	else if (checked == 15) { time1.value='$last1{15}'; time2.value='$last2{15}'; }
	else if (checked == 60) { time1.value='$last1{60}'; time2.value='$last2{60}'; }
}

EOT

	if (&hackTime(param('time1'))) {
		param('last', 0);
	}
	elsif (! param('last')) {
		param('last', 5);
	}

	if (my $last = param('last')) {
		param('time1', $last1{$last});
		param('time2', $last2{$last});
	}

	return $jscript;
}

sub byUnderscored
{
	my $a1 = $a =~ tr/_/_/;
	my $b1 = $b =~ tr/_/_/;
	return ($a1 cmp $b1) || ($a cmp $b);
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

# ==============================================================================
#                              R U N    R E P O R T
# ==============================================================================

sub mainReport
{
	my($bg) = "gray";
	my($fg) = "#d0d0d0";
	my($matchIP1, $matchIP2, $matchPorts1, $matchPorts2);
	my($matchDir1, $matchDir2, $matchDirP);
	my($matchProtocol, $matchFreeForm);
	my($matchIfs);
	my($matchTosMask, $matchTosVal, $matchTosInvert);
	my($reportMode, $sortBy, $outputStyle, $displayLines);
	my(@myFiles);

	# CGI variables
	#
	# ip	    - ip/mask filter (ip address)
	# port	  - port filter (0-255)
	# dir	   - direction (source, dest, either)
	# proto	 - protocol (tcp, udp, icmp)
	# reports       - 'raw flows', 'ip', 'port', 'peers'
	# sortby	- sort by octets, packets, flows, time, bps, pps
	# lines	 - how many lines to display
	# output	- 'table' or 'ascii'
	# dns	   - checked or not
	# acl	   - name of acl from index file
	#
	# ------------------------------------------------

	# -------------------------
	#  PARSE PASSED PARAMETERS
	# -------------------------

	if (my $err=&parseIP('ip1', \$matchIP1)) { return $err; }
	if (my $err=&parseIP('ip2', \$matchIP2)) { return $err; }

	if (my $err=&parsePorts('port1', \$matchPorts1)) { return $err; }
	if (my $err=&parsePorts('port2', \$matchPorts2)) { return $err; }

	$matchIfs = [split(/\s*[,;]\s*/, param('ifs'))];

	# ---- parse protocol (default = any)
	$matchProtocol = &hackParam('proto', { -tcp=>6, -udp=>17, -icmp=>1,
		-other=>-1, -Protocol=>0, -any=>0, -default=>0 });

	# ---- parse freeform information
	my $matchFreeForm = &hackFreeForm('qtype', 'qval');

	# ---- parse direction (default = either)
	$matchDir1 = &hackDir('ip1dir');
	$matchDir2 = &hackDir('ip2dir');

	($matchTosVal, $matchTosMask, $matchTosInvert) = &hackTos(param('tos'));

	# --- PARSE REPORT VARIABLES
	my $reportType = param('rtype');		# raw connection flow exporter security
	my $reportFlowType;
	my $reportConnType;
	my $reportRawType = {};

	my $reportFlow = param('reportFlow');
	my @reportRaw = param('reportRaw');

	if ($reportType eq 'raw') {
		$reportRawType->{basic} = 1;
		$reportRawType->{dns} = 1 if ($dnsEnable);
		$reportRawType->{dnsclobber} = 1 if ($dnsEnable == 2);
		$reportRawType->{cat} = 1 if ($catEnable);

		foreach (@reportRaw) {
			if (/(exp|routing|asn)/) { $reportRawType->{$_} = 1; }
			else { print STDERR "invalid reportRaw @reportRaw\n"; undef $reportType; }
		}
	}
	elsif ($reportType eq 'connection') {
		if (param('reportConn') eq 'simple') { $reportConnType = 'simple'; }
		elsif (param('reportConn') eq 'multihop') { $reportConnType = 'multihop'; $matchIfs = [] if (@$matchIfs == 1); }
		else { undef $reportType; }
	}
	elsif ($reportType eq 'flow') {
		if ($reportFlow eq 'ip') { 	$reportFlowType = "ip-address";	}
		elsif ($reportFlow eq 'src') {	$reportFlowType = "ip-source-address-destination-count"; }
		elsif ($reportFlow eq 'dst') {	$reportFlowType = "ip-destination-address-destination-count"; }
		elsif ($reportFlow eq 'port') {	$reportFlowType = "ip-port"; }
		elsif ($reportFlow eq 'peer') { $reportFlowType = "ip-source/destination-address"; }
		elsif ($reportFlow eq 'flow') { $reportFlowType = "ip-source/destination-address/ip-protocol/ip-tos/ip-source/destination-port"; }
		else { undef $reportFlow; }
	}
	elsif ($reportType eq 'other') {

		if ($reportFlow eq 'asn') {	$reportType = 'flow'; $reportFlowType = "source/destination-as"; }
		elsif ($reportFlow eq 'exporter') { $reportType = 'exporter'; }
	}
	else {
		undef $reportType;
	}


	# --- sort by type (default = bps)
	$sortBy = param('sortby');
	if ($sortBy !~ /^(octets|packets|flows|count|duration|time)$/) { $sortBy = 'octets'; }

	if ( ($sortBy eq "count") && ($reportFlowType !~ /count/) ) {
		$sortBy = 'octets';
	}
	elsif ( ($sortBy =~ /^(duration|time)$/) && ($reportType ne 'connection') ) {
		$sortBy = 'octets';
	}

	# --- extract ACL
	my $acl = param('acl');

	if (($acl =~ /^\s*$/) || ($acl =~ /(ACL|Category)/)) {
		undef $acl;
	}
	elsif (param('group') && param('foo')) {
		$acl = &findACL( param('foo'), param('group'), $acl );

#		$acl = 'Strict:' . param('foo') . ':' . param('group') . ':' . $acl;
	}
	else {
		$acl = "ACL_$acl";
	}
	# else simple ACL

	# --- view totals?
	my $includeTotals = (param('totals') =~ /on/i);

	# --- how many display lines
	$displayLines = param('lines');
	if (($displayLines =~ /all/i) || ($reportType eq 'exporter')) {
		undef $displayLines;
		$displayLines = 20000 if ((! defined $displayLines) && (param('output') eq 'excel'));
	}
	else {
		$displayLines = int($displayLines) || 100;
	}

	# --- parse the filename and where we are in it

	my $time1 = &hackTime(param('time1'));
	my $time2 = &hackTime(param('time2'));

	foreach (sort {$a <=> $b} keys %$availFlowFiles) {
		push(@myFiles, $availFlowFiles->{$_}) if (($_ + (0.75 * $period) >= $time1) && ($_ <= $time2));
	}

	if (! @myFiles) {
		print "<font color=red>No flow files available in that time range</font>\n";
		return;
	}

	my $tReportFile = "$tempDir/flow-report.$$.input";
	my $tOutputFile = "$tempDir/flow-report.$$.output";
	my $tFilterFile = "$tempDir/flow-report.$$.filter";
	my $tErrorFile = "$tempDir/flow-report.$$.error";
	my $tStatusFile = "$tempDir/flow-report.$$.status";
	my $tAltStatusFile = "$tempDir/flow-report.$$.altstatus";
	my $tCsvFile = "$tempDir/flow-report.$$.csv";


#	print header(), start_html( -style=>{'code' => $STYLE}, -script=>$JSCRIPT, -onLoad=>'statusClose();' );

	# --- display debug info in an HTML comment
	print (($debug) ? "<pre>" : "<!--\n");

		print <<EOT;
\$reportType = $reportType
\$reportConnType = $reportConnType
\$reportFlowType = $reportFlowType
EOT
		print "\%reportRawType{" . join(', ', map { $_ . '=' . $reportRawType->{$_} } keys %$reportRawType) . "}\n";

		print "matchPorts1=" . join(', ', map { ($_->{not} ? "!" : "") . $_->{port} } @$matchPorts1) . "\n";
		print "matchPorts2=" . join(', ', map { ($_->{not} ? "!" : "") . $_->{port} } @$matchPorts2) . "\n";
		print "matchDir1=$matchDir1 matchIP1=" . join(', ', map { ($_->{not} ? "!" : "") . &integer2IP($_->{ip}) . '/' . &integer2IP($_->{mask}) } @$matchIP1) . "\n";
		print "matchDir2=$matchDir2 matchIP2=" . join(', ', map { ($_->{not} ? "!" : "") . &integer2IP($_->{ip}) . '/' . &integer2IP($_->{mask}) } @$matchIP2) . "\n";
		print "matchIfs=" . join(', ', @$matchIfs) . "\n";
		print "matchProtocol=$matchProtocol matchTos=$matchTosVal/$matchTosMask matchTosInvert=$matchTosInvert\n";
		print "matchFreeForm=$matchFreeForm\n";
		print "  qtype=" . param('qtype') . "  qval=" . param('qval') . "\n";
		print "matchACL=" . ((defined $acl) ? $acl : "undef") . "\n";
		print "foo=" . param('foo') . ", group=" . param('group') . "\n";
		print "sortBy=$sortBy includeTotals=$includeTotals displayLines=$displayLines outputFmt=$outputFmt\n";
		print "files=@myFiles\n";
	print (($debug) ? "</pre>" : "-->\n");

	# optionally create the filter
	undef $tFilterFile if (! &createFilterFile($tFilterFile,
		$matchProtocol, $matchPorts1, $matchPorts2, $matchIfs,
		$matchDir1, $matchIP1, $matchDir2, $matchIP2, $matchFreeForm,
		$matchTosVal, $matchTosMask, $matchTosInvert));

	my $fh;

	if ($outputFmt == $FMT_CSV) {
		open(CSV, ">$tCsvFile");
		$fh = *CSV;
	}
	else {
		$fh = *STDOUT;
	}

	if ($reportType eq 'raw') {			# raw dump
		($globalIfs, $globalExpnames) = &loadInterfaces;

		&runRaw($fh, $tFilterFile, $tOutputFile, $tStatusFile, $displayLines, $reportRawType, $acl, @myFiles);
	}

	elsif ($reportType eq 'flow') {			# flow report
		# create the report file
		&createReportFile($tReportFile, $tOutputFile, $reportFlowType, $sortBy, $displayLines, $includeTotals);

		# run the report
		&runReport($tReportFile, $tFilterFile, $tErrorFile, $tStatusFile, $tAltStatusFile, $tOutputFile, $acl, undef, @myFiles);
		&dumpFile($tOutputFile) if ($debug);

		# output the report
		&reportOutput($fh, $tOutputFile);
	}

	elsif ($reportType eq 'exporter') {
		($globalIfs, $globalExpnames) = &loadInterfaces;

		# run the report
		&runReport(undef, $tFilterFile, $tErrorFile, $tStatusFile, $tAltStatusFile, $tOutputFile, $acl, "$flowCheck --sort=$sortBy", @myFiles);
		&dumpFile($tOutputFile) if ($debug);

		# output the report
		$dnsEnable = $catEnable = 0;
		&reportOutput($fh, $tOutputFile, 1);
	}
	elsif ($reportType eq 'connection') {
		($globalIfs, $globalExpnames) = &loadInterfaces;

		# run the report
		&runReport(undef, $tFilterFile, $tErrorFile, $tStatusFile, $tAltStatusFile, $tOutputFile, $acl, "$flowConn --sort=$sortBy --type=$reportConnType --top=$displayLines", @myFiles);
		&dumpFile($tOutputFile) if ($debug);

		# output the report
#		$dnsEnable = $catEnable = 0;
		&reportOutput($fh, $tOutputFile, 1);
	}
	else {						  # generate a nice report
	}

	if ($outputFmt == $FMT_CSV) {
		close(CSV);

		my $ofile;

		if ( param('output') =~ /excel/i ) {		# Excel
			$ofile = "flow-report.$$.xls";
			&excelIt($tCsvFile, "$graphDir/$ofile");
		}
		else {						# CSV
			$ofile = "flow-report.$$.csv";
			`cp -p $tCsvFile $graphDir/$ofile`;
		}
		print <<EOT;
<script type="text/javascript">
window.open("$graphDirURL/$ofile","Download");
</script>
EOT
	}

	return undef;
}

sub excelIt
{
	my ($ifile, $ofile) = @_;

	use Spreadsheet::WriteExcel;

	my @results;
	open(IN, $ifile);
	while ( <IN> ) {
		chomp;
		push(@results, [ split (',') ]);
	}
	close(IN);
	push(@results, []);

	my $workbook  = Spreadsheet::WriteExcel->new($ofile);
	my $worksheet = $workbook->add_worksheet();
	my $format = $workbook->add_format();
	$format->set_bold();

	while (@results) {
		last if (@{$results[0]} > 2);		# header/total lines to end
		push(@results, shift @results);
	}

	my %width;

	for (my $row=0; $row<@results; $row++) {
		my $col = 0;

		map {
			$width{$col} = length($_) if (length($_) > $width{$col});
			$worksheet->write($row, $col++, $_, ($row == 0) ? $format : undef);
		} @{$results[$row]};
	}

	for (my $col=0; $col<100; $col++) {
		last if (! exists $width{$col});
		$worksheet->set_column($col, $col, $width{$col});
	}
	
	$workbook->close();
}

# -------------------------
#   CREATE FILTER FILE
# -------------------------

sub createFilterFile
{
	my ($tFilterFile, $matchProtocol, $matchPorts1, $matchPorts2, $matchIfs,
		$matchDir1, $matchIP1, $matchDir2, $matchIP2, $matchFreeForm,
		$matchTosVal, $matchTosMask, $matchTosInvert) = @_;

	if (! (
		($matchProtocol)					# 0 = any
		|| (defined $matchTosVal)
		|| (defined $matchFreeForm)
		|| ((defined $matchPorts1) && (@$matchPorts1))
		|| ((defined $matchPorts2) && (@$matchPorts2))
		|| ((defined $matchIfs) && (@$matchIfs))
		|| ((defined $matchIP1) && (@$matchIP1))
		|| ((defined $matchIP2) && (@$matchIP2))
	) ) {
		print STDERR "no filter\n";
		return 0;
	}

	my($myIP, $myMask, $first);
	print STDERR "writing $tFilterFile<br>\n";  #  if ($debug);

	open(OUT, ">$tFilterFile");
	print OUT "# filter config file\n\n";

	if (defined $matchFreeForm) {
		my $fftype = shift @$matchFreeForm;
		my $primitive = uc('FF' . $fftype);

		if ($fftype =~ /(bytes|packets|flows)/) {
			$fftype = 'octets' if ($fftype eq 'bytes');
			print OUT "filter-primitive $primitive\n";
			print OUT " type counter\n";
			foreach (@$matchFreeForm) { print OUT " permit " . $_->{counter} . "\n"; }
		}
		elsif ($fftype =~ /(pps|bps)/) {
			print OUT "filter-primitive $primitive\n";
			print OUT " type double\n";
			foreach (@$matchFreeForm) { print OUT " permit " . $_->{counter} . "\n"; }
		}
		elsif ($fftype eq 'protocol') {
			my($deny, $stuff) = &intprimitive($matchFreeForm, $primitive, 'ip-protocol', $fftype);
			print OUT $stuff . "\n";
		}
		elsif ($fftype eq 'tcp_flags') {
			$fftype = 'ip-tcp-flags';
			print OUT "filter-primitive $primitive\n";
			my $f = shift @$matchFreeForm;
			print OUT <<EOT;
 type ip-tcp-flags
 permit $f/0xff
EOT
		}
		elsif ($fftype eq 'nexthop') {
			$fftype = 'ip-nexthop-address';
			my($stuff, $lastNot) = &ipprimitive($matchFreeForm, $primitive);
			print OUT $stuff . "\n";
		}
		elsif ($fftype eq 'tos') {
			$fftype = 'ip-tos';
			print OUT "filter-primitive $primitive\n";
			print OUT " type ip-tos\n";

			my $tosp = shift @$matchFreeForm;
			foreach my $mask (keys %$tosp) {
				foreach my $val (keys %{$tosp->{$mask}}) {
					print OUT " permit $val/$mask\n";
				}
			}
		}

		push(@myFilter, "match $fftype $primitive");
	}

# ----------------------------------------------------------

	if ($matchProtocol > 0) {		       # filter by protocol
		print OUT <<EOT;
filter-primitive PROTOCOL
 type ip-protocol
 permit $matchProtocol

EOT
		push(@myFilter, "match ip-protocol PROTOCOL");
	}
	elsif ($matchProtocol < 0) {		    # filter all common protocols
		print OUT <<EOT;
filter-primitive PROTOCOL
 type ip-protocol
 deny 1,6,17
 default permit

EOT
		push(@myFilter, "match ip-protocol PROTOCOL");
	}

	if (defined $matchTosVal) {			# filter by ToS
		if (! $matchTosInvert) {
			print OUT <<EOT;
filter-primitive TOS
 type ip-tos
 mask $matchTosMask
 permit $matchTosVal

EOT
		}
		else {
			print OUT <<EOT;
filter-primitive TOS
 type ip-tos
 mask $matchTosMask
 deny $matchTosVal
 default permit

EOT
		}

		push(@myFilter, "match ip-tos TOS");
	}

	if ((defined $matchIfs) && (@$matchIfs)) {
		my $lastip;
		my $count = 0;
		my $any;

		foreach (sort {$a cmp $b} @$matchIfs) {
			next if (! /^([\d\.]+)\:(\d+)$/);
			my($ip, $if) = ($1, $2);

			if ($ip ne $lastip) {
				$lastip = $ip;
				$count++;

				print OUT <<EOT;

filter-primitive ExporterIP$count
 type ip-address
 permit $ip
EOT
				if ($if eq '0') {			# any interface
					$any = 1; 

					push(@bigOrs,
						" match ip-exporter-address ExporterIP$count\n"
					);
				}
				else {					# one or more specific interfaces
					$any = 0;

					push(@bigOrs,
						" match ip-exporter-address ExporterIP$count\n" .
						" match input-interface ExporterIF$count\n",

						" match ip-exporter-address ExporterIP$count\n" .
						" match output-interface ExporterIF$count\n",
					);
					print OUT <<EOT
filter-primitive ExporterIF$count
 type ifIndex
EOT
				}
			}
			if (! $any) {
				print OUT <<EOT;
 permit $if
EOT
			}
		}
	}

	if ((defined $matchIP1) && (@$matchIP1)) { print OUT &ipfilter($matchIP1, '1', $matchDir1); }
	if ((defined $matchIP2) && (@$matchIP2)) { print OUT &ipfilter($matchIP2, '2', $matchDir2); }
	if ((defined $matchPorts1) && (@$matchPorts1)) { print OUT &portfilter($matchPorts1, '1', $matchDir1); }
	if ((defined $matchPorts2) && (@$matchPorts2)) { print OUT &portfilter($matchPorts2, '2', $matchDir2); }

	print OUT "filter-definition myFilter\n";
	print OUT &goofyOr($matchDir1, $matchDir2, @myFilter);
	close(OUT);

	&dumpFile($tFilterFile) if ($debug);
	return 1;

# ------------------------------------------------------------

	sub ipprimitive
	{
		my($ipArray, $name) = @_;
		my($stuff, $lastNot, $anyNot);

		$stuff .= <<EOT;
filter-primitive $name
 type ip-address-mask
EOT
		foreach (sort {$b->{not} <=> $a->{not}} @$ipArray) {
			my $myIP = &integer2IP($_->{ip});
			my $myMask = &integer2IP($_->{mask});

			$stuff .= join(" ", "", (($_->{not}) ? "deny" : "permit"), $myIP, $myMask) . "\n";
			$lastNot = $_->{not};
			$anyNot |= $_->{not};
		}
		$stuff .= " permit 0.0.0.0 0.0.0.0\n" if ($lastNot);
		$stuff .= "\n";

		return ($stuff, $lastNot);
	}

	sub ipfilter
	{
		my($ipArray, $which, $myDir) = @_;
		my($stuff, $lastNot) = &ipprimitive($ipArray, "IPADDR$which");

		if (($lastNot) && ($myDir == 0)) {	       # if 'NOT' is used, create an 'AND' clause
			push(@myFilter, "match ip-source-address IPADDR$which");
			push(@myFilter, "match ip-destination-address IPADDR$which");
		}
		else {					  # otherwise, use a normal 'OR' clause
			push(@myFilter, "match ip-DIR$which-address IPADDR$which");
		}
		return $stuff;
	}

	sub intprimitive
	{
		my($intArray, $name, $type, $keyval, $myDir) = @_;
		my ($stuff, @deny, @permit);

		$stuff .= <<EOT;
filter-primitive $name
 type $type
EOT
		foreach (@$intArray) {
			if ($_->{not})	{ push(@deny, $_->{$keyval}); }
			else		{ push(@permit, $_->{$keyval}); }
		}

		if ((@deny) && ($myDir == 0)) {					# AND'd
			$stuff .= " deny " . join(",", @deny) . "\n";
			if (@permit) {
				$stuff .= " permit " . join(",", @permit) . "\n";
			}
			else {
				$stuff .= " default permit\n";
			}
		}
		else {								# OR'd
			$stuff .= " permit " . join(",", @permit) . "\n";
		}
		return ((scalar @deny), $stuff);
	}

	sub portfilter
	{
		my($portArray, $which, $myDir) = @_;
		my $name = "PORT$which";

		my($deny, $stuff) = &intprimitive($portArray, $name, "ip-port", 'port', $myDir);

		if (($deny) && ($myDir == 0)) {					# AND'd
			push(@myFilter, "match ip-source-port PORT$which");
			push(@myFilter, "match ip-destination-port PORT$which");
		}
		else {								# OR'd
			push(@myFilter, "match ip-DIR$which-port PORT$which");
		}
		return $stuff . "\n";
	}

	sub counterfilter
	{
		my($counterArray) = shift;
		foreach (@$counterArray) {
			if ($_->{port} =~ /([\>\<\=])\s*()/) { } 
		}
	}
}

sub goofyOr
{
	my($matchDir1, $matchDir2, @clauses) = @_;
	my(@globals, @goofies, @ors, $level);

	sub goofyRecursion
	{
		my($myGoofies, $where, @previous) = @_;
		my($myDir, $englishDir, $tClause, $match, $substDir);
		my($clause) = $myGoofies->[$where];

		if (! defined $clause) {		# end of the rope
			$level--;
			push(@ors, join("", @previous, @globals));
			return;
		}

		return if ($clause !~ /-(DIR[12])-/);
		$substDir = $1;
		if ($substDir eq "DIR1") { $match = $matchDir1; }
		elsif ($substDir eq "DIR2") { $match = $matchDir2; }
		else { $match = 0; }

		foreach $myDir (-1, 1) {
			$englishDir = ($myDir > 0) ? "source" : "destination";

			if (($match == 0) || ($match == $myDir)) {
				$tClause = $clause;
				$tClause =~ s/$substDir/$englishDir/;

				&goofyRecursion($myGoofies, $where+1, @previous, $tClause) if (&unique($tClause, @previous));
			}
		}
	}

	foreach (@clauses) {
		if (/-DIR[P12]-/) { push(@goofies, " $_\n"); }
		else { push(@globals, " $_\n"); }
	}

	&goofyRecursion(\@goofies);

	foreach my $or (@ors) {
		foreach (split (/\n/, $or) ) {
		}
	}

	if (@bigOrs) {
		my @massiveOrs;
		foreach my $b (@bigOrs) {
			foreach my $o (@ors) {
				push(@massiveOrs, $b . $o);
			}
		}
		@ors = @massiveOrs;
	}

	return join(" or\n", @ors);
}

sub unique
{
	my ($c, @clauses) = @_;

	$c =~ s/\s\S+$//;
	foreach (@clauses) {
		s/\s\S+$//;
		return 0 if ($c eq $_);
	}
	return 1;
}


# -------------------------
#    CREATE REPORT FILE
# -------------------------

sub createReportFile
{

	my($tReportFile, $tOutputFile, $reportType, $sortBy, $displayLines, $includeTotals) = @_;

	print "writing $tReportFile<br>\n" if ($debug);
	open(OUT, ">$tReportFile");
	print OUT <<EOT;
# stat config file

EOT

	print OUT <<EOT;
stat-report myStuff
 type $reportType
 output
  path $tOutputFile
EOT
	print OUT "  options +totals\n" if ($includeTotals);
	print OUT "  sort +$sortBy\n" if ($reportType !~ /summary/);
	print OUT "  records " . $displayLines . "\n" if ($displayLines);

	print OUT <<EOT;

stat-definition myReport
 report myStuff
EOT
#	print OUT " filter myFilter\n" if (defined $tFilterFile);
	close(OUT);

	&dumpFile($tReportFile) if ($debug);

	return 1;
}

our $statusWindowOpen;		# global

sub statusOpen
{
	$| = 1;
	print <<EOT;
<script language="JavaScript">statusOpen();</script>
EOT
	$statusWindowOpen = 1;
}

sub statusClose
{
	return if (! $statusWindowOpen);

	print <<EOT;
<script language="JavaScript">statusClose();</script>
EOT

	undef $statusWindowOpen;
}

sub statusUpdate
{
	&statusOpen if (! $statusWindowOpen);

	print <<EOT;
<script language="JavaScript">status("$_[0]");</script>
EOT
}

# -------------------------
#       RUN REPORT
# -------------------------

sub runReport
{
	my($tReportFile, $tFilterFile, $tErrorFile, $tStatusFile, $tAltStatusFile, $tOutputFile, $tACL, $tAltReport, @files) = @_;
	my($pid, $cmd);

	if (($tAltReport) && (! defined $tFilterFile) && (! defined $tACL)) {
		$cmd = $tAltReport . " [files] 2>$tAltStatusFile >$tOutputFile";
	}
	else {
		$cmd = "$flowCat -d 6 [files] 2>$tStatusFile";						# which files
		$cmd .= " | $flowNfilter -f $tFilterFile -F myFilter" if (defined $tFilterFile);	# filter
		$cmd .= " | $flowCatACL $tACL - | $flowImport -V 5 -f 0" if (defined $tACL);		# standalone ACL

		if (defined $tAltReport) {
			$cmd .= " | $tAltReport -"; 							# run a different report
			$cmd .= " 2>$tAltStatusFile >$tOutputFile";					# bitbucket the status msgs
		}
		else {
			$cmd .= " | $flowReport -s $tReportFile -S myReport";				# run a flow-tools report
			$cmd .= " 2>$tErrorFile";							# capture errors (?)
		}
	}

	my $dcmd = $cmd;
	$dcmd =~ s/\[files\]/"[" . (scalar @files) . " files]"/e;
	print STDERR "adhoc: $dcmd\n";

	$debug = 0;
	print "cmd: $dcmd<br>\n" if ($debug);
	$debug = 0;

	$cmd =~ s/\[files\]/@files/;
	exec $cmd if (! ($pid=fork()));

	$| = 1;
	my @statusFiles = ( $tStatusFile );
	push (@statusFiles, $tAltStatusFile) if (defined $tAltReport);

	my $fileMax = @files;
	my $fileCount = 1;
	my ($lastStatusMsg, $statusMsg, $subStatusMsg, $ticker, $count);

	my $flowFileTotal = 1;
	my $flowTotalCount = 0;
	my $flowFileBaseline = 0;

	while (waitpid($pid, &WNOHANG) != -1) {
		select(undef,undef,undef,0.1);
		next if (! $trackStatus);

		foreach ( &checkStatus(@statusFiles) ) {

			if (/working file=(.*)/) {
				$ticker = time;
				$statusMsg = "reading file " . $fileCount++ . " of " . $fileMax . "<br>$1<br>&nbsp;";

				$flowFileTotal = int( (-s $1) / $sizeOfOneFlow) || 1;
				$flowFileBaseline = $flowTotalCount;
			}

			if (/flows[\:=]\s*(\d+)/) {		# flow-cat debug or alt status message from wvFlowConn
				$flowTotalCount = $1;
				my $fileFlowCount = $flowTotalCount - $flowFileBaseline;
				my $progress = int($fileFlowCount * 100 / $flowFileTotal);
				$progress = 'unknown' if ($progress > 99);
				$subStatusMsg = "progress=$progress\% flows=" . &commafy($fileFlowCount);
				$subStatusMsg .= " sessions=" . &commafy($1) if (/sessions=(\d+)/);
			}
		}

		if ( defined $statusMsg ) {
			next if ((time - $startTime) < $delayBeforeStatusWindow);

			if ($statusMsg ne $lastStatusMsg) {
				&statusUpdate(sprintf($statusMsg, ''));
				$lastStatusMsg = $statusMsg;
			}
			elsif ($count != (time - $ticker)) {
				$count = time - $ticker;
				if ($count >= 3) {
					$subStatusMsg = "progress <i>unknown</i> (elapsed=$count seconds)" if (! defined $subStatusMsg);
					&statusUpdate( $statusMsg . $subStatusMsg );
				}
			}
		}
	}

	if (-s $tErrorFile) {
		&statusClose;

		if ((`grep 'short read' $tErrorFile`) && (defined $tFilterFile)) {
			print "<font color=red>No flows matched your filter criteria!</font>\n";
			return;
		}

		print "<font color=red>Error running flow-report</font><ol>\n";
		print b("Command"), br, $cmd, p;
		&dumpFile($tErrorFile);
		&dumpFile($tReportFile);
		&dumpFile($tFilterFile);
		print "</ol>\n";
	}
}

sub checkStatus
{
	my @results;

	foreach my $fname (@_) {
		$fh{$fname} = IO::Handle->new() if (! exists $fh{$fname});
		local *STATUS = $fh{$fname};

		if (! defined fileno(STATUS)) {
			open(STATUS, $fname) || next;
		}

		while ( <STATUS> ) { push(@results, $_); }
		seek(STATUS, 0, 1);
	}
	return @results;
}


# -------------------------
#    RUN RAW FLOW DUMP
# -------------------------

sub runRaw
{
	my($fh, $tFilterFile, $tOutputFile, $tStatusFile, $displayLines, $layout, $tACL, @files) = @_;
	my($cmd, $buf, $fmt, @fields, @fieldEnabled, @fieldHex, @fieldUDP, @fieldIgnore);
	my(%dns);

	my @allCols = qw/
		exaddr exname nexthop nexthopname input srcas srcaddr
		srcmask srcname srccat output dstas dstaddr dstmask
		dstname dstcat prot srcport dstport tcp dscp dpkts
		doctets bps start dur
	/;

	my $layoutCols = {

		'basic' => {
			-enabled => [ qw/srcaddr dstaddr prot srcport dstport tcp dscp dpkts doctets bps start dur/ ],
		},

		'exp' => {
			-enabled => [ qw/exaddr input output/ ],
		},

		'routing' => {
			-enabled => [ qw/nexthop srcmask dstmask/ ],
			-disabled => [ qw/srcaddr dstaddr/ ],
		},

		'asn' => {
			-enabled => [ qw/srcas dstas/ ],
		},

		'dns' => {
			-upgrade => {
				'srcaddr' => 'srcname',
				'dstaddr' => 'dstname',
				'srcmask' => 'srcname',
				'dstmask' => 'dstname',
				'exaddr' => 'exname',
			},
		},

		'dnsclobber' => {
			-disabled => [ qw/srcaddr dstaddr exaddr/],
		},

		'cat' => {
			-enabled => [ qw/srccat dstcat/ ],
		},
	};

	my $columns = {
		'input' => {
			'label' => 'input-int',
			'width' => $IFWIDTH,
			'hack' => sub {
				my $v = shift;
				return &packIf($globalIfs->{$globalExp}->{$v->{input}}) || $v->{input} || 'Local';
			},
		},

		'output' => {
			'label' => 'output-int',
			'width' => $IFWIDTH,
			'hack' => sub {
				my $v = shift;
				return &packIf($globalIfs->{$globalExp}->{$v->{output}}) || $v->{output} || 'Local';
			},
		},

		'exaddr' => {
			'label' => 'exporter',
			'width' => 15,
			'hack' => sub {
				my $v = shift;
				return $globalExp = $v->{exaddr};
			},
		},

		'exname' => {
			'label' => 'exporter-name',
			'width' => 17,
			'hack' => sub {
				my $v = shift;
				$globalExp = $v->{exaddr};
				return $globalExpnames->{$globalExp} || $globalExp;
			},
		},

		'nexthop' => {
			'label' => 'next-hop',
			'width' => 15,
		},

		'nexthopname' => {		# unused because of width difficulties
			'label' => 'next-hop-name',

			'hack' => sub {
				my $v = shift; 
				return $dns{$v->{nexthop}} || $v->{nexthop};
			},
		},

		'srcaddr' => {
			'label' => 'ip-src-addr',
			'width' => 15,
		},

		'dstaddr' => {
			'label' => 'ip-dst-addr',
			'width' => 15,
		},

		'srcmask' => {
			'label' => 'ip-src-addr',
			'width' => 18,
			'hack' => sub {
				my $v = shift;
				return $v->{srcaddr} . '/' . $v->{srcmask};
			},
		},

		'dstmask' => {
			'label' => 'ip-dst-addr',
			'width' => 18,
			'hack' => sub {
				my $v = shift;
				return $v->{dstaddr} . '/' . $v->{dstmask};
			},
		},

		'srcas' => {
			'label' => 'src-as',
			'width' => 6,
		},

		'dstas' => {
			'label' => 'dst-as',
			'width' => 6,
		},

		'srcname' => {
			'label' => 'ip-src-name',

			'hack' => sub {
				my $v = shift; 
				return $dns{$v->{srcaddr}} || ( ($dnsEnable == 1) ? $v->{srcaddr} : undef );
			},
		},

		'dstname' => {
			'label' => 'ip-dst-name',

			'hack' => sub {
				my $v = shift; 
				return $dns{$v->{dstaddr}} || ( ($dnsEnable == 1) ? $v->{dstaddr} : undef );
			},
		},

		'srccat' => {
			'label' => 'ip-src-category',

			'hack' => sub {
				my $v = shift;
				return $nameTrie->match($v->{srcaddr});
			},
		},

		'dstcat' => {
			'label' => 'ip-dst-category',

			'hack' => sub {
				my $v = shift;
				return $nameTrie->match($v->{dstaddr});
			},
		},

		'srcport' => {
			'label' => 'src-port',
			'width' => 8,
		},

		'dstport' => {
			'label' => 'dst-port',
			'width' => 8,
		},

		'doctets' => {
			'label' => 'bytes',
			'width' => 10,
		},

		'dpkts' => {
			'label' => 'packets',
			'width' => 8,
		},

		'prot' => {
			'label' => 'proto',
			'width' => 5,

			'hack' => sub {
				my $v = shift; 
				my $p = $v->{prot};
				return ($iprotocols{$p} || $p);
			},
		},

		'bps' => {
			'label' => 'bps',
			'width' => 5,
			'hack' => sub {
				my $v = shift;
				my $b = $v->{doctets};
				my $t = ($v->{last} - $v->{first}) / 1000;
				return '' if ($t < 0.50);
				my $bps = int( $b * 8 / $t );
				return ($bps < 1_000) ? $bps :
					($bps < 1_000_000) ? int($bps/1_000) . "k" :
					($bps < 1_000_000_000) ? int($bps/1_000_000) . "m" :
					int($bps/1_000_000_000) . "g"
					;
			},
		},

		'dscp' => {
			'label' => 'dscp',
			'width' => 4,

			'hack' => sub {
				my $v = shift; 
				my $p = $v->{tos};
				if ($p == 0b00101000) { return 'af11' }
				elsif ($p == 0b00110000) { return 'af12' }
				elsif ($p == 0b00111000) { return 'af13' }
				elsif ($p == 0b01001000) { return 'af21' }
				elsif ($p == 0b01010000) { return 'af22' }
				elsif ($p == 0b01011000) { return 'af23' }
				elsif ($p == 0b01101000) { return 'af31' }
				elsif ($p == 0b01110000) { return 'af32' }
				elsif ($p == 0b01111000) { return 'af33' }
				elsif ($p == 0b10001000) { return 'af41' }
				elsif ($p == 0b10010000) { return 'af42' }
				elsif ($p == 0b10011000) { return 'af43' }
				elsif ($p == 0b00100000) { return 'cs1'  }
				elsif ($p == 0b01000000) { return 'cs2'  }
				elsif ($p == 0b01100000) { return 'cs3'  }
				elsif ($p == 0b10000000) { return 'cs4'  }
				elsif ($p == 0b10100000) { return 'cs5'  }
				elsif ($p == 0b11000000) { return 'cs6'  }
				elsif ($p == 0b11100000) { return 'cs7'  }
				elsif ($p == 0b10111000) { return 'ef'  }
				elsif ($p == 0b00000000) { return '0' }
				else { return sprintf('0x%x', $p >> 2) }
			},
		},

		'tcp' => {
			'label' => 'tcp-flags',
			'width' => 9,

			'hack' => sub {
				my $v = shift;
				my $f = $v->{tcp_flags};
				my $flags;

				if ($f & 1) {  $flags |= 'F     ' }
				if ($f & 2) {  $flags |= ' S    ' }
				if ($f & 4) {  $flags |= '  R   ' }
				if ($f & 8) {  $flags |= '   P  ' }
				if ($f & 16) { $flags |= '    A ' }
				if ($f & 32) { $flags |= '     U' }
				$flags =~ tr/ /-/;
				return lc($flags);
			},
		},

		'start' => {
			'label' => 'start-time',
			'width' => 12,

			'hack' => sub {
				my $v = shift; 
				my $t = $v->{unix_secs} + ($v->{first} - $v->{sysuptime}) / 1000;

				if ($outputFmt == $FMT_CSV) {
					return strftime("%Y-%m-%d %H:%M:%S", localtime(int($t))) .
						sprintf(".%03d", 1000 * ($t - int($t)));
				}
				else {
					return strftime("%H:%M:%S", localtime(int($t))) .
						sprintf(".%03d", 1000 * ($t - int($t)));
				}

			},
		},

		'dur' => {
			'label' => 'dur',
			'width' => '6',

			'hack' => sub {
				my $v = shift; 
				my $t = ($v->{last} - $v->{first}) / 1000;

				return sprintf("%.03f", $t);
			},
		},
	};

	# figure out which columns are interesting

	my $myCols = {};
	foreach my $x (keys %$layout) {
		if (exists $layoutCols->{$x}->{-enabled}) { map { $myCols->{$_}=1 } @{$layoutCols->{$x}->{-enabled}}; }
	}
	foreach my $x (keys %$layout) {
		if (exists $layoutCols->{$x}->{-upgrade}) {
			while( my($k,$v) = each %{$layoutCols->{$x}->{-upgrade}}) {
				$myCols->{$v} = 1 if (exists $myCols->{$k});
			}
		}
	}
	foreach my $x (keys %$layout) {
		if (exists $layoutCols->{$x}->{-disabled}) { map { delete $myCols->{$_} } @{$layoutCols->{$x}->{-disabled}}; }
	}
	my @layCols = grep(/\S/, map { $myCols->{$_} ? $_ : undef } @allCols);

	$cmd = "$flowCat @files 2>$tStatusFile";						# which files
	$cmd .= " | $flowNfilter -f $tFilterFile -F myFilter" if (defined $tFilterFile);	# filter
	$cmd .= " | $flowCatACL $tACL - | $flowImport -V 5 -f 0" if (defined $tACL);		# standalone ACL
#	$cmd .= " | $flowConn -";
	$cmd .= " | $flowExport -f 2";								# ascii

	print "<b>running $cmd</b>...<br>\n" if ($debug);

	open(IN, "$cmd |");
	open(OUT, ">$tOutputFile");

	<IN> =~ /^\#:(.*)/;	# flush header line
	my @fields = split(/,/, $1);

	my(%ips);		# hash of IPs
	my($lines) = 0;

	while ( <IN> ) {
		print OUT $_;
		s/(\d+\.\d+\.\d+\.\d+)/$ips{$1}=1/ge;
		last if ( ($displayLines) && ($lines++ >= $displayLines) );
	}

	close(OUT);
	close(IN);

	if ($dnsEnable) {	       # perform DNS resolution
		&dnsResolver(\%dns, keys %ips);

		my($dnsWidth) = 15;
		foreach (values %dns) {
			if ((my $x = length($_)) > $dnsWidth) {
				$dnsWidth = $x;
			}
		}
		$columns->{srcname}->{width} = $dnsWidth;
		$columns->{dstname}->{width} = $dnsWidth;
	}
	if ($catEnable) {		# perform CATEGORY resolution
		my($catWidth) = 15;
		foreach (values %ips) {
			if ((my $x = length($nameTrie->match_string($_))) > $catWidth) {
				$catWidth = $x;
			}
		}
		$columns->{srccat}->{width} = $catWidth;
		$columns->{dstcat}->{width} = $catWidth;
	}

	# if necessary, load interface data...

	if ($myCols->{exaddr}) {
		($globalIfs, $globalExpnames) = &loadInterfaces;
	}

	print { $fh } $tableStart{$outputFmt};

	if ($outputFmt == $FMT_TABLE) {
		print { $fh } Tr(
			map { th($_) } map { $columns->{$_}->{label} } @layCols
		), "\n";

		map { $fmt .= '<td>%s</td>' } @layCols;
	}
	elsif ($outputFmt == $FMT_ASCII) {
		foreach (@layCols) {
			my $width = ( $columns->{$_}->{width} ) ?
				$columns->{$_}->{width} . "." . $columns->{$_}->{width} : "";
			$fmt .= '%' . $width . 's ';
		}
		chop $fmt;

		print { $fh } b( sprintf($fmt, map { $columns->{$_}->{label} } @layCols) ) . "\n";
	}
	elsif ($outputFmt == $FMT_CSV) {

		map { $fmt .= '%s,' } @layCols;
		chop $fmt;

		print { $fh } sprintf($fmt, map { $columns->{$_}->{label} } @layCols);
	}

	open(IN, $tOutputFile);
	my $count = 0;

	while ( <IN> ) {
		chomp;

		my @f = split(/,/);
		my $v = {};

		foreach ( qw/unix_secs unix_nsecs sysuptime exaddr dpkts
			doctets first last engine_type engine_id srcaddr
			dstaddr nexthop input output srcport dstport prot
			tos tcp_flags srcmask dstmask srcas dstas/ ) {

			$v->{$_} = shift @f;
		}


		print { $fh }
			( ($count++ % 2) ? $tableRowOdd{$outputFmt} : $tableRowEven{$outputFmt}) .
			sprintf($fmt, map { exists $columns->{$_}->{hack} ? $columns->{$_}->{hack}->($v) : $v->{$_} } @layCols) .
			$tableRowEnd{$outputFmt};
	}
	close(IN);

	print { $fh } $tableEnd{$outputFmt};
}

sub packIf
{
	my $if = shift;

	return undef if (! $if);
	if (! exists $packedIfs{$if}) {
		$packedIfs{$if} = ($if =~ /^([A-Za-z\-]+)(\d[\d\:\.\/]*)/) ? substr($1,0,2) . $2 : substr($if,0,$IFWIDTH);
	}
	return $packedIfs{$if};
}

# --------------------------------------------------------------------------------
sub reportOutput
{
	my($fh, $tOutputFile, $expEnable) = @_;

	my($repeating, @fields, @fieldMultiplier, @fieldInt, @fieldMax, @fieldUndef, @fieldNoComma, @fieldIgnore, @fieldHack);
	my($first) = 1;
	my($fmt);
	my(%dns);
	my($dnsWidth) = 15;
	my($catWidth) = 15;
	my($expWidth) = 15;
	my($maxFieldWidth);

	if (($dnsEnable) || ($catEnable) || ($expEnable)) {
		my %ips;

		open(IN, $tOutputFile);
		while ( <IN> ) { s/(\d+\.\d+\.\d+\.\d+)/$ips{$1}=1/ge; }
		close(IN);

		if ($dnsEnable) {			# perform bulk DNS lookup
			&statusUpdate("Resolving DNS names")
				if ( ($trackStatus) && ((time - $startTime) >= $delayBeforeStatusWindow) );

			&dnsResolver(\%dns, keys %ips);

			foreach (values %dns) {
				if ((my $x = length($_)) > $dnsWidth) { $dnsWidth = $x; }
			}
		}
		if ($catEnable) {
			foreach (values %ips) {
				if ((my $x = length($nameTrie->match_string($_))) > $catWidth) { $catWidth = $x; }
			}
		}
		if ($expEnable) {
			foreach (values %ips) {
				if ((my $x = length($globalExpnames->{$_})) > $expWidth) { $expWidth = $x; }
			}
		}
	}
	&statusClose if ($trackStatus);

	my(%labelMatrix) = (
		'input' => 'input-int',
		'output' => 'output-int',
		'octets' => 'bytes',
		'bps' => 'bits/sec',
		'pps' => 'pkts/sec',
		'ip-source-address' => 'ip-src-addr',
		'ip-destination-address' => 'ip-dst-addr',
		'ip-address' => 'ip-addr',
		'ip-hostname' => 'ip-host',
		'ip-source-hostname' => 'ip-src-dns',
		'ip-source-category' => 'ip-src-category',
		'ip-destination-hostname' => 'ip-dst-dns',
		'ip-destination-category' => 'ip-dst-category',
		'ip-source-address-count' => 'peers',
		'ip-destination-address-count' => 'peers',
		'ip-protocol' => 'prot',
		'ip-tos' => 'dscp',
		'ip-source-port' => 'sport',
		'ip-destination-port' => 'dport',
		'exaddr' => 'exporter-ip',
		'exname' => 'exporter-name',
		'rx-only' => 'rx-only-interfaces',
		'tx-only' => 'tx-only-interfaces',

		'ip-client-addr' => 'client-ip',
		'ip-client-hostname' => 'client-dns',
		'ip-client-category' => 'client-category',
		'ip-server-addr' => 'server-ip',
		'ip-server-hostname' => 'server-dns',
		'ip-server-category' => 'server-category',
		'ip-client-port' => 'client-port',
		'ip-server-port' => 'server-port',
	);

	my(%labelWidth) = (
		'ip-address' => 15,
		'ip-source-address' => 15,
		'ip-source-address-count' => 7,
		'ip-destination-address' => 15,
		'ip-destination-address-count' => 7,
		'ip-hostname' => $dnsWidth,
		'ip-source-hostname' => $dnsWidth,
		'ip-destination-hostname' => $dnsWidth,
		'ip-source-category' => $catWidth,
		'ip-destination-category' => $catWidth,
		'ip-port' => 7,
		'ip-client-port' => 11,
		'ip-server-port' => 11, 
		'ip-tos' => 4,
		'ip-protocol' => 4,
		'ip-source-port' => 5,
		'ip-destination-port' => 5,
		'input' => 10,
		'output' => 10,
		'first' => 19,
		'last' => 19,
		'start' => 19,
		'end' => 19,
		'start_ms' => 23,
		'end_ms' => 23,
		'analysis' => 15,
		'timespan' => 9,
		'exaddr' => 15,
		'exname' => $expWidth,
		'tx-only' => 25,
		'rx-only' => 25,
		'flows' => 10,
		'octets' => 14,
		'packets' => 11,
		'duration' => 11,
		'bps' => 10,
		'pps' => 9,
	);

	my(%labelTransform) = (
		'duration' => 'INT/1000',
		'bps' => 'UNDEFINT',
		'ip-port' => 'NOCOMMA',
		'ip-address' => 'NOCOMMA',
		'ip-source-address' => 'NOCOMMA',
		'ip-destination-address' => 'NOCOMMA',
		'ip-source-port' => 'NOCOMMA',
		'ip-destination-port' => 'NOCOMMA',
		'ignores' => 'SKIP',
		'input' => 'NOCOMMA',
		'output' => 'NOCOMMA',
		'ip-client-port' => 'NOCOMMA',
		'ip-server-port' => 'NOCOMMA',
		'duration' => 'INT,MAX=14400'
	);

	my(%labelHack) = (
		'input' => sub {
			my $v = shift;
			return &packIf($globalIfs->{$globalExp}->{$v}) || $v || 'Local';
		},

		'output' => sub {
			my $v = shift;
			return &packIf($globalIfs->{$globalExp}->{$v}) || $v || 'Local';
		},

		'c2s-tos' => \&dispTos,

		's2c-tos' => \&dispTos,

		'ip-tos' => \&dispTos,

		'dscp' => \&dispTos,

		'exaddr' => sub {
			return $globalExp = shift;
		},

		'exname' => sub {
			my $v = shift;
			return $globalExpnames->{$v} || $v;
		},

		'rx-only' => \&iflist,

		'tx-only' => \&iflist,

		'first' => \&stamp,

		'last' => \&stamp,

		'start' => \&stamp,

		'end' => \&stamp,

		'start_ms' => \&stamp_ms,

		'end_ms' => \&stamp_ms,

		'ip-protocol' => sub {
			$GLOBAL_PROTOCOL = shift;
			return &dispProtocol($GLOBAL_PROTOCOL);
		},

		'octets' => sub { $GLOBAL_OCTETS = shift; },

		'duration' => sub { $GLOBAL_DURATION = shift; },

		'timespan' => sub {
			my $sec = shift;
			return sprintf("%d:%02d:%02d", int($sec / 3600), int(($sec % 3600) / 60), $sec % 60);
		},
	);

	sub iflist { return join(' ', map { &packIf($globalIfs->{$globalExp}->{$_}) || $_ } grep (!/^0$/, split(/ /, shift)) ); }

	sub stamp { return POSIX::strftime("%Y-%m-%d %H:%M:%S", localtime(shift)); }

	sub stamp_ms {
		my $stamp = shift;
		my $ms = sprintf("%03d", ($stamp - int($stamp)) * 1000);
		return POSIX::strftime("%Y-%m-%d %H:%M:%S", localtime(int($stamp))) . '.' . $ms; }

	print { $fh } $tableStart{$outputFmt};
	my $count = 0;
	my $flowDetail = 0;
	my ($groupLast, @groupFields);

	open(IN, $tOutputFile);
	while ( <IN> ) {
		chomp;

		# note that DNS is filled in for the exporter here, but it is clobbered by the exporter cache later on.

		if ( ($dnsEnable) && ($catEnable) ) {
			s/(\d+\.\d+\.\d+\.\d+)/$1 . "," . ($dns{$1} || ( ($dnsEnable == 1) ? $1 : '' ) ) . "," . $nameTrie->match($1)/sge;
		}
		elsif ($dnsEnable) {
			s/(\d+\.\d+\.\d+\.\d+)/$1 . "," . ($dns{$1} || ( ($dnsEnable == 1) ? $1 : '' ) )/sge;
		}
		elsif ($catEnable) {
			s/(\d+\.\d+\.\d+\.\d+)/$1 . "," . $nameTrie->match($1)/sge;
		}
		elsif ($expEnable) {
			s/(\d+\.\d+\.\d+\.\d+)/$1 . ","/sge;
		}

		print STDERR "$dnsEnable $catEnable $expEnable $_\n" if ($debug);

		# recn: ip-source-address,ip-destination-address,flows,octets,packets,duration,bps,pps

		# recn: exaddr,input,output,ip-protocol,ip-client-addr,ip-client-port,ip-server-addr,ip-server-port,tcp_flags,start,end,duration,c2s-flows,c2s-pkts,c2s-octets,c2s-tos,s2c-flows,s2c-pkts,s2c-octets,s2c-tos

		s/\*//g;
		if (/^# recn: (.*)/) {	  # repeating line
			my $i=0;
			foreach (split(/,/, $1)) {
				push(@fields, $_);
				if (/^(ip-|)(client|server)-(addr|port)$/) {
					push(@groupFields, $i);
				}

				if (/^ip-(client-|server-|source-|destination-|)addr(ess|)$/) {
					if ($dnsEnable) {		# sneak in a new field for dns name
						$fieldIgnore[$i] = 1 if ($dnsEnable == 2);		# ignore the IP field
						push(@fields, "ip-$1" . "hostname");
						$i++;
					}
					if ($catEnable) {		# sneak in a new field for category name
						push(@fields, "ip-$1" . "category");
						$i++;
					}
				}
				elsif (/^exaddr$/) {
					if ($dnsEnable) { push(@fields, 'exname'); $i++; }
					if ($catEnable) { push(@fields, 'exdummy'); $i++; $fieldIgnore[$i]=1; }
				}
				elsif (/^ip-source-port$/) {
					$flowDetail |= 0x01;
				}
				elsif (/^ip-destination-port$/) {
					$flowDetail |= 0x02;
				}
				elsif (/^ip-protocol$/) {
					$flowDetail |= 0x04;
				}
				elsif (/^octets$/) {
					$flowDetail |= 0x08;
				}
				elsif (/^duration$/) {
					if ($flowDetail == 0x0f) {
						push(@fields, 'bps');
						$i++;
					}
					else {	
						undef $flowDetail;
					}
				}
				$i++;
			}
			print { $fh } "\n" if (! $first);

			$first = $repeating = 1;
			print STDERR "flowDetail = $flowDetail, fields = @fields\n";
		}
		elsif (/^# rec\d+: (.*)/) {     # multiple individual lines
			push(@fields, split(/,/, $1));
			$repeating = 0;
			$first = 1;
		}
		elsif (! /^#/) {		# a line of data
			if ($repeating) {	       # repeating data
				if ($first) {		   # print header
					my(@ofields);

					print { $fh } "\n<tr>" if ($outputFmt == $FMT_TABLE);

					for (my $i=0; $i<@fields; $i++) {
						next if ($fieldIgnore[$i]);

						local($_) = $fields[$i];
						push(@ofields, ($labelMatrix{$_} || $_));

						if ($outputFmt == $FMT_ASCII) {
							my $width = (($labelWidth{$_}) ?  $labelWidth{$_} . "." . $labelWidth{$_} : "");
							$fmt .= '%' . $width . 's ';
						}

						# convert these numbers to integers?
						$fieldInt[$i] = 1 if ($labelTransform{$_} =~ /INT/);
						$fieldUndef[$i] = 1 if ($labelTransform{$_} =~ /UNDEF/);
						$fieldMax[$i] = $1 if ($labelTransform{$_} =~ /MAX=(\d+)/);

						# add a field multipler?
						$fieldMultiplier[$i] = (1/$1) if ($labelTransform{$_} =~ /\/(\d+)$/);
						$fieldMultiplier[$i] = $1 if ($labelTransform{$_} =~ /\*(\d+)$/);

						# inhibit commafication
						$fieldNoComma[$i] = 1 if ($labelTransform{$_} =~ /NOCOMMA/);

						# hack subroutine
						$fieldHack[$i] = $labelHack{$_} if (exists $labelHack{$_});

						print "i=$i, fields=$fields[$i], fieldInt=$fieldInt[$i], fieldUndef=$fieldUndef[$i], fieldMultiplier=$fieldMultiplier[$i], fieldHack=$fieldHack[$i]<br>\n" if ($debug);
					}
					undef $first;

					if ($outputFmt == $FMT_ASCII) {
						chop $fmt;		     # get rid of last space

						print { $fh }
							( ($count % 2) ? $tableRowOdd{$outputFmt} : $tableRowEven{$outputFmt}) .
							b( sprintf($fmt, @ofields) ).
							$tableRowEnd{$outputFmt};
					}
					elsif ($outputFmt == $FMT_CSV) {
						$fmt = join(',', map { '%s' } @ofields);

						print { $fh }
							( ($count % 2) ? $tableRowOdd{$outputFmt} : $tableRowEven{$outputFmt}) .
							sprintf($fmt, @ofields) .
							$tableRowEnd{$outputFmt};
					}
					elsif ($outputFmt == $FMT_TABLE) {
						$fmt = join('', map { '<td>%s</td>' } @ofields);

						print { $fh }
							( ($count % 2) ? $tableRowOdd{$outputFmt} : $tableRowEven{$outputFmt}) .
							join('', map { th($_) } @ofields) .
							$tableRowEnd{$outputFmt};
					}

				}

				my $i=0;
				my(@ofields);

				my $dobps = 0;
				$GLOBAL_OCTETS = $GLOBAL_DURATION = $GLOBAL_PROTOCOL = 0;
				my @values = split(/,/);

				if (@groupFields) {			# only change color if we've left a field grouping
					my $v = join($;, map { $values[$_] } @groupFields);
					if ($v ne $groupLast) { $count++; $groupLast = $v; }
				}
				else {
					$count++;
				}

				while (@values) {
					$_ = shift @values;

	#				print STDERR "i=$i, v=$_, fieldHack[\$i]=$fieldHack[$i]\n";

					$_ = &{$fieldHack[$i]}($_) if (exists $fieldHack[$i]);
					$_ *= $fieldMultiplier[$i] if ($fieldMultiplier[$i] > 0);
					if ((! $fieldUndef[$i]) || (defined $_))  {
						$_ = int($_) if ($fieldInt[$i]);
						if ( ($fieldMax[$i]) && ($_ > $fieldMax[$i]) ) { $_ = '#N/A'; }
						$_ = &commafy($_) if (! $fieldNoComma[$i]);
					}

					if ((! @values) && ($flowDetail) && (! $dobps)) {
						$dobps = 1;
						if ( (($GLOBAL_PROTOCOL == 6) || ($GLOBAL_PROTOCOL == 17)) && ($GLOBAL_DURATION >= 1000)) {	# add a "bps" field to the end
							push(@values, $GLOBAL_OCTETS * 8 / ($GLOBAL_DURATION / 1000) );
						}
						else {
							push(@values, undef);
						}
					}

					next if ($fieldIgnore[$i++]);
					push(@ofields, $_);
				}

				print { $fh }
					( ($count % 2) ? $tableRowOdd{$outputFmt} : $tableRowEven{$outputFmt}) .
					sprintf($fmt, @ofields) .
					$tableRowEnd{$outputFmt};
			}
			else {			  # non-repeating data
				if ($first) {
					undef $first;
					undef $maxFieldWidth;
					foreach (@fields) {
						$maxFieldWidth = length($_) if (length($_) > $maxFieldWidth);
					}
				}

				my @values = split(/,/);
				while (@values) {
					$_ = shift @values;
					my $label = shift @fields;

					next if ($labelTransform{$label} =~ /SKIP/);
					my $fieldNoComma = ($labelTransform{$label} =~ /NOCOMMA/);
					my $fieldInt = ($labelTransform{$label} =~ /INT/);
					my $fieldMult = ($labelTransform{$label} =~ /\/(\d+)$/) ? 1 / $1 :
						($labelTransform{$label} =~ /\*(\d+)$/) ? $1 : 1;

					$_ *= $fieldMult;
					$_ = int($_) if ($fieldInt);
					$_ = &commafy($_) if (! $fieldNoComma);

					if ($outputFmt == $FMT_CSV) {
						print { $fh } $label, ",", $_, "\n";
					}
					elsif ($outputFmt == $FMT_TABLE) {
						print { $fh } "\n<tr><th>$label<td>$_";
					}
					elsif ($outputFmt == $FMT_ASCII) {
						print { $fh } "<b>", sprintf("%$maxFieldWidth.$maxFieldWidth" . "s", $label), "</b> $_\n";
					}
				}
			}
		}
	}

	print { $fh } $tableEnd{$outputFmt};

	close(IN);
}

# --------------------------------------------------------------------------------
sub dumpFile
{
	my($fName) = $_[0];

	open(IN, $fName) || return;
	print "<pre><b>$fName</b>\n";
	while ( <IN> ) {
		print $_;
	}
	print "</pre><p>\n";
	close($fName);
}

# --------------------------------------------------------------------------------
sub parseIP
{
	my($parm, $array) = @_;

	foreach (split(/[,\s]+/, param($parm))) {
		my($not, $matchIP, $matchMask);

		/(\!)?\s*(.*)/;
		$not = ($1 eq "!");
		($matchIP, $matchMask) = &IP2integer($2);

		if (! defined $matchIP) {
			return "Error with IP address: $_\n";
		}
		else {
			foreach ((ref $matchIP) ? @$matchIP : ( $matchIP )) {
				$_ &= $matchMask;
				push(@$$array, {'not'=>$not, 'ip'=>$_, 'mask'=>$matchMask});
			}
		}
	}
}

sub parsePorts
{
	my($parm, $array) = @_;

	foreach (split(/[,\s]+/, param($parm))) {
		if (/(\!?)\s*(\d+)/) {
			push(@$$array, { 'port' => $2, 'not' => ($1 eq '!') });
		}
		else {
			return "Error with port number: $_\n";
		}
	}
}

sub parseCounter
{
	my($parm, $array) = @_;

	foreach (split(/\s*(,\s|;)\s*/, param($parm))) {
		if (/([\>\<\=]?)\s*([\d,]+)/) {
			my $range;
			if ($1 eq '>') { $range = 'gt '; }
			elsif ($1 eq '<') { $range = 'lt '; }
			elsif ($1 eq '=') { $range = ''; }
			else { $range = 'gt '; }

			my $num = $2; $num =~ s/,//g;
			print STDERR "parseCounter $range$num\n";
			push(@$$array, { 'counter' => "$range$num" });
		}
		else {
			return "Error with counter: $_\n";
		}
	}
}

sub parseTos
{
	my($parm, $tosp) = @_;

	foreach (split(/[\s,]+/, param($parm))) {

		my ($matchTosVal, $matchTosMask, $matchTosInvert) = &hackTos($_);
		if (defined $matchTosVal) {
			$tosp->{$matchTosMask}->{$matchTosVal} = 1;
		}
		elsif (/^(\d+)$/) {
			$tosp->{255}->{$1} = 1;
		}
		else {
			return "Error with ToS: $_\n";
		}
	}
}

sub parseProtocol
{
	my($parm, $array) = @_;

	foreach (split(/[\s,]+/, param($parm))) {
		if (exists $protocols{$_}) {
			push(@$$array, { 'protocol' => $protocols{$_} });
		}
		elsif (/^(\d+)$/) {
			push(@$$array, { 'protocol' => $1 });
		}
		else {
			return "Error with Protocol: $_\n";
		}
	}
}

sub hackFreeForm
{
	my($type,$val) = @_;
	my $ptype = param($type);
	my $results = [];

	if ( $ptype =~ /^(bytes|packets|flows|pps|bps)$/i) {
		if ( my $err=&parseCounter($val, \$results) ) { return undef; }
	}
	elsif ( $ptype =~ /^tos$/i) {
		my $tosp = {};
		if ( my $err=&parseTos($val, $tosp) ) { return undef; }
		push(@$results, $tosp);
	}
	elsif ( $ptype =~ /^protocol$/i) {
		if ( my $err=&parseProtocol($val, \$results) ) { return undef; }
	}
	elsif ( $ptype =~ /^nexthop$/i) {
		if (my $err = &parseIP($val, \$results) ) { return undef; }
	}
	elsif ( $ptype =~ /^tcp_flags$/i) {
		my $flags = 0;
		my $v = param($val);

		$flags |= 0x01 if ($v =~ /f/i);
		$flags |= 0x02 if ($v =~ /s/i);
		$flags |= 0x04 if ($v =~ /r/i);
		$flags |= 0x08 if ($v =~ /p/i);
		$flags |= 0x10 if ($v =~ /a/i);
		$flags |= 0x20 if ($v =~ /u/i);
		$flags |= 0x40 if ($v =~ /e/i);	# ece
		$flags |= 0x80 if ($v =~ /c/i);	# cwr

		push(@$results, $flags);
	}
	else {
		return undef;
	}

	return [$ptype, @$results];
}

sub hackTos
{
	my $v = shift;

	if (exists $tosMasks{$v}) {
		if ($tosMasks{$v} =~ /^(\!?)(0x[0-9a-f]{2,2})\/(0x[0-9a-f]{2,2})$/) {
			return ( oct($2), oct($3), ($1 eq "!") );
		}
	}
	return undef;
}

sub hackDir
{
	my($p) = $_[0];
	my(@v) = param($p);
	my($dir) = undef;		# 0;

	foreach (@v) {
		if (/src/i)     { $dir += 1; }
		elsif (/dst/i)  { $dir -= 1; }
	}
	return $dir;
}

sub hackParam
{
	my($p, $h) = @_;
	my($v) = param($p);
	my $default = undef;

	print "param '$p' = " . param($p) if ($debug);

	foreach (keys %$h) {
		$default = $$h{$_} if ((/default/) || (! defined $default));

		/^\-?(.*)/;			     # strip leading '-'
		if ($v =~ /^$1$/i) {
			print ", matches $_ '$$h{$_}'<br>\n" if ($debug);
			return $$h{$_};
		}
	}
	print ", returning default '$default'<br>\n" if ($debug);
	return $default;
}

sub trim
{
	my($x) = $_[0];

	if ($x > 1_000_000) {
		$x = "<font size=2><b>" . sprintf("%.2fM", $x / 1_000_000) . "</b></font>";
	}
	elsif ($x > 1_000) {
		$x = "<font size=2>" . sprintf("%.2fK", $x / 1_000) . "</font>";
	}
	else {
		$x = "<font size=2>" . sprintf("%.2f", $x) . "</font>";
	}
	return $x;
}

sub self
{
	my($url) = self_url;

	$url =~ tr/;/&/;			# because meta refresh don't like semicolons
	$url =~ s/\&([^=]+)=\&/\&/g;	    # trim blank values
	return $url;
}


# --------------------------------------------------------------------------------

sub IP2integer
{
	my(@addr_info, @ips);
	$_ = shift @_;
	s/\s+//g;

	if (/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/) {
		return (unpack("N4", inet_aton($1)), $subnetMasks{$2});
	}
	elsif (/^(\d+\.\d+\.\d+\.\d+)$/) {
		return (unpack("N4", inet_aton($1)), $subnetMasks{32});
	}
	elsif (/^([a-z0-9\-\.]+)$/i) {
		return undef unless ( @addr_info = gethostbyname( $1 ) );
		splice(@addr_info, 0, 4);
		foreach (@addr_info) { push(@ips, unpack("N4", $_)); }
		return ( ((@ips > 1) ? [ @ips ] : $ips[0]), $subnetMasks{32} );
	}
	elsif (/^([a-z0-9\-\.]+)\/(\d+)$/i) {
		return undef unless ( @addr_info = gethostbyname( $1 ) );
		splice(@addr_info, 0, 4);
		foreach (@addr_info) { push(@ips, unpack("N4", $_)); }
		return ( ((@ips > 1) ? [ @ips ] : $ips[0]), $subnetMasks{$2} );
	}
	return undef;
}

# ------------------------------------------------------------------------
# gethostbyaddress -- returns the DNS name
sub ghba
{
	my(@octets) = split(/\./, $_[0]);

	return undef if (@octets != 4);
	return gethostbyaddr(pack( 'C4', @octets), 2);
}

# ------------------------------------------------------------------------
# gethostbyname -- returns the dotted-decimal IP address
sub ghbn
{
	my(@addr_info);
	return $_[0] if ($_[0] =~ /^(\d+)+\.(\d+)\.(\d+)\.(\d+)$/);
	return undef unless ( @addr_info = gethostbyname( $_[0] ) );
	return(join(".", unpack('C*', $addr_info[4])));
}

sub integer2IP
{
	my(@x) = ($_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
	return join(".", @x);
}


# --------------------------------------------------------------------------------
# delete image files that are over 10 minutes old

sub houseKeeping
{
	my($dir) = $tempDir;
	my(@files);
	my($cutoff) = time - 600;		       # 600 seconds ago

	# $tempDir/liveFlows.$serialNo.txt

	opendir(DIR, $dir);
	@files = grep (/^flow-report\.\d+\./, readdir(DIR));
	closedir(DIR);

	foreach (@files) {
		unlink("$dir/$_") if ( (stat("$dir/$_"))[9] < $cutoff);
	}
}

# --------------------------------------------------------------------------------
sub commafy
{
	local $_ = $_[0];

	return $_ if ($outputFmt == $FMT_CSV);
	return $_ if (! /^\d+\.?\d*$/);
	$_ = sprintf("%.02f", $_) if (/\./);
	while (s/^(\d+)(\d{3})/$1,$2/) {}
	return $_;
}

sub logit
{
	print $_[1] . "<br>\n" if ($debug);
}

# -------------------------------------------------------------------
# maintain the DNS file -- uses globals $dnsFile and

sub dnsResolver
{
	my($dnshash, @toLookup) = @_;
	my(@ips, %dns);

	#### read the DNS file
	open(IN, $dnsFile);
	while ( <IN> ) {
		if (/^(\S+)\s+([\d\.]+)\s+\#\s+(\d+)$/) {       # 'host ip # expiration'
			$dns{$2}->{hostname} = $1;
			$dns{$2}->{timeout} = $3;
		}
	}
	close(IN);

	#### see what needs to be done
	foreach my $ip (@toLookup) {
		push(@ips, $ip) if ((! defined $dns{$ip}) || ($dns{$ip}->{timeout} < time));
	}

	#### perform a bulk lookup
	&bulkdns(\%dns, @ips) if (@ips);

	#### write the DNS file
	open(OUT, ">$dnsFile");
	foreach (keys %dns) {
		print OUT $dns{$_}->{hostname} . "\t" . $_ . "\t# " . $dns{$_}->{timeout} . "\n";
	}
	close(OUT);

	foreach (@toLookup) {

		next if ($dns{$_}->{hostname} eq $dnsNegativeCacheHostname);

		if ($dnsHostOnly) {
			$dnshash->{$_} = $1 if ($dns{$_}->{hostname} =~ /^([^\.]+)/);
		}
		else {
			$dnshash->{$_} = $dns{$_}->{hostname};
		}
	}

	&logit($LOG_TRIVIA, "Wrote " . (scalar keys %dns) . " entries to $dnsFile");
}

# -------------------------------------------------------------------
# perform a bulk DNS lookup -- uses globals $dnsTimeout, $dnsPacing, @dnsServers
sub bulkdns
{
	use Net::DNS;
	use IO::Select;

	my($iphash, @ips) = @_;
	my($count_query) = 0;
	my($count_answer) = 0;

	my $res = Net::DNS::Resolver->new;
	my $sel = IO::Select->new;
	my $endTime = time + $dnsTimeout + 1;

	$res->nameservers(@dnsServers) if (@dnsServers);

	while (1) {
		if ((time < $endTime) && ($_ = shift @ips)) {
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

#        foreach (keys %$queried) {              # note that there was no answer from these guys...
#                if ($queried->{$_} < time - 2) {
#                        $iphash->{$_}->{timeout} = time + $dnsNegativeCacheTimeout;
#                        $iphash->{$_}->{hostname} = $dnsNegativeCacheHostname;
#                }
#        }

	&logit($LOG_DEBUG, "DNS resolver got $count_answer of $count_query queries");
	return $count_answer;
}


sub dispProtocol {
	my $p = shift; 
	if ($p == 1) { return 'icmp' }
	elsif ($p == 6) { return 'tcp' }
	elsif ($p == 17) { return 'udp' }
	elsif ($p == 47) { return 'gre' }
	else { return $p; }
};

sub dispTos {
	my $p = shift;
	return if (! defined $p);

	if ($p == 0b00101000) { return 'af11' }
	elsif ($p == 0b00110000) { return 'af12' }
	elsif ($p == 0b00111000) { return 'af13' }
	elsif ($p == 0b01001000) { return 'af21' }
	elsif ($p == 0b01010000) { return 'af22' }
	elsif ($p == 0b01011000) { return 'af23' }
	elsif ($p == 0b01101000) { return 'af31' }
	elsif ($p == 0b01110000) { return 'af32' }
	elsif ($p == 0b01111000) { return 'af33' }
	elsif ($p == 0b10001000) { return 'af41' }
	elsif ($p == 0b10010000) { return 'af42' }
	elsif ($p == 0b10011000) { return 'af43' }
	elsif ($p == 0b00100000) { return 'cs1'  }
	elsif ($p == 0b01000000) { return 'cs2'  }
	elsif ($p == 0b01100000) { return 'cs3'  }
	elsif ($p == 0b10000000) { return 'cs4'  }
	elsif ($p == 0b10100000) { return 'cs5'  }
	elsif ($p == 0b11000000) { return 'cs6'  }
	elsif ($p == 0b11100000) { return 'cs7'  }
	elsif ($p == 0b10111000) { return 'ef'  }
	elsif ($p == 0b00000000) { return '0' }
	else { return $p }		# sprintf('0x%x', $p >> 2) }
};

sub loadInterfaces
{
	my %exporter;
	my $stateDir = "/tmp";
	my $ifCacheDir;

	# FUTURE WORK: should add recursion here

	open(IN, $configFile);
	while ( <IN> ) {
		chop;
		next if (/^\s*\#/);	# skip comment-only lines

		s/\s*[\#\;].*//;	# get rid of comments
		s/^\s+//;		# get rid of leading whitespace
		s/\s+$//;		# get rid of trailing whitespace
		s/\s+/ /g;		# make sure all whitespace is realy a single space
					#  (increases readability of the regexps below)

		if (/^directory (temp|state) (.*)/) {
			$stateDir = $2;
		}
		elsif (/^directory cache (.*)/) {
			$ifCacheDir = $1;
		}
	}
	close(IN);

	$ifCacheDir = $stateDir if (! defined $ifCacheDir);

	opendir(DIR, $ifCacheDir) || print "$!<br>\n";
	my(@ifDataFiles) = grep (/^ifData/, readdir(DIR));
	closedir(DIR);

	my $ifs = {};
	my $expnames = {};

	foreach (@ifDataFiles) {
		next if (! /^ifData\.(\d+\.\d+\.\d+\.\d+)$/);
		my $ip = $1;
		my $name;

		open(IN, "$ifCacheDir/$_");
		<IN>; <IN>; <IN>; <IN>; <IN>; <IN>;
		chomp( $name = <IN> );

		while ( <IN> ) {
			chomp;
			next if (! /\t/);
			my ($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);
			$ifs->{$ip}->{$ifIndex} = $ifDescr;
			$expnames->{$ip}=$name;
		}
		close(IN);
	}

	return ($ifs, $expnames);
}

sub findACL
{
	my ($foo, $group, $acl) = @_;

	my $go = 0;
	my $choice;

	open(IN, $indexFile);
	while ( <IN> ) {
		chomp;

		if (/^\[(.*?)\]/) {
			$go = ($1 eq 'ACLs');
		}
# ACL_Internet
# Strict:Summary:SummaryServices:ACL_Internet
# Strict:Detail:DetailedServices:ACL_Internet

		elsif ( ($go) && (/^(\S*ACL_$acl)\t\S/) ) {
			return $1 if ($1 eq "Strict:$foo:$group:ACL_$acl");	# exact match
			$choice = $1 if (length($1) > length($choice));
		}
	}
	close(IN);
	return $choice;
}

sub loadDaclMaps
{
	my $hostTrie = new Net::Patricia;

	return $hostTrie if (! -f $daclFile);		# provide dummy structure

	open(HASHCACHE, $daclFile);
	my(@elements) = @{Storable::fd_retrieve(\*HASHCACHE)};

	foreach my $elem (@elements) {
		my %hash = %{Storable::fd_retrieve(\*HASHCACHE)};
		my $count = scalar keys %hash;				# how many elements in this hash?

		foreach (keys %hash) {
			next if (! /^\d+\.\d+\.\d+\.\d+/);
			my $cat = ($hash{$_} == 1) ? $elem : $hash{$_};
			$cat =~ s/_auto$//;
			$cat =~ s/^DACL_//;
			$cat =~ s/^host[a-z]+_//i;			# purge human-entered "HOST_" "HOSTS_" "HOSTLIST_" etc

			my $hp = $hostTrie->match_exact_string($_) || { 'k'=>$_ };

			if ( (! exists $hp->{vCount}) || ($count < $hp->{vCount}) ) {
				$hp->{vCount} = $count;
				$hp->{vCat} = $cat;
				$hostTrie->add_string($_, $hp);
			}
		}
	}

	if ($debug) {
		$hostTrie->climb(sub  {
			my $hp = shift;
			print $hp->{k} . "\t" . $hp->{vCat} . "\t" . $hp->{vCount} . "\n";
		} );
	}

	my $newTrie = new Net::Patricia;

	# flatten, for speed
	$hostTrie->climb(sub {
		my $hp = shift;
		$newTrie->add_string($hp->{k}, $hp->{vCat});
	} );

	close(HASHCACHE);
	return $newTrie;
}

sub hackTime
{
	if ($_[0] =~ /^\s*(\d{4})-(\d\d)-(\d\d)\s+(\d\d)\:(\d\d)\s*$/) {
		return timelocal( 0, $5, $4, $3, $2 - 1, $1 - 1900 );
	}
	return undef;
}

