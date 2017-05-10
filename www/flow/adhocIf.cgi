#!/usr/bin/perl

# adhocIf.cgi -- display list of interfaces and let the user select one or more
#
#  v1.0  07-10-08  initial version
#  v1.01 07-31-08  bug fix with last item.
#  v1.02 09-20-10  added 'any' interfaces
#  v1.03 01-01-12  added support for hierarchical capture directories

use CGI qw(:standard :html3 *table escape -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use strict;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $pad = '&nbsp;';

&cgiSelectIfs;
exit 0;

sub cgiSelectIfs
{
	my $ifs = &loadInterfaces;
	my @exps = sort byPaddedNum keys %$ifs;
	my $ifLabels = {};

	for (my $ix=0; $ix<@exps; $ix++) {
		my $exp = $exps[$ix];
		$ifLabels->{$ix} = {
			0 => 'Any interface',
			map { $_ => $ifs->{$exp}->{ifs}->{$_}->{ifDescr} . ' : ' . $ifs->{$exp}->{ifs}->{$_}->{ifAlias} } sort {$a <=> $b} keys %{$ifs->{$exp}->{ifs}}
		};
	}

	my $JSCRIPT;

	$JSCRIPT .= "var ip2exp = { " .  join(', ', map { "'" . $ifs->{$exps[$_]}->{ip} . "' : " . $_ } (0 .. $#exps) ) . "};\n";
	$JSCRIPT .= "var exp2ip = { " .  join(', ', map { $_ . " : '" . $ifs->{$exps[$_]}->{ip} . "'" } (0 .. $#exps) ) . "};\n";

	$JSCRIPT .= <<EOT;
var lastCount = -1;

function updateifs( exp ) {

	for (var i=0; i<=$#exps; i++) {
		exp.form['ifs' + i].style.display = (i == exp.selectedIndex) ? '' : 'none';
	}
}

function importvars( ) {
	myreset( window.document.selectIfs );
	var items = window.opener.document.inputForm.ifs.value.split(/[,;]\\s*/);
	var firstexp = -1;

	for (var i=0; i<items.length; i++) {
		var ipif = items[i].split(/:/);
		var exp = ip2exp[ipif[0]];

		if (typeof(exp) == 'undefined') { continue; }
		if (firstexp < 0) { firstexp = exp; }
		var selList = window.document.selectIfs["ifs"+exp];

		for (var j=0; j<selList.length; j++) {
			if (selList.options[j].value == ipif[1]) {
				selList.options[j].selected = 1;
				break;
			}
		}
	}
	mystatus( window.document.selectIfs );
	if (firstexp >= 0) {
		window.document.selectIfs.exporters.selectedIndex = firstexp;
		updateifs(window.document.selectIfs.exporters);
	}
}

function exportvars( ) {
	var ipifs = new Array;

	for (var i=0; i<=$#exps; i++) {
		var ip = exp2ip[i];
		var selList = window.document.selectIfs["ifs" + i];
		for (var j=0; j<selList.length; j++) {
			if (selList.options[j].selected) {
				ipifs.push(ip + ':' + selList.options[j].value);
			}
		}
	}
	window.opener.document.inputForm.ifs.value=ipifs.join(', ');
	var foo = window.opener.document.getElementById('ifSelect');
	var count = ipifs.length;
	foo.innerHTML = ((count > 0) ? count : 'all') + ' interface' + ((count != 1) ? 's' : '');
}

function mycancel( f ) {		// one-click cancel
	window.close();
	window.opener.focus();
}

function myselect( f ) {		// one-click select
	exportvars();
	window.close();
	window.opener.focus();
}

function myreset( f ) {		// clear list
	for (var i=0; i<=$#exps; i++) {
		var selList = f['ifs' + i];
		for (var j=0; j<selList.length; j++) { selList.options[j].selected = 0; }
	}
	mystatus( f );
}

function mystatus( f ) {		// update status bar
	var count = 0;

	for (var i=0; i<=$#exps; i++) {
		var selList = f['ifs' + i];
		var ecount = 0;
		for (var j=0; j<selList.length; j++) {
			if (selList.options[j].selected) { count++; ecount++; }
		}

		f['exporters'].options[i].style.fontWeight=((ecount) ? 'bold' : '');
	}

	if (count != lastCount) {
		lastCount = count;
		var id = document.getElementById('status');
		id.innerHTML = ((count > 0) ? count : 'no') + ' interface' + ((count != 1) ? 's' : '') + ' highlighted';
	}
}

EOT

	my $STYLE = <<EOT;
BODY,select {
	font-family: monospace;
	font-size: 8pt;
}
EOT
	print header(),
		start_html(-title=>'interface selector',
			-script => [
				{ -code => $JSCRIPT },
			],
			-style => [
				{ -code => $STYLE },
			],
			-onLoad => 'importvars()',
		),
		start_form({ -name=>'selectIfs' }),

			popup_menu(
				-name=>'exporters',
				-values=>[0 .. $#exps],
				-labels=>{ map { $_ => $exps[$_] } (0 .. $#exps) },
				-default=>0,
				-onChange=>'updateifs(this)',
			),
			br,

			(map { 
				scrolling_list(
					-name=>"ifs$_",
					-values=>[0, sort {$a <=> $b} keys %{$ifs->{$exps[$_]}->{ifs}}],
					-labels=>$ifLabels->{$_},
					-size=>20,
					-multiple=>'true',
					-style=>'width:100%; ' . (($_) ? 'display:none' : ''),
					-onChange=>'mystatus(this.form)',
				)
			} (0 .. $#exps)),

			p({-align=>'center'},
				button(-id=>'select', -name=>'Select', -onClick=>'myselect(this.form)'),
				' &nbsp; ',
				button(-name=>'Clear', -onClick=>'myreset(this.form)'),
				' &nbsp; ',
				button(-name=>'Cancel', -onClick=>'mycancel(this.form)'),
			),

			p({ -id=>'status', -align=>'center' }, ''),

		end_form(),
		end_html();

}

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
			$ifs->{$name}->{ip} = $ip;
			$ifs->{$name}->{ifs}->{$ifIndex}->{ifAlias} = $ifAlias;
			$ifs->{$name}->{ifs}->{$ifIndex}->{ifDescr} = $ifDescr;
		}
		close(IN);
	}

	return $ifs;
}

sub byPaddedNum
{
	my($a1,$b1) = ($a,$b);
	$a1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	$b1 =~ s/(\d+)/sprintf("%08d",$1)/ge;
	return (lc($a1) cmp lc($b1));
}

