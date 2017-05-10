#!/usr/bin/perl

# render click-through routine
#
# click through only works when a datafile has two elements, a matrix and a group.
# the matrix must be first.
# 
#  v1.0   initial version
#  v1.01  04-24-07  made strict compatible, and improved pixel search range.
#  v1.02  05-12-07  added rrd 1.2 support
#  v1.03  08-16-07  added multiple exporter IP support
#  v1.04  06-24-08  added support for packed rrds
#  v1.05  07-31-08  changed pixel hunt routine, made error messages more friendly
#  v1.06  12-02-11  version checkpoint. better drilldown logic.

use CGI qw(:standard :html3 escape -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use GD;
use POSIX;
use strict;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our @pixelSearch = (
	[0, 0],
	[-1, 0],
	[1, 0],
	[0, -1],
	[0, 1],
	[-1, -1],
	[1, -1],
	[-1, 1],
	[1, 1],
	[-2, 0],
	[2, 0],
);

my($INFOSUFFIX) = "info";
my($leftMargin, $topMargin);

my $drilldown = {
	86400 * 2 => 3600 * 4,		# graphs of 2 or more days drill to 4-hour graphs
	86400 * 14 => 86400,		# graphs of 14 or more days drill to 1-day graphs
};

&main;

exit 0;

# ------------------------------------------------------------------------------------

sub main
{
	my ($startTime, $endTime, $width, $height, %colors);
	my %dependencies;
	my $endTime = time;

	my $img = param("img");
	my $xpos = param("x");
	my $ypos = param("y");

	my $imgFile = "$graphDir$img";
	my $infoFile = "$graphDir$img.$INFOSUFFIX";

	if ((! -f $imgFile) || (! -f $infoFile)) {
		&errdie("Graph data no longer exists.",
			"(graphs are purged after about 60 minutes)");
	}

	my ($clickFoo, $clickGroup);

	# --- read RRD creation info
	my ($version, $capture);

	open(IN, $infoFile) || &errdie("Could not read $infoFile: $!");
	chomp($version = <IN>);		# get RRD version
	if ($version =~ /^1\.0/) {		# rrd 1.0.x
		$leftMargin = 75;
		$topMargin = 32;
	}
	else {					# assume rrd 1.2.x
		$leftMargin = 67;
		$topMargin = 32;
	}

	my $clickSrcDir;		# check source directory
	chomp($capture = <IN>);

	my $selfurl;			# URL to self
	chomp($selfurl = <IN>);

	my $packed;			# packed rrd file
	chomp($packed = <IN>);

	while (my ($file, $dir) = each %flowDirs) {
		if ($dir eq $capture) { $clickSrcDir = $file; last; }
	}

	while ( <IN> ) {
		if (/^(-s|--start) (\d+)/) { $startTime = $2; }
		elsif (/^(-e|--end) (\d+)/) { $endTime = $2; }
		elsif (/^(-w|--width) (\d+)/) { $width = $2; }
		elsif (/^(-h|--height) (\d+)/) { $height = $2; }
		elsif (/^(-t|--title) (\S+)/) { $clickGroup = $2; }
		elsif (/^(line\d|area|stack):[^\#]+\#([^\:]+):\s*(\S+)/i) { $colors{lc($2)} = $3 if (! exists $colors{lc($2)}); }
		elsif (/^DEF:.*?[\/\.](.*)[\/\.]([^\.]+)\.rrd/) {
			my $stuff = $1;
			my $key = $2;
			my $count = 0;
			my $nextOneIsProbablyTheFoo;

			if ($packed) {
				$stuff .= "/$key";
				$key = 'packed';
			}

			foreach ( reverse split(/[\/\.]/, $stuff) ) {
				if (/(\#|\d+\-\d+\-\d+\-\d+\_?\d*)/) {
					$dependencies{$key}->{$count}->{$_} = 1;
					$nextOneIsProbablyTheFoo = 1;
				}
				elsif ($nextOneIsProbablyTheFoo) {
					$clickFoo = $_;
					undef $nextOneIsProbablyTheFoo;
				}
				$count++;
			}
		}
	}
	close(IN);

#	print "clickGroup=$clickGroup  clickFoo=$clickFoo<br>\n";

	# --- read in image file and calculate pixel color
	my $myImage = GD::Image->newFromPng($imgFile, 1) || &errdie("Could not read $imgFile: $!");

	# --- calculate selected category
	my $clickItem;
	my @pixColors;

	foreach (@pixelSearch) {
		my ($xoff, $yoff) = @$_;

		my $pixelColor = sprintf("%02x%02x%02x", $myImage->rgb($myImage->getPixel($xpos+$xoff,$ypos+$yoff)) );
		push(@pixColors, $pixelColor);
		if (defined ($clickItem = $colors{$pixelColor}) ) {
			$xpos += $xoff; $ypos += $yoff;
			last;
		}
	}

	if (($xpos < $leftMargin) || ($ypos < $topMargin) || ($xpos >= $leftMargin + $width) || ($ypos >= $topMargin + $height)) {
		if (! defined $clickItem) {
			&errdie("You have clicked $clickItem out of range.");
		}
		else {
			print STDERR "infoFile=$infoFile\n";
			print STDERR "selfurl=$selfurl\n";
			$selfurl =~ /;v([^=]+)=graph;/;
			my $graphvar = $1;
			$selfurl =~ s/;s$graphvar=[^;]*//g;			# delete all references to the var
			$selfurl .= ";s$graphvar=$clickItem";			# add our category
			print redirect($selfurl);
			exit 0;
		}
	}

	# --- calculate horizontal position (time)
	my $spanTime = $endTime - $startTime;
	my $clickTime1 = $startTime + (($xpos - $leftMargin    ) * ($spanTime / $width));
	my $clickTime2 = $startTime + (($xpos - $leftMargin + 2) * ($spanTime / $width));

	foreach (sort {$b <=> $a} keys %$drilldown) {
		if ($spanTime >= $_) {			# redirect to another graph
			my $newstart = $clickTime1 - int($drilldown->{$_} / 2);
			my $newend = $clickTime1 + int($drilldown->{$_} / 2);
			$selfurl =~ s/;start=[^;]*//g;
			$selfurl =~ s/;end=[^;]*//g;
			$selfurl .= ";start=$newstart;end=$newend";
			print redirect($selfurl);
			exit 0;
		}
	}

	if (! defined $clickItem) {
		my $black = $myImage->colorAllocate(0,0,0);
		$myImage->line($xpos-5,$ypos-5,$xpos+5,$ypos+5,$black);
		$myImage->line($xpos-5,$ypos+5,$xpos+5,$ypos-5,$black);

		my $errfname = "$img.error.png";
		open(OUT, ">$graphDir/$errfname");
		binmode(OUT);
		print OUT $myImage->png;
		close(OUT);

		&errdie("Could not determine anything of interest where you clicked.",
			"The 'X' marks where you clicked.",
			ul( img({-src=>$graphDirURL . "/$errfname"}) ),
			p,
			'Colors encountered: ' . join(', ', @pixColors)
		);
	}

	# --- identify what type of matrix is in use

	my $realItem = ($packed) ? 'packed' : $clickItem;
	my $x = (keys %{$dependencies{$realItem}->{0}})[0];
	my $matrixType;

	if ($x =~ /\#/) {				$matrixType = "if"; }		# matrix
	elsif ($x =~ /^\d+\-\d+\-\d+\-\d+$/) {		$matrixType = "ip"; }		# ip, could be nexthop!
	elsif ($x =~ /^\d+\-\d+\-\d+\-\d+\_\d+$/) {	$matrixType = "subnet"; }	# subnet
	else {
		&errdie("This type of matrix does not support clickable graphs (clickItem=$clickItem x=$x).");
	}

	# --- compose a filter list for it
	my (@filters1, @filters2, %ifFound, %ifNotFound);

	if ($matrixType eq "if") {
		my %matrix2filter;
		&loadInterfaces(\%matrix2filter);

		foreach (keys %{$dependencies{$realItem}->{0}}) {
			if (! exists $matrix2filter{$_}) { $ifNotFound{$_} = 1; next; }
			$ifFound{$_} = 1;
			push(@filters1, @{$matrix2filter{$_}});
		}
	}
	elsif (($matrixType eq "ip") || ($matrixType eq "subnet")) {
		foreach (keys %{$dependencies{$realItem}->{0}}) {
			push(@filters1, &matrix2IP($_));
		}

		foreach (keys %{$dependencies{$realItem}->{1}}) {
			push(@filters2, &matrix2IP($_));
		}
	}

	my $clickFilter = join(';', join(', ', @filters1), join(', ', @filters2));
	
	# --- print summary results

	my $sClickTime1 = POSIX::strftime("%Y-%m-%d %H:%M", localtime($clickTime1));
	my $sClickTime2 = POSIX::strftime("%Y-%m-%d %H:%M", localtime($clickTime2));

#	print "clickTime1 ", scalar localtime($clickTime1), "<br>\n";
#	print "clickTime2 ", scalar localtime($clickTime2), "<br>\n";
#	print "clickItem ", $clickItem, "<br>\n";
#	print "clickFilter ", $clickFilter, "<br>\n";
#	print "clickSrcDir ", $clickSrcDir, "<br>\n";

	my $click = join("&", "time1=" . escape($sClickTime1), "time2=" . escape($sClickTime2),
			"item=" . escape($clickItem), "filter=" . escape($clickFilter),
			"foo=" . escape($clickFoo), "group=" . escape($clickGroup),
			"srcdir=" . escape($clickSrcDir) );

	print STDERR "redirect info\n" .
		redirect("adhoc.cgi?$click");

	print redirect("adhoc.cgi?$click");

	if ( (%ifFound) || (%ifNotFound) ) {
		print "<!--\n";
		print join("\n", "interfaces found:" , map { s/\%([0-9a-f]{2})/chr(hex($1))/ge; "  $_" }  sort keys %ifFound) . "\n";
		print join("\n", "interfaces not found:" , map { s/\%([0-9a-f]{2})/chr(hex($1))/ge; "  $_" }  sort keys %ifNotFound) . "\n";
		print "-->\n";
	}
}

sub errdie		# never returns
{
	my $msg = shift;

	print header(),
		start_html,
		h2( i($msg) ),
		@_,
		hr,
		button(-name=>'Go Back and Try Again', -onClick=>'history.go(-1)'),
		end_html;

	exit 0;
}

sub recurseConfig
{
	my ($file, $stateDir, $ifCacheDir) = @_;
	my $file = shift;
	my @lines;

	open(IN, $file) || die "Could not read $file";
	while ( <IN> ) {
		chop;
		next if (/^\s*\#/);	# skip comment-only lines

		s/\s*[\#\;].*//;	# get rid of comments
		s/^\s+//;		# get rid of leading whitespace
		s/\s+$//;		# get rid of trailing whitespace
		s/\s+/ /g;		# make sure all whitespace is realy a single space
		push(@lines, $_);
	}
	close(IN);

	foreach (@lines) {
		if (/^directory (temp|state) (.*)/) {
			$$stateDir = $2;
		}
		elsif (/^directory cache (.*)/) {
			$$ifCacheDir = $1;
		}
		elsif (/^include (['"]*)(.+)\1/) {
			my $subfile = $2;
			if ($subfile !~ /^\//) {
				$file =~ /^(.*\/)[^\/]+$/;
				$subfile = "$1$subfile";
			}
			&recurseConfig($subfile, $stateDir, $ifCacheDir);
		}
	}
}

sub loadInterfaces
{
	my $interfaceTable = shift;

	my %exporter;
	my $stateDir = "/tmp";
	my $ifCacheDir;

	&recurseConfig($configFile, \$stateDir, \$ifCacheDir);
	$ifCacheDir = $stateDir if (! defined $ifCacheDir);

	opendir(DIR, $ifCacheDir) || &errdie("Could not read $ifCacheDir: $!");
	my(@ifDataFiles) = grep (/^ifData/, readdir(DIR));
	closedir(DIR);

	foreach (@ifDataFiles) {
		next if (! /^ifData\.(\d+\.\d+\.\d+\.\d+)$/);

		my $exporterIP = $1;

		open(IN, "$ifCacheDir/$_");
		<IN>; <IN>; <IN>; <IN>; <IN>; <IN>;
		chomp( my $exporterName = <IN> );

		push(@{$interfaceTable->{$exporterName . "#" . "Local"}}, join(":", $exporterIP, 0));
		while ( <IN> ) {
			chomp;
			next if (! /\t/);
			my ($ifIndex, $ifDescr, $ifAlias, $ifSpeed) = split(/\t/);

			$ifDescr =~ s/[^A-Z^a-z^0-9^\-]/sprintf("%%%2x",ord($&))/ge;
			push(@{$interfaceTable->{$exporterName . "#" . $ifDescr}}, join(":", $exporterIP, $ifIndex));
		}
		close(IN);
	}
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

sub unhackIP                    # currently unused
{
	my(@x) = ($_[0] >> 24, $_[0] >> 16 & 0x0ff, $_[0] >> 8 & 0xff, $_[0] & 0xff);
	return join(".", @x);
}

sub matrix2IP
{
	my $ip = shift;
	if ($ip =~ /^(\d+)\-(\d+)\-(\d+)\-(\d+)\_(\d+)$/) {
		return "$1.$2.$3.$4/$5";
	}
	elsif ($ip =~ /^(\d+)\-(\d+)\-(\d+)\-(\d+)$/) {
		return "$1.$2.$3.$4";
	}
	return undef;
}

