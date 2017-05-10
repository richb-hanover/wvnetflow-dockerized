#!/usr/bin/perl

use strict;
use CGI qw(:standard :html3 -nosticky);
use CGI::Carp qw( fatalsToBrowser );

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our ($root, $file, @files, %done);

if ($configFile =~ /(.*)\/([^\/]+)$/) {
	$root = $1;
	$file = $2;
}

print header,
        start_html($file);

our $count = 0;
push(@files, $file);

while (($count++ < 10) && (@files)) {
	$file = shift @files;
	$file = $1 if ($file =~/^['"](.*)['"]$/);
	$file = ($file =~ /^\//) ? $file : "$root/$file";
	next if ($done{$file});
	$done{$file} = 1;

        my $mtime = (stat($file))[9];
        my $config = `cat $file`;

	$config =~ s/(\n\x20*exporter.*?community\s+)(\S+)/$1\[removed\]/g;
	$config =~ s/(authpassword|privpassword|community)(=\S+)/$1=\[removed\]/g;

        print h1($file), h3(scalar localtime($mtime)), pre($config);

	$config =~ s/^\s*include\s*(\S+)/push(@files,$1);/gem;
}

print end_html;

