#!/usr/bin/perl

@dirs = (
	"/var/log/webview/flows/data",
);

my $purge = ($ARGV[0] =~ /-purge/);

foreach my $dir (@dirs) {
	open(IN, "find $dir -name *.rrd -mtime +60 |");				# +60 means older than 60 days
	while ( <IN> ) {
		chomp;
		print scalar localtime( (stat($_))[9] ), " ";
		if ($purge) { unlink($_); print "[deleted] "; }
		print $_, "\n";
	}
	close(IN);
}

