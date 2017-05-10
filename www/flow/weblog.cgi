#!/usr/bin/perl

# simple web-based flowage status screen

use strict;
use CGI qw(:standard :html3 -nosticky);
use CGI::Carp qw( fatalsToBrowser );
use Time::Local;

our %months = ( qw/ jan 0 feb 1 mar 2 apr 3 may 4 jun 5 jul 6 aug 7 sep 8 oct 9 nov 10 dec 11/ );
our $monthre = '(' . join('|', keys %months) . ')';

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

# define one or more flowage instances to report on

our $rrdcachedStats = "$rrdcachedCmd --daemon unix:/tmp/rrdcached.sock STATS";

our $sources = {
	'Webview' => {
		'reportOrder'	=> 10,
		'flowageLog'	=> '/opt/netflow/data/flowage.log',
		'flowageStdout'	=> undef,					# '/tmp/flowage.stdout',
		'flowageStderr'	=> undef,					# '/tmp/flowage.stderr',
		'captureDir'	=> '/opt/netflow/capture/2055',
		'captureLive'	=> '/dev/shm/2055',
	},
};

$| = 1;

print header(), start_html('Webview Processing Status');

print button(-name=>'Refresh', -onClick=>'window.location.reload()'), ' &nbsp; ',
	button(-name=>'Home', -onClick=>"window.location=\"$rootDirURL\""), p;

my $start2read = {};

# collect summary status
print a({-name=>'top'}), h2('Processing summary'), "<ol><table border=1 cellspacing=0 cellpadding=3>";
foreach my $source (sort { $sources->{$a}->{reportOrder} <=> $sources->{$b}->{reportOrder} } keys %$sources) {
	my $hp = $sources->{$source};
	my $lastStamp;

	my ($procStart, %s2rd);

	open(IN, $hp->{flowageLog});		# "tail -1000 $hp->{flowageLog} |");
	while ( <IN> ) {
		if (/\d+ reading [\w\/]+\/ft-v05\.([\d\-\.]+)/) {
			$lastStamp = $1;

			if (defined $procStart) {	# measure time from start to reading (i.e., snmp time)
				$s2rd{$procStart} = &hackDate($_) - $procStart;
				undef $procStart;
			}
		}
		elsif (/start of flowage.pl/) {
			$procStart = &hackDate($_);
		}
	}
	close(IN);

	my $msg;

	if ( $lastStamp !~ /^(\d+)\-(\d+)\-(\d+)\.(\d\d)(\d\d)(\d\d)/) {
		$msg = "unparseable file $lastStamp";
	}
	else {
		my $behind = time - timelocal($6, $5, $4, $3, $2 -1, $1);

		if ($behind < 900) {		# under 15 min
			$msg = font({-color=>'green'}, 'healthy');
		}
		else {
			$msg = "lagging by ";
			$msg .= ($behind > 3600) ? int($behind / 3600) . 'h ' : '';
			$msg .= int( ($behind % 3600) / 60 ) . 'm ';
			$msg .= ($behind % 60) . 's';

			if ($behind > 3600 * 4) {
				$msg = font({-color=>'red'}, $msg);
			}
		}
	}

	print Tr( th( a( {-href=>"#$source"}, $source) ), td($msg) ) . "\n";

	my (%s2rc, %s2rv);
	foreach (sort {$a <=> $b} keys %s2rd) {
		my $field = ($_ > time - 3600)  ? 'last hour' : ($_ > time - 14400) ? 'last 4 hours' : ($_ > time - 86400) ? 'last day' : next;
		$s2rv{$field} += $s2rd{$_};
		$s2rc{$field} ++;
	}
	foreach my $field (keys %s2rv) {
		$start2read->{$source}->{$field} = int($s2rv{$field} / $s2rc{$field});
	}
}

`uptime` =~ /load average: ([\d\.]+)/;

print Tr( th( a( {-href=>"#system"}, 'system') ), td("one-minute load=$1") ) . "\n";

`$rrdcachedStats` =~ /QueueLength: (\d+)/;

print Tr( th( a( {-href=>"#rrdcached"}, 'rrdcached') ), td("queue depth=$1") ) . "\n";

my $indexResults = &indexStats;
foreach my $result (@$indexResults) {

	my $stem = $result->{stem};
	my $files = $result->{fileCount};
	my $bytes = $result->{byteCount};

	my $blabel = "none";

	if ($bytes >=1024 * 1024 * 1024 * 1024) {	$blabel = sprintf("%0.1f TB", $bytes / (1024 * 1024 * 1024 * 1024)); }
	elsif ($bytes >= 1024 * 1024 * 1024) {		$blabel = sprintf("%0.1f GB", $bytes / (1024 * 1024 * 1024)); }
	elsif ($bytes >= 1024 * 1024) {			$blabel = sprintf("%0.1f MB", $bytes / (1024 * 1024)); }
	elsif ($bytes >= 1024) {			$blabel = sprintf("%0.1f KB", $bytes / (1024)); }
	elsif ($bytes > 0) {				$blabel = "$bytes bytes" }

	print Tr( th( a( {-href=>"#$stem"}, "datafile $stem") ), td("files=$files, diskspace=$blabel") ) . "\n";
}

print "</table></ol>\n";

# ---------------------- end of summary

foreach my $source (sort { $sources->{$a}->{reportOrder} <=> $sources->{$b}->{reportOrder} } keys %$sources) {
	my $hp = $sources->{$source};

	print hr, a( {-name=>$source} );
	&dump($source . ': Flowage Activity Log (last 200 lines)', "tail -2000 $hp->{flowageLog} | grep -v -E 'Exporter.*Loaded' | tail -200") if (defined $hp->{flowageLog});

	&dumpStuff($source . ': Start-up lag times (mostly SNMP)',
		join("\n", map  { $_ . ' = ' . $start2read->{$source}->{$_} . ' sec' }
				keys %{$start2read->{$source}}
		)
	) if (defined $hp->{flowageLog});
	&dump($source . ': Active collection', "find $hp->{captureLive} -ls") if (defined $hp->{captureLive});
	&dump($source . ': Capture directory (last 10 files)', "ls -l $hp->{captureDir} | grep -v summary | tail -10") if (defined $hp->{captureDir});
	&dump($source . ': Flowage STDOUT', "cat $hp->{flowageStdout}") if (defined $hp->{flowageStdout});
	&dump($source . ': Flowage STDERR', "cat $hp->{flowageStderr}") if (defined $hp->{flowageStderr});
}

print hr, a( {-name=>'system'} );
#&dump('System: Log of Active->Capture management', "tail -10 /var/log/flow-shuffle.log");
&dump('System: Current system clock', "date");
&dump('System: Uptime', "uptime");
&dump('System: top', "top -b -c -n 1");

print hr, a( {-name=>'rrdcached'} );
&dump('rrdcached: Status', $rrdcachedStats);

foreach (@$indexResults) {
	my $stem = $_->{stem};
	my $results = $_->{results};

	print hr, a( {-name=>$stem} );

	my $stuff;

	foreach (keys %$results) {
		if ( ! ref($results->{$_}) ) {
			$stuff .= $results->{$_} . " total $_ are being tracked\n\n";
		}
	}

	foreach my $sub (keys %$results) {
		if ( ref($results->{$sub}) ) {
			$stuff .= "$sub has this breakdown:\n";

			foreach (sort { $results->{$sub}->{$b} <=> $results->{$sub}->{$a} } keys %{$results->{$sub}}) {
				$stuff .= "\t" . $results->{$sub}->{$_} . "\t$_\n";
			}
			$stuff .= "\n";
		}
	}

	&dumpStuff("datafile $stem", $stuff);
}


print hr,
	button(-name=>'Top', -onClick=>'window.location="#top"'), ' &nbsp; ',
	button(-name=>'Refresh', -onClick=>'window.location.reload()'), ' &nbsp; ',
	button(-name=>'Home', -onClick=>"window.location=\"$rootDirURL\""),
	p;

print end_html();

exit;

sub dump
{
	my($label, $cmd) = @_;
	my $acc = `$cmd`;
	$acc =~ s/(processed \d+ flows.*?per sec\))/<b>$1<\/b>/g;
	print h2($label), "<ul><pre><b>$cmd</b>\n\n" . $acc . "</pre></ul>\n";
}

sub dumpStuff
{
	my($label, $stuff) = @_;
	print h2($label), "<ul><pre>$stuff</pre></ul>\n";
}


sub indexStats
{
	my $results = [];

	my $hp = {};
	my $reading;
	my @stems;

	open(IN, $indexFile);
	while (<IN>) {
		chomp;
		if (/^\[([^\]]+)\]/) {
			$reading = $1;
			$hp->{$reading} = [];
		}
		elsif ((defined $reading) && ($reading !~ /=/) && (/^\s*(\S+)\s*(.*?)\s*$/)) {	# stuff
			push(@{$hp->{$reading}}, $1);
		}
	}
	close(IN);

	foreach my $file (@{$hp->{files}}) {
		next if ($file !~ /^(.*)\/([^\.]+)([^\/]+)(\.rrd)$/);
		my ($dir, $stem, $sfile, $suffix) = ($1, $2, $3, $4);
		my $sp = {};
		my @subs;

# Summary - 1915 interfaces, 105,192 RRD files, 25 GB

		$sfile =~ s/\[(.*?)\]/push(@subs, $1); "([^\\.]+)"/ge;
		if (-d "$dir/$stem") { $sfile =~ s/\./\//g; }		# convert dots to slashes

#		print "$dir=$dir, stem=$stem, sfile=$sfile, suffix=$suffix, subs=@subs\n";
		
		foreach my $sub (@subs) {			# preset count=0 for all categories
			foreach (@{$hp->{$sub}}) { $sp->{$sub}->{$_} = 0; }
		}

		my $fileCount = 0;
		my $byteCount = 0;

		print STDERR "find $dir/$stem -name '*$suffix' -printf '%b %p\n' |\n";
		open(IN, "find $dir/$stem -name '*$suffix' -printf '%b %p\n' |");
		while ( <IN> ) {
			if (/^(\d+)\s+.*$sfile$suffix$/) {
				my @vars = ($1, $2, $3, $4, $5, $6, $7, $8, $9);

				$fileCount++;
				$byteCount += shift @vars;

				foreach (@subs) { $sp->{$_}->{shift @vars}++; }
			}
		}
		close(IN);

		my $resultsHash = {};		

		foreach my $sub (@subs) {
			if ($sub =~ /^\%(.*)/) {
				$resultsHash->{$1} = scalar keys %{$sp->{$sub}};
			}
			else {
				$resultsHash->{$sub} = { map { $_, $sp->{$sub}->{$_} } keys %{$sp->{$sub}} };
			}
		}

		push( @$results, { 'stem'=>$stem, 'fileCount'=>$fileCount, 'byteCount'=>$byteCount*512, 'results'=>$resultsHash } );
	}
	return $results;
}

# Tue Jan 15 14:40:02 2013

sub hackDate
{
	if ($_[0] =~ /^\S\S\S $monthre (\d\d) (\d\d)\:(\d\d)\:(\d\d) (\d\d\d\d)/io) {
		return timelocal($5, $4, $3, $2, $months{lc($1)}, $6);
	}
	return undef;
}


