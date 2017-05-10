#!/usr/bin/perl

# there is probably a 1-line way to do what this script does.

use Socket;
use strict;

our $rrdCachedSocketOpen;
our $rrdcached = $ENV{RRDCACHED_ADDRESS};
our $LOG_DEBUG = 4;
our $LOG_ERROR = 1;
our $LOG_INFO = 2;

our @cmds;

if ($0 =~ /rrdcached-(flushall|stats)$/) {
	push(@cmds, uc($1));
}

while ($_ = shift @ARGV) {
	if (/^--daemon$/) {
		$rrdcached = shift @ARGV;
	}
	elsif ((/^(flush|pending|forget|help)$/i) && (@ARGV)) {
		push(@cmds, uc($1) . ' ' . shift @ARGV);
	}
	elsif (/^(flushall|queue|stats)$/i) {
		push(@cmds, uc($1));
	}
	else {
		undef $rrdcached; last;
	}
}

if (! defined $rrdcached) {
	print <<EOT;
usage: $0 [--daemon <rrdcached address>] [rrcached commands ...]
EOT
	exit 1;
}

	
$| = 1;

if (! &rrdCachedOpen($rrdcached) ) {
	&logit($LOG_ERROR, "Failed to open RRDCACHED socket");
}
else {
	foreach (@cmds) { &docmd($_); }
	&rrdCachedClose;
}

exit 0;

sub logit {
	my $level = shift @_;
	return if ($level == $LOG_DEBUG);
	map { print "$_\n" } @_;
}

sub docmd
{
	my $cmd = shift;

	&logit($LOG_INFO, "=== $cmd ===");
	&rrdCachedPut($cmd);

	my $first = &rrdCachedGet;
	&logit($LOG_INFO, $first);

	if ($first =~ /^(\d+)/) {
		for (1 .. $1) {
			my $x = &rrdCachedGet;
			if (! defined $x) { 
				&logit($LOG_ERROR, "Stopping due to <undef> value");
				last;
			}
			&logit($LOG_INFO, $x);
		}
	}
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

		&rrdCachedPut("STATS");
		if (&rrdCachedGet =~ /(\d+) Statistics follow/) {
			$ok = 1;
			for (1 .. $1) {
				my $x = &rrdCachedGet;
				if (! defined $x) { undef $ok; last; }
			}
		};

		if (! $ok) {
			$err = "did not receive expected results to STATS command";
		}
	}

	if ($err) {
		&logit($LOG_ERROR, "RRDCACHED: $err");
		&rrdCachedClose;
		return undef;
	}

	return 1;		# good!
}

sub rrdCachedClose
{
	&rrdCachedPut("QUIT") if ($rrdCachedSocketOpen);
	close(RRDCACHED);
	$rrdCachedSocketOpen = 0;
}

sub rrdCachedPut
{
	foreach (@_) {
		my $buf = $_ . "\n";
		&logit($LOG_DEBUG, "RRDCACHED: write " . length($buf) .  ": " . &hexit($buf));
		print RRDCACHED $buf;
	}
	return 1;
}

sub rrdCachedGet
{
	my $buf;

	if (! defined eval {
		local $SIG{ALRM} = sub { die; };
		alarm 1;
		$buf = <RRDCACHED>;
		&logit($LOG_DEBUG, "RRDCACHED: read " . length($buf) . ": " . &hexit($buf));
		chomp($buf);
	} ) {
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

