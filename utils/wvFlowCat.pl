#!/usr/bin/perl
# ------------------------------------------------
# wvFlowCat.pl
# Craig Weinhold, CDW
#
#  v1.0  6-26-03  initial version
#
# emulates flow-cat, but with perl ACL processing
# ------------------------------------------------

use Cflow qw(:flowvars find);   # for reading Cflowd data files
use Net::Patricia;
use Storable;

BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

my $acl = shift @ARGV;
my $globals = {};

$debug = (-t STDOUT);

# $debug = 1;

if (my $aclCode = &readACL($acl, $globals)) {
	# the ACL may depend on other ACLs. if so, add them to $codemid

	my $codepre = "sub wanted {\n";
	my $codesuf = "print \$raw if $aclCode;\n}\n";
	my $codemid;
	$aclCode =~ s/\$(ACL_\w+)/ $codemid .= " \$$1 = " . $globals->{$1} . ";\n" /ge;
	my $code = $codepre . $codemid . $codesuf;

	print STDERR "wvFlowCat: $code\n" if ($debug);

	eval $code;
	if ($@) {
		print STDERR "wvFlowCat: Error in eval: $code\n";
	}
	else {
		Cflow::find(\&wanted, \&perfile, @ARGV);
	}
}
else {
	print STDERR "wvFlowCat: acl $acl not found\n";
}

exit 0;

# --------------------------------------------------------------------------------

sub perfile
{
	print STDERR "working file=", $_[0], "\n";
}

# --------------------------------------------------------------------------------

sub readACL
{
	my($acl, $globals) = @_;
	my($reading, $aclCode);

	# --- read index file
	open(IN, $indexFile);
	while ( <IN> ) {
		chomp;
		if (/^\s*\[([^\]]+)\]\s*$/) {	   # bracketed section
			$reading = $1;
		}
		elsif ($reading =~ /ACLs/i) {
			if (/^(\S+)\t(.*)/) {
				$globals->{"$1"} = $2;
				$aclCode = $2 if ($acl eq $1);
			}

			elsif (/^(\S+:)(\S+)\t(.*)/) {
				$aclCode = $3 if ($acl eq "$1$2");
			}
		}
	}
	close(IN);

	if (! defined $aclCode) {
		print STDERR "Undefined ACL: $acl\n";		# note: this probably won't be seen
		return;
	}

	# at some point in the past, I believed the following code to
	# be flawed. But now I cannot figure out why. It seems necessary.
	# Perhaps I was concerned about 'use strict'

	# --- read DACL file
	if (-f $daclFile) {
		open(HASHCACHE, $daclFile);
		my(@elements) = @{Storable::fd_retrieve(\*HASHCACHE)};

		open(OUT, ">/tmp/dacls.txt");
		print OUT "reading $daclFile\n";

                foreach my $elem (@elements) {
			print OUT "[$elem]\n";
                        $$elem = new Net::Patricia;
                        my %hash = %{Storable::fd_retrieve(\*HASHCACHE)};
			my $count = 0;
#			print STDERR $elem . "\t" . join(' ', keys %hash) . "\n";
			# hash values may be IP or IP/bits
                        foreach (keys %hash) {
				print OUT $_ . "\t" . $hash{$_} . "\n";
				if (/^\d+\.\d+\.\d+\.\d+/) { $$elem->add_string($_, { 'k'=>$_, 'v'=>$hash{$_} } ); $count++; }
			}
                }
		close(OUT);

		close(HASHCACHE);
	}

	return $aclCode;
}
