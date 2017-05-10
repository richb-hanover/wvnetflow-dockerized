#!/usr/bin/perl
#
# getFilter.cgi
# Craig Weinhold, CDW
#
# produces a list of subnet masks and descriptions and lets the user choose.
# the selection is put into the IP/mask form element on adhoc.cgi
#
#  v1.0 2003-01-28  initial version.
#

use strict;
use CGI qw(:standard :html3 -nosticky);
use Socket;
use CGI::Carp qw( fatalsToBrowser );
BEGIN { require '/etc/webview.conf'; WebviewConfiguration->import(); }

our $field =  param('field');
our %ips

&loadSubnets(\%ips, $subnetFile);
&groomMasks(\%ips);

my $JSCRIPT = <<EOT;
function setIt(myvar)
{
	window.opener.document.inputForm.$field.value = myvar;
	window.blur();
	window.opener.focus();
}
EOT

print header,
	start_html(-title=>'Subnets',
		-script=>$JSCRIPT
		),

#	h3({-align=>center}, "Select a subnet from the list below"),

	"<pre>";

foreach (sort { uc($ips{$a}->{description}) cmp uc($ips{$b}->{description}) } keys %ips) {
	my $ipmask = $_ . "/" . $ips{$_}->{bits};
	my $desc = $ips{$_}->{description};
	my $padding = " " x (18 - length($ipmask));

	print $padding,
		a( {-href=>'javascript:setIt(' . "'" . $ipmask . "'" . ');'}, $ipmask ),
		" ", $desc, "\n";

#	print button(-name=>"foo", -value=>"*", -onClick=>"setIt();"),
#		"\n";
}

print "</pre>",
	end_html;

exit 0;


sub loadSubnets
{
	my($ips, $fName) = @_;

	open(IN, $fName);
	while ( <IN> ) {
		chomp;
		s/\s*[#;].*//;		# comments
		s/^\s+//;		# leading space
		s/\s+$//;		# trailing space

		next if (! /^([\d\.]+)\/?(\d*)\s+(.*)/);
		my($ip, $bits, $desc) = ($1, $2, $3);

		$ips->{$ip}->{description} = $desc;
		$ips->{$ip}->{bits} = $bits if (($bits > 0) || ($bits eq "0"));
	}
	close(IN);
}

sub byip
{
	my $a1 = pack('C4', $1, $2, $3, $4) if ($a =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
	my $b1 = pack('C4', $1, $2, $3, $4) if ($b =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
	return ($a1 cmp $b1);
}

sub groomMasks
{
	my($ips) = $_[0];
	my(@ipList) = sort byip keys %$ips;

	sub bestMask
	{
		my $ip = unpack('N', inet_aton(shift @_));
		my $nextip = unpack('N', inet_aton(shift @_));
		my $mask = 0xffffffff;
		my $bits = 33;
		my $minbits = ($ip < 0x80000000) ? 8 : (($ip < 0xC0000000) ? 16 : 24);

		while (1) {
#			printf("%08x -- %08x %08x -- %08x %08x\n",
#				$mask, $ip, ($ip & $mask), $nextip, ($nextip & $mask));

			last if ((($ip & $mask) != $ip) || (($nextip & $mask) == $ip));
			last if ($bits == $minbits);

			$bits--;
			last if (! $mask);			# reached 0.0.0.0/0
			$mask <<= 1;
		}
		return $bits;
	}

	my ($ip, $nextip);

	foreach (@ipList, "255.255.255.255") {
		$ip = $nextip;
		$nextip = $_;
		next if ( (! defined $ip) || ($ips->{$ip}->{bits}) );
		$ips->{$ip}->{bits} = &bestMask($ip, $nextip);
#		print "working on $ip  (next=$_ $nextIP)     bits=$bits\n";
	}
}

