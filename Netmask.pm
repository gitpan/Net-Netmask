
package Net::Netmask;

use vars qw($VERSION);
$VERSION = 1.4;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(findNetblock);
@EXPORT_OK = qw(int2quad quad2int %quadmask2bits imask);

my $remembered = {};
my %quadmask2bits;
my %imask2bits;

use strict;
use Carp;

sub new
{
	my ($package, $net, $mask) = @_;

	$mask = '' unless defined $mask;

	my $base;
	my $bits;
	my $error;
	my $ibase;

	if ($net =~ m,^(\d+\.\d+\.\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ($1, $2);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+):(\d+\.\d+\.\d+\.\d+)$,) {
		$base = $1;
		my $quadmask = $2;
		if (exists $quadmask2bits{$quadmask}) {
			$bits = $quadmask2bits{$quadmask};
		} else {
			$error = "illegal netmask: $quadmask";
		}
	} elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,)
		&& ($mask =~ m,\d+\.\d+\.\d+\.\d+$,)) 
	{
		$base = $net;
		if (exists $quadmask2bits{$mask}) {
			$bits = $quadmask2bits{$mask};
		} else {
			$error = "illegal netmask: $mask";
		}
	} elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,) &&
		($mask =~ m,0x[a-z0-9]+,i)) 
	{
		$base = $net;
		my $imask = hex($mask);
		if (exists $imask2bits{$imask}) {
			$bits = $imask2bits{$imask};
		} else {
			$error = "illegal netmask: $mask ($imask)";
		}
	} elsif ($net =~ /^\d+\.\d+\.\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ($net, 32);
	} elsif ($net =~ /^\d+\.\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0", 24);
	} elsif ($net =~ /^\d+\.\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0.0", 16);
	} elsif ($net =~ /^\d+$/ && ! $mask) {
		($base, $bits) = ("$net.0.0.0", 8);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ("$1.0", $2);
	} elsif ($net =~ m,^(\d+\.\d+)/(\d+)$,) {
		($base, $bits) = ("$1.0.0", $2);
	} elsif ($net eq 'default') {
		($base, $bits) = ("0.0.0.0", 0);
	} else {
		$error = "could not parse $net $mask";
	}

	warn $error if $error;

	$ibase = quad2int($base) unless $ibase;
	$ibase &= imask($bits);

	return bless { 
		'IBASE' => $ibase,
		'BITS' => $bits, 
		'ERROR' => $error,
	};
}

sub base { my ($this) = @_; return int2quad($this->{'IBASE'}); }
sub bits { my ($this) = @_; return $this->{'BITS'}; }
sub size { my ($this) = @_; return 2**(32- $this->{'BITS'}); }
sub next { my ($this) = @_; int2quad($this->{'IBASE'} + $this->size()); }
sub broadcast {
    my($this) = @_;
    int2quad($this->{'IBASE'} + $this->size() - 1);
}

sub desc 
{ 
	my ($this) = @_; 
	return int2quad($this->{'IBASE'}).'/'.$this->{'BITS'};
}

sub imask 
{
	return (2**32 -(2** (32- $_[0])));
}

sub mask 
{
	my ($this) = @_;

	return int2quad ( imask ($this->{'BITS'}));
}

sub hostmask
{
	my ($this) = @_;

	return int2quad ( ~ imask ($this->{'BITS'}));
}

sub enumerate
{
	my ($this) = @_;
	my $size = $this->size();
	my @ary;
	my $ibase = $this->{'IBASE'};
	for (my $i = 0; $i < $size; $i++) {
		push(@ary, int2quad($ibase+$i));
	}
	return @ary;
}

sub inaddr
{
	my ($this) = @_;
	my $ibase = $this->{'IBASE'};
	my $blocks = int($this->size()/256);
	return (join('.',unpack('xC3', pack('V', $ibase))).".in-addr.arpa",
		$ibase%256, $ibase%256+$this->size()-1) if $blocks == 0;
	my @ary;
	for (my $i = 0; $i < $blocks; $i++) {
		push(@ary, join('.',unpack('xC3', pack('V', $ibase+$i*256)))
			.".in-addr.arpa", 0, 255);
	}
	return @ary;
}

sub quad2int
{
	return unpack("N", pack("C4", split(/\./, $_[0])));
}

sub int2quad
{
	return join('.',unpack('C4', pack("N", $_[0])));
}

sub storeNetblock
{
	my ($this, $t) = @_;
	$t = $remembered unless $t;

	my $base = $this->{'IBASE'};

	$t->{$base} = [] unless exists $t->{$base};

	my $mb = maxblock($this);
	my $b = $this->{'BITS'};
	my $i = $b - $mb;

	$t->{$base}->[$i] = $this;
}

sub findNetblock
{
	my ($ipquad, $t) = @_;
	$t = $remembered unless $t;

	my $ip = quad2int($ipquad);

	for (my $b = 32; $b >= 0; $b--) {
		my $im = imask($b);
		my $nb = $ip & $im;
		if (exists $t->{$nb}) {
			my $mb = imaxblock($nb, 32);
			my $i = $b - $mb;
			confess "$mb, $b, $ipquad, $nb" if $i < 0;
			confess "$mb, $b, $ipquad, $nb" if $i > 32;
			while ($i >= 0) {
				return $t->{$nb}->[$i]
					if defined $t->{$nb}->[$i];
				$i--;
			}
		}
	}
}

sub maxblock 
{ 
	my ($this) = @_;
	return imaxblock($this->{'IBASE'}, $this->{'BITS'});
}

sub imaxblock
{
	my ($ibase, $tbit) = @_;
	confess unless defined $ibase;
	while ($tbit > 0) {
		my $im = imask($tbit-1);
		last if (($ibase & $im) != $ibase);
		$tbit--;
	}
	return $tbit;
}



BEGIN {
	for (my $i = 0; $i <= 32; $i++) {
		$imask2bits{imask($i)} = $i;
		$quadmask2bits{int2quad(imask($i))} = $i;
	}
}
