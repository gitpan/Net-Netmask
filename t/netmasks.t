#!/usr/local/bin/perl -I. -w

use Net::Netmask;

#  addr			mask		base		newmask	     bits  mb
my @rtests = qw(
 209.157.68.22:255.255.224.0	u	209.157.64.0	255.255.224.0	19 18
 209.157.68.22		255.255.224.0	209.157.64.0	255.255.224.0	19 18
 209.157.70.33		0xffffe000	209.157.64.0	255.255.224.0	19 18
 209.157.70.33/19		u	209.157.64.0	255.255.224.0	19 18
 209.157.70.33			u	209.157.70.33	255.255.255.255	32 32
 140.174.82			u	140.174.82.0	255.255.255.0	24 23
 140.174			u	140.174.0.0	255.255.0.0	16 15
 10				u	10.0.0.0	255.0.0.0	8  7
 209.157.64/19			u	209.157.64.0	255.255.224.0	19 18
 209.157.64.0-209.157.95.255	u	209.157.64.0	255.255.224.0	19 18
 209.157/17			u	209.157.0.0	255.255.128.0	17 16
 default			u	0.0.0.0		0.0.0.0		0  0
);

my @store = qw(
 209.157.64.0/19
 default
 209.157.81.16/28
 209.157.80.0/20
);

my @lookup = qw(
 209.157.75.75	209.157.64.0/19
 209.157.32.10	0.0.0.0/0
 209.157.81.18	209.157.81.16/28
 209.157.81.14	209.157.80.0/20
);

my @store2 = qw(
 209.157.64.0/19
 default
 209.157.81.16/28
 209.157.80.0/24
);

my @lookup2 = qw(
 209.157.75.75	209.157.64.0/19
 209.157.32.10	0.0.0.0/0
 209.157.81.18	209.157.81.16/28
 209.157.81.14	209.157.64.0/19
);

printf "1..%d\n", ($#rtests+1) / 6 * 4 + 3 + 3 + 6 + 1 + 7 + 3 + 4
	+ ($#lookup+1)/2 + ($#lookup2+1)/2 + 3;

my $debug = 0;
my $test = 1;
my $x;

my ($addr, $mask, $base, $newmask, $bits, $max);
while (($addr, $mask, $base, $newmask, $bits, $max) = splice(@rtests, 0, 6)) {
	$mask = undef if $mask eq 'u';
	$x = new Net::Netmask ($addr, $mask);

	printf STDERR "test $test, %s %s: %s %s %d %d\n", 
		$addr, $mask, $x->base(), $x->mask(), 
		$x->bits(), $x->maxblock() if $debug;
	
	print $x->base() eq $base ? "ok $test\n" : "not ok $test\n"; $test++;
	print $x->mask() eq $newmask ? "ok $test\n" : "not ok $test\n"; $test++;
	print $x->maxblock() == $max ? "ok $test\n" : "not ok $test\n"; $test++;
	print $x->bits() == $bits ? "ok $test\n" : "not ok $test\n"; $test++;
}

my @y;

$x = new Net::Netmask ('209.157.64.0/19');
print $x->size() == 8192 ? "ok $test\n" : "not ok $test\n"; $test++;

print $x->hostmask() eq '0.0.31.255' ? "ok $test\n" : "not ok $test\n"; $test++;

@y = $x->inaddr();
print STDERR "REVERSE: @y\n" if $debug;
print $y[0] eq '64.157.209.in-addr.arpa' 
	? "ok $test\n" : "not ok $test\n"; $test++;
print $y[31*3] eq '95.157.209.in-addr.arpa' 
	? "ok $test\n" : "not ok $test\n"; $test++;
print defined($y[32*3]) ? "not ok $test\n" : "ok $test\n"; $test++;

$x = new Net::Netmask ('140.174.82.4/32');
print $x->size() == 1 ? "ok $test\n" : "not ok $test\n"; $test++;

# perl bug: cannot just print this.
my $p = ($x->inaddr())[0] eq '82.174.140.in-addr.arpa' 
	?  "ok $test\n"
	: "not ok $test\n";
print $p;
printf STDERR "REVERSE$test %s\n", $x->inaddr() if $debug;
$test++;

$x = new Net::Netmask ('140.174.82.64/27');
print (($x->inaddr())[1] == 64 ? "ok $test\n" : "not ok $test\n"); $test++;
print (($x->inaddr())[2] == 95 ? "ok $test\n" : "not ok $test\n"); $test++;
@y = $x->inaddr();
print STDERR "Y$test @y\n" if $debug;

$x = new Net::Netmask ('default');
print $x->size() == 4294967296 ? "ok $test\n" : "not ok $test\n"; $test++;

$x = new Net::Netmask ('209.157.64.0/27');
@y = $x->enumerate();
print $y[0] eq '209.157.64.0' ? "ok $test\n" : "not ok $test\n"; $test++;
print $y[31] eq '209.157.64.31' ? "ok $test\n" : "not ok $test\n"; $test++;
print defined($y[32]) ? "not ok $test\n" : "ok $test\n"; $test++;

$x = new Net::Netmask ('10.2.0.16/19');
@y = $x->enumerate();
print $y[0] eq '10.2.0.0' ? "ok $test\n" : "not ok $test\n"; $test++;
print $y[8191] eq '10.2.31.255' ? "ok $test\n" : "not ok $test\n"; $test++;
print defined($y[8192]) ? "not ok $test\n" : "ok $test\n"; $test++;

my $table = {};

for my $b (@store) {
	$x = new Net::Netmask ($b);
	$x->storeNetblock();
}

for my $b (@store2) {
	$x = new Net::Netmask ($b);
	$x->storeNetblock($table);
}

my $result;
while (($addr, $result) = splice(@lookup, 0, 2)) {
	my $nb = findNetblock($addr);
	printf STDERR "lookup(%s): %s, wanting %s.\n",
		$addr, $nb->desc(), $result if $debug;
	print $nb->desc() eq $result ? "ok $test\n" : "not ok $test\n"; $test++;
}

while (($addr, $result) = splice(@lookup2, 0, 2)) {
	my $nb = findNetblock($addr, $table);
	printf STDERR "lookup(%s): %s, wanting %s.\n",
		$addr, $nb->desc(), $result if $debug;
	print $nb->desc() eq $result ? "ok $test\n" : "not ok $test\n"; $test++;
}


$newmask = Net::Netmask->new("192.168.1.0/24");
print (($newmask->broadcast() eq "192.168.1.255") ? "ok $test\n" : "not ok $test\n"); $test++;
print (($newmask->next() eq "192.168.2.0") ? "ok $test\n" : "not ok $test\n"); $test++;
print ($newmask->match("192.168.0.255") ? "not ok $test\n" : "ok $test\n"); $test++;
print ($newmask->match("192.168.2.0") ? "not ok $test\n" : "ok $test\n"); $test++;
print ($newmask->match("10.168.2.0") ? "not ok $test\n" : "ok $test\n"); $test++;
print ($newmask->match("209.168.2.0") ? "not ok $test\n" : "ok $test\n"); $test++;
print ($newmask->match("192.168.1.0") ? "ok $test\n" : "not ok $test\n"); $test++;
print ($newmask->match("192.168.1.255") ? "ok $test\n" : "not ok $test\n"); $test++;
print ($newmask->match("192.168.1.63") ? "ok $test\n" : "not ok $test\n"); $test++;

print (($newmask->nth(1) eq '192.168.1.1') ? "ok $test\n" : "not ok $test\n"); $test++;
print (($newmask->nth(-1) eq '192.168.1.255') ? "ok $test\n" : "not ok $test\n"); $test++;
print (($newmask->nth(-2) eq '192.168.1.254') ? "ok $test\n" : "not ok $test\n"); $test++;
print (($newmask->nth(0) eq '192.168.1.0') ? "ok $test\n" : "not ok $test\n"); $test++;

my $bks;
$block = new Net::Netmask '209.157.64.1/32';
$block->storeNetblock($bks);
print findNetblock('209.157.64.1',$bks) ? "ok $test\n" : "not ok $test\n"; $test++;

