#! /usr/local/bin/perl

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.
WriteMakefile(
	'NAME' => 'Net::Netmask',
	'DISTNAME' => 'Net-Netmask',
	'VERSION' => '1.3',
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'}
);

package MY;

sub postamble {
    <<"END_OF_POSTAMBLE";

pm_to_blib: README

README: Netmask.pod
\tpod2text Netmask.pod >README

END_OF_POSTAMBLE
}
