#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH::Parallel;
# $Net::OpenSSH::debug = 32;

my $hosts = 50;

my $osp = Net::OpenSSH::Parallel->new(maximum_workers => 5, maximum_connections => 5, debug => 0); #1|128|256);
$osp->add_host("host-$_", "localhost") for 1..$hosts;

$osp->push('*', system => 'echo %LABEL% starting');

# for (1..10*$hosts) {
#     $osp->push("host-" . (1+int(rand $hosts)), join => "host-" . (1 + int(rand $hosts)));
# }
$osp->push('host-1,host-2', join => 'host-2,host-3');
$osp->push('*', system =>
	   q{sleep `perl -e 'my $s = int(rand 3); print STDERR qq(%LABEL% sleeping for $s\n); print qq($s\n)'`});
$osp->push('*', join => '*');
$osp->push('*', system => 'echo goodbye %LABEL%');
$osp->run;
