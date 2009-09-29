#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH::Parallel;
use Net::OpenSSH::Parallel::Constants qw(:all);
$Net::OpenSSH::debug = -1;

my $hosts = 4;

my $osp = Net::OpenSSH::Parallel->new(workers => 5, connections => 5, debug => 0); #1|128|256);
$osp->add_host("host-$_", "localhost") for 1..$hosts;
$osp->add_host("foo", "foo", on_error => OSSH_ON_ERROR_ABORT);
$osp->push('*', cmd => 'echo %LABEL% starting');

# for (1..10*$hosts) {
#     $osp->push("host-" . (1+int(rand $hosts)), join => "host-" . (1 + int(rand $hosts)));
# }
$osp->push('host-1,host-2', join => 'host-2,host-3');
$osp->push('*', cmd =>
	   q{sleep `perl -e 'my $s = int(rand 3); print STDERR qq(%LABEL% sleeping for $s\n); print qq($s\n)'`});
$osp->push('*', join => '*');
$osp->push('*', command => 'echo goodbye %LABEL%');
$osp->run;
