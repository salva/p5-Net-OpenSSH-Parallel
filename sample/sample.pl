#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH::Parallel;

my $osp = Net::OpenSSH::Parallel->new(debug => -1);
$osp->add_host("host-$_", "localhost") for 1..4;

$osp->push('*', system => 'echo %LABEL%');
$osp->push('*', system => "sleep `perl -e 'print int(rand 5), qq(\n)'`");
$osp->push('host-1,host-2', join => 'host-2,host-3');
$osp->push('*', system => 'echo goodbye');
$osp->run;
