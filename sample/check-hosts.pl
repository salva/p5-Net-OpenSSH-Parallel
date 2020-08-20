#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Net::OpenSSH::Parallel;

my $retries = 2;
my $timeout = 10;
my $workers = 20;
my $key_check;
my $verbose;
my $cmd;
my $debug = 0;
my $filter;

my $log_fn = "/tmp/check-host-";

GetOptions("retries|r=i" => \$retries,
           "timeout|t=i" => \$timeout,
	   "workers|w=i" => \$workers,
           "verbose|v"   => \$verbose,
	   "debug|d=i"   => \$debug,
	   "filter|f"    => \$filter,
	   "key-check|k" => \$key_check,
	   "cmd|c=s"     => \$cmd);

$debug = 1 if $verbose and $debug == 0;

$Net::OpenSSH::Parallel::debug = -1 if $debug >= 3;

my @labels;
my %host;
my %name;
my $ix = 1;
while(<>) {
    chomp;
    next if /^\s*(#.*)?$/;
    my ($user, $passwd, $host) = /^\s*(?:([^:]+)(?::(.*))?\@)?(.*?)\s*$/;
    my $name = (length $user ? "$user\@$host" : $host);
    my $label = "${name}_$ix";
    $ix++;
    $label =~ s/[^\w\@]/_/g;
    $host{$label} = $_;
    $name{$label} = $name;
    push @labels, $label;
}

my @master_opts = ("-oConnectTimeout=$timeout");
push @master_opts, "-oUserKnownHostsFile=/dev/null", "-oStrictHostKeyChecking=no" unless $key_check;
push @master_opts, "-vv" if $debug;

my %cmd_opts;
$cmd_opts{stdout_discard} = 1 if $filter;
$cmd_opts{stderr_discard} = 1 if $filter;

my $p = Net::OpenSSH::Parallel->new(connections => $workers + 1,
				    workers => $workers);

for my $label (@labels) {
    my %opts = ( host => $host{$label},
		 reconnections => $retries,
		 master_opts => \@master_opts );

    if ($debug >= 2) {
	open my $log, ">", "$log_fn$label";
	$opts{master_stderr_fh} = $log
    }
    else {
	$opts{master_stderr_discard} = 1
    }
    $p->add_host($label, %opts)
}

$p->push('*', 'connect');
$p->push('*', 'cmd', \%cmd_opts, $cmd) if defined $cmd;
$p->run;

for my $label (@labels) {
    my $error = $p->get_error($label);
    if ($error) {
	if ($debug) {
	    if ($debug == 1) {
		print STDERR "$name{$label}: KO\n"
	    }
	    else {
		print STDERR "$name{$label}: KO (see $log_fn$label)\n"
	    }
	}
    }
    else {
	if ($filter) {
	    print "$host{$label}\n"
	}
	else {
	    print "$name{$label}: OK\n"
	}
    }
}


__END__

=head1 NAME

check-hosts.pl

=head1 SYNOPSIS

  check-hosts.pl [-r retries] [-t timeout] [-w workers] [-c cmd] [-v] [-f] [-k] path/to/file_with_host_list

=head1 DESCRIPTION

This script checks if the host in the given list are reachable.

The entries in the list of hosts must have one of the following formats:

    host_or_ip
    user@host_or_ip
    user:password@host_or_ip

The following optional arguments are accepted:

=over

=item -v

Verbose mode. When enable prints also the non-reachable hosts


=item -r, --retries=N

Reconnection retries

=item -t, --timeout=SECONDS

Connection timeout in seconds

=item -c, --cmd=REMOTE_COMMAND

Optional command to be run on the remote hosts.

=item -k, --key-check

By default the script skips the remote host key checking (as it
doesn't make sense if you are just checking the remote hosts are all
up).

This flag reactivates it.

=item -f, --filter

Changes the output format so that it becomes identical to the input
but with the non reachable hosts removed.

=item -w, --workers=N

Maximum number of parallel connections (or ssh workers).

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
