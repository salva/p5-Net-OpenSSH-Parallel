#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Net::OpenSSH::Parallel;

my $retries = 2;
my $timeout = 10;
my $key_check;
my $verbose;
my $cmd;
my $debug;

GetOptions("retries|r=i" => \$retries,
           "timeout|t=i" => \$timeout,
           "verbose|v"   => \$verbose,
	   "debug|d"     => \$debug,
	   "key-check|k" => \$key_check,
	   "cmd|c=s"     => \$cmd);

if ($debug) {
    $Net::OpenSSH::Parallel::debug = -1;
}

my @labels;
my %host;
while(<>) {
    chomp;
    next if /^\s*(#.*)?$/;
    my ($user, $passwd, $host) = /^\s*(?:([^:]+)(?::(.*))?\@)?(.*?)\s*$/;
    my $label = (length $user ? "$user\@$host" : $host);
    $host{$label} = $_;
    push @labels, $label;
}

my @master_opts = "-oConnectTimeout=$timeout";
push @master_opts, "-oUserKnownHostsFile=/dev/null", "-oStrictHostKeyChecking=no" unless $key_check;

my $p = Net::OpenSSH::Parallel->new;
$p->add_host($_,
	     host => $host{$_},
	     reconnections => $retries,
	     master_stderr_discard => 1,
	     master_opts => \@master_opts) for @labels;
$p->push('*', 'connect');
$p->push('*', 'cmd', $cmd) if defined $cmd;
$p->run;

for (@labels) {
    my ($user, $passwd, $host) = /^\s*(?:([^:]+)(?::(.*))?\@)?(.*?)\s*$/;
    my $error = $p->get_error($_);
    if ($error) {
        print STDERR "$_: KO\n" if $verbose
    }
    else {
	print "$_: OK\n"
    }
}


__END__

=head1 NAME

check-hosts.pl

=head1 SYNOPSIS

  check-hosts.pl [-r retries] [-t timeout] [-c cmd] [-v] path/to/file_with_host_list

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

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
