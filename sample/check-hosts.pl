#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use Net::OpenSSH::Parallel;

my $retries = 2;
my $timeout = 10;
my $verbose;
my $cmd;

GetOptions("retries|r=i" => \$retries,
           "timeout|t=i" => \$timeout,
           "verbose|v"   => \$verbose,
	   "cmd|c"       => \$cmd);

my @hosts;
while(<>) {
    chomp;
    next if /^\s*(#.*)?$/;
    push @hosts, $_
}

my $p = Net::OpenSSH::Parallel->new(reconnections => 2);
$p->add_host($_,
	     reconnections => $retries,
	     master_stderr_discard => 1,
	     master_opts => ["-oConnectTimeout=$timeout"]) for @hosts;
$p->push('*', 'connect');
$p->push('cmd', $cmd) if defined $cmd;
$p->run;

for (@hosts) {
    my ($user, $passwd, $host) = /^\s*(?:([^:]+)(?::(.*))?\@)?(.*?)\s*$/;
    my $target = (length $user ? "$user\@$host" : $host);
    my $error = $p->get_error($_);
    if ($error) {
        print "$target: KO\n" if $verbose
    }
    else {
	print "$target: OK\n"
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

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
