#!/usr/bin/perl

use strict;
use warnings;

use Net::OpenSSH::Parallel;

my $p = Net::OpenSSH::Parallel->new(reconnections => 2);

while(<>) {
    chomp;
    next if /^\s*(#.*)?$/;
    $p->add_host($_)
}

$p->push('*', cmd => "echo", '%HOST% is alive');

$p->run;


__END__

=head1 NAME

check-hosts.pl

=head1 SYNOPSIS

  check-hosts.pl path/to/file_with_host_list

=head1 DESCRIPTION

This script checks if the host in the given list are reachable.

The entries in the list of hosts must have one of the following formats:

    host_or_ip
    user@host_or_ip
    user:password@host_or_ip

In order to ensure that the remote ssh connection is working, an
C<echo> command is issued there. That may not work when the remote
shell is something not reseambling a UNIX shell.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2020 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com)

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
