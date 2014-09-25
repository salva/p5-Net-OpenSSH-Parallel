#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

use Net::OpenSSH::Parallel;
use Socket;

my $net = shift // die "network missing\n";
my $passwd = shift;

my ($ip, $mask) = $net =~ m|^([^/]+)(?:/(\d+))?$|
    or die "bad network specification\n";

$mask ||= 24;
$mask < 20 and die "network too big\n";

my $addr = inet_aton($ip)
    or die "unable to resolve IP\n";

my $imask = (1 << (32 - $mask)) - 1;
my $iaddr = unpack(N => $addr) & ~$imask;

my $pssh = Net::OpenSSH::Parallel->new(connections => 64,
                                       reconnections => 0);

for my $i (0..$imask) {
    my $host = inet_ntoa(pack(N => $iaddr | $i));
    # warn "trying host: $host\n";
    $pssh->add_host($host,
                    password => $passwd,
                    master_stderr_discard => 1,
                    timeout => 20,
                    master_opts => ['-oStrictHostKeyChecking=no',
                                    '-oUserKnownHostsFile=/dev/null']);
}

$pssh->all(cmd => 'echo `hostname` "=>" %HOST%');
$pssh->run;

__END__

=head1 NAME

find-my-machines.pl

=head1 SYNOPSIS

  find-my-machines.pl <network>[/<mask>]

=head1 DESCRIPTION

This program tries to connect to all the IPs in the given range
through SSH and log with the user default public keys.

Then, for every host where it is able to log in, the hostname and IP
is printed.

=head1 EXAMPLE

  $ find-my-machines.pl 10.0.8.0/23
  vpn => 10.0.9.151
  atun => 10.0.9.138

=head1 SEE ALSO

The blog L<entry|http://blogs.perl.org/users/salvador_fandino/2014/02/finding-my-computer.html>.

=head1 COPYRIGHT AND LICENSE

Copyright E<copy> 2014 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
