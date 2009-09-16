package Net::OpenSSH::Parallel;

our $VERSION = '0.01';

use strict;
use warnings;

sub new {
    my $class = shift;
    my $self = { queues => {},
		 joins => {},
		 queue_by_pid => {} };
    bless $self, $class;
    $self;
}

sub add_queue {
    my $self = shift;
    my $queue = Net::OpenSSH::Paralle::Queue->new(@_);
    $self->{queues}{$queue->label} = $queue;
}

package Net::OpenSSH::Parallel::Queue;
use Carp;

sub new {
    my $class = shift;
    my $label = shift;
    $label =~ /([,*!()<>\/{}])/ and croak "invalid char '$1' in queue label";
    my %opts = (@_ & 1 ? host => @_ : @_);
    $opts{host} = $label unless defined $opts{host};

    my $self = { label => $label,
		 workers => 1,
		 status => 'new',
		 opts => \%opts,
		 ssh => undef,
		 queue => []};
    bless $self, $class;
}

sub label { shift->{label} }

1;
__END__

=head1 NAME

Net::OpenSSH::Parallel - Run SSH jobs in parallel

=head1 SYNOPSIS

  use Net::OpenSSH::Parallel;

  my $pssh = Net::OpenSSH::Parallel->new(max_connections => 50, max_workers => 30);
  for my $h (@hosts)
    $pssh->add_queue($h);
  }

  $pssh->push('*', scp_put => '/local/file/path', '/remote/file/path');
  $pssh->push('*', system => 'gurummm',
              '/remote/file/path', '/tmp/output.%HOST%');
  $pssh->push('*', scp_get => '/tmp/output.%HOST%', 'logs/')


=head1 DESCRIPTION

Stub documentation for Net::OpenSSH::Parallel, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandino, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Salvador Fandino

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.


=cut
