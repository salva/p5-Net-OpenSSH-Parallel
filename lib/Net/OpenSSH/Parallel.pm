package Net::OpenSSH::Parallel;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

use POSIX qw(WNOHANG);

sub new {
    my $class = shift;
    my $self = { joins => {},
		 hosts => {},
		 host_by_pid => {},
		 in_state => {
			      init => {},
			      connecting => {},
			      ready => {},
			      running => {},
			      done => {},
			     },
	       };
    bless $self, $class;
    $self;
}

sub add_host {
    my $self = shift;
    my $host = Net::OpenSSH::Paralle::Host->new(@_);
    my $label = $host->{label};
    $self->{hosts}{$label} = $host;
    $self->{hosts}{in_state}{done} = $host;
}

sub _set_host_state {
    my ($self, $host, $state) = @_;
    my $label = $host->{label};
    my $old = $host->{state};
    delete $self->{in_state}{$old}{$label}
	or die "internal error: host $label is in state $old but not in such queue";
    $self->{in_state}{$state}{$label} = 1;
    $host->{state} = $state;
}

my %sel2re_cache;

sub _selector_to_re {
    my ($self, $part) = @_;
    $sel2re_cache{$part} ||= do {
	$part = quotemeta $part;
	$part =~ s/\\\*/.*/g;
	qr/^$part$/;
    }
}

sub _select_labels {
    my ($self, $selector) = @_;
    my %sel;
    my @parts = split /\s*,\s*/, $selector;
    for (@parts) {
	my $re = $self->_selector_to_re($_);
	$sel{$_} = 1 for grep $_ =~ $re, keys %{$self->{hosts}};
    }
    return keys %sel;
}

sub push {
    my $self = shift;
    my $selector = shift;
    my $action = shift;
    my $in_state = $self->{in_state};
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    $action =~ /^(?:system|scp_get|scp_put)$/
	or croak "bad_action"

    my @labels = $self->_select_labels($selector);
    for my $label (@labels) {
	my $host = $self->{hosts}{$label};
	if ($in_state->{done}) {
	    if ($host->ssh) {
		$self->_set_host_state($host, 'ready')
	    }
	    else {
		$self->_set_host_state($host, 'init');
	    }

	}
	push @{$host->{queue}}, [$action, \%opts, @_];
    }
}

sub _at_init {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    $host->ssh and die "internal error: host in state init is already connected";
    my $ssh = $host->{ssh} = Net::OpenSSH->new(expand_vars => 1,
					       %{$host->{opts}},
					       async => 1);
    $ssh->error and die "unable to create connection to host $label";
    $ssh->set_var(LABEL => $label);
    $self->_set_host_state($host, 'connecting');

}

sub _at_connecting {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    if ($ssh->wait_for_master(1)) {
	$self->set_host_status('ready');
    }
    elsif ($ssh->error) {
	die "connection to $label failed: ". $ssh->error;
    }
}

sub _at_ready {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    my $queue = $host->{queue};
    my $task = shift @$queue;
    if (defined $task) {
	my $action = shift @$task;
	my $method = "_start_$action";
	my $pid = $self->$method($label, @$task);
	$pid or die "action $action failed to start: ". $host->{ssh}->error;
	$self->{host_by_pid}{$pid} = $label;
	$self->_set_host_state($label, 'running');
    }
    else {
	$self->_set_host_state($label, 'done');
    }
}

sub _start_system {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $ssh->spawn($opts, @_);
}

sub _start_scp_get {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $opts{async} = 1;
    $ssh->scp_get($opts, @_);
}

sub _start_scp_put {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $opts{async} = 1;
    $ssh->scp_put($opts, @_);
}

sub _wait_for_jobs {
    my ($self, $time) = @_;
    my $dontwait = ($time == 0);
    # This loop is here because we want to call waitpit before and
    # after the select. If we find some child has exited in the first
    # round we don't call select at all and return immediately
    while (1) {
	while (1) {
	    my $pid = waitpid(-1, WNOHANG);
	    last if $pid <= 0;
	    $dontwait = 1;
	    $self->_finish_action($pid, $?);
	}
	$dontwait and return 1;
	select(undef, undef, undef, $time);
	$dontwait = 1;
    }
}

sub run {
    my ($self, $time) = @_;
    my $hosts = $self->{hosts};
    my ($init, $connecting, $ready, $running, $done)
	= @{$self->{in_state}}[qw(init connecting ready running done)];
    while (1) {
	return 1 if keys(%$hosts) == keys(%$done);

	$self->_at_init($_) for keys %$init;
	$self->_at_connecting($_) for keys %$connecting;
	$self->_at_ready($_) for keys %$ready;
	my $time = ( keys(%$init) ? 0 :
		     keys(%$connecting) ? 0.1 :
		     3.0);
	$self->_wait_for_jobs($time);
    }
}


package Net::OpenSSH::Parallel::Host;
use Carp;

sub new {
    my $class = shift;
    my $label = shift;
    $label =~ /([,*!()<>\/{}])/ and croak "invalid char '$1' in host label";
    my %opts = (@_ & 1 ? host => @_ : @_);
    $opts{host} = $label unless defined $opts{host};

    my $self = { label => $label,
		 workers => 1,
		 status => 'new',
		 opts => \%opts,
		 ssh => undef,
		 state => 'done',
		 queue => []};
    bless $self, $class;
}

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
              '/remote/file/path', '/tmp/output');
  $pssh->push('*', scp_get => '/tmp/output', 'logs/%HOST%/output')

  $pssh->run;

=head1 DESCRIPTION

Run this here, that there, etc.

=head2 API


=head1 SEE ALSO

L<Net::OpenSSH>

=head1 COPYRIGHT AND LICENSE

Copyright E<copy> 2009 by Salvador FandiE<ntilde>o.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
