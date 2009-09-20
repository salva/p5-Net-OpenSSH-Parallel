package Net::OpenSSH::Parallel;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp qw(croak carp verbose);

use Net::OpenSSH;
use POSIX qw(WNOHANG);
use Time::HiRes qw(time);

sub new {
    my ($class, %opts) = @_;

    my $debug = delete $opts{debug};
    %opts and croak "unknonwn option(s): ". join(", ", keys %opts);

    my $self = { joins => {},
		 hosts => {},
		 host_by_pid => {},
		 in_state => {
			      init => {},
			      connecting => {},
			      ready => {},
			      running => {},
			      done => {},
			      error => {},
			     },
		 debug => $debug || 0,
	       };
    bless $self, $class;
    $self;
}

my %debug_channel = (api => 1, state => 2, select => 4, at => 8, action => 16);

sub _debug {
    my $self = shift;
    my $channel = shift;
    my $bit = $debug_channel{$channel}
	or die "internal error: bad debug channel $channel";
    if ($self->{debug} & $debug_channel{$channel}) {
	print STDERR sprintf("%6.3f", (time - $^T)), "| ", join('', @_), "\n";
    }
}


sub add_host {
    my $self = shift;
    my $host = Net::OpenSSH::Parallel::Host->new(@_);
    my $label = $host->{label};
    $self->{hosts}{$label} = $host;
    $self->_debug(api => "[$label] added ($host)");
    $self->{in_state}{done}{$label} = 1;
    $self->_debug(state => "[$label] state set to done");
}

sub _set_host_state {
    my ($self, $label, $state) = @_;
    my $host = $self->{hosts}{$label};
    my $old = $host->{state};
    delete $self->{in_state}{$old}{$label}
	or die "internal error: host $label is in state $old but not in such queue";
    $self->{in_state}{$state}{$label} = 1;
    $host->{state} = $state;
    $self->_debug(state => "[$label] state changed $old --> $state");
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
    my @labels = keys %sel;
    $self->_debug(select => "selector($selector) --> [", join(', ', @labels), "]");
    return @labels;
}

sub push {
    my $self = shift;
    my $selector = shift;
    my $action = shift;
    my $in_state = $self->{in_state};
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    $action =~ /^(?:system|scp_get|scp_put)$/
	or croak "bad_action";

    my @labels = $self->_select_labels($selector);
    for my $label (@labels) {
	my $host = $self->{hosts}{$label};
	push @{$host->{queue}}, [$action, \%opts, @_];
	$self->_debug(api => "[$label] action $action queued");
	if ($in_state->{done}{$label}) {
	    if ($host->{ssh}) {
		$self->_set_host_state($label, 'ready')
	    }
	    else {
		$self->_set_host_state($label, 'init');
	    }
	}
    }
}

sub _at_init {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    $self->_debug(at => "[$label] at_init, starting SSH connection");
    $host->{ssh} and die "internal error: host in state init is already connected";
    my $ssh = $host->{ssh} = Net::OpenSSH->new(expand_vars => 1,
					       %{$host->{opts}},
					       async => 1);
    $ssh->error and die "unable to create connection to host $label";
    $ssh->set_var(LABEL => $label);
    $self->_set_host_state($label, 'connecting');

}

sub _at_connecting {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    $self->_debug(at => "[$label] at_connecting, waiting for master");
    my $ssh = $host->{ssh};
    if ($ssh->wait_for_master(1)) {
	$self->_debug(at => "[$label] at_connecting, master connected");
	$self->_set_host_state($label, 'ready');
    }
    elsif ($ssh->error) {
	die "connection to $label failed: ". $ssh->error;
    }
}

sub _at_ready {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    $self->_debug(at => "[$label] at_init");
    my $queue = $host->{queue};
    my $task = shift @$queue;
    if (defined $task) {
	my $action = shift @$task;
	$self->_debug(at => "[$label] at_init, starting new action $action");
	my $method = "_start_$action";
	my $pid = $self->$method($label, @$task);
	$pid or die "action $action failed to start: ". $host->{ssh}->error;
	$self->_debug(action => "[$label] action pid: $pid");
	$self->{host_by_pid}{$pid} = $label;
	$self->_set_host_state($label, 'running');
    }
    else {
	$self->_debug(at => "[$label] at_init, queue_is_empty, we are done!");
	$self->_set_host_state($label, 'done');
    }
}

sub _start_system {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $self->_debug(action => "[$label] start system action");
    $ssh->spawn($opts, @_);
}

sub _start_scp_get {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh}; 
    $self->_debug(action => "[$label] start scp_get action");
    $opts->{async} = 1;
    $ssh->scp_get($opts, @_);
}

sub _start_scp_put {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $self->_debug(action => "[$label] start scp_put action");
    $opts->{async} = 1;
    $ssh->scp_put($opts, @_);
}

sub _finish_action {
    my ($self, $pid, $rc) = @_;
    my $label = delete $self->{host_by_pid}{$pid};
    if (defined $label) {
	$self->_debug(action => "[$label] action finished pid: $pid, rc: $rc");
	$self->_set_host_state($label, 'ready');
	$rc and die "$label child (pid: $pid) exited with non-zero return code (rc: $rc)";
    }
    else {
	carp "espourios child exit (pid: $pid)";
    }
}

sub _wait_for_jobs {
    my ($self, $time) = @_;
    my $dontwait = ($time == 0);
    $self->_debug(at => "_wait_for_jobs time: $time");
    # This loop is here because we want to call waitpit before and
    # after the select. If we find some child has exited in the first
    # round we don't call select at all and return immediately
    while (1) {
	$self->_debug(at => "_wait_for_jobs reaping children");
	while (1) {
	    my $pid = waitpid(-1, WNOHANG);
	    my $rc = $?;
	    last if $pid <= 0;
	    $self->_debug(action => "waitpid caught pid: $pid, rc: $rc");
	    $dontwait = 1;
	    $self->_finish_action($pid, $rc);
	}
	$dontwait and return 1;
	$self->_debug(at => "_wait_for_jobs calling select");
	{
	    # This is a hack to make select finish as soon as we get a
	    # CHLD signal.
	    local $SIG{CHLD} = sub {};
	    select(undef, undef, undef, $time);
	}
	$dontwait = 1;
    }
}

sub run {
    my ($self, $time) = @_;
    my $hosts = $self->{hosts};
    my $in_state = $self->{in_state};
    my ($init, $connecting, $ready, $running, $done)
	= @{$in_state}{qw(init connecting ready running done)};
    while (1) {
	# use Data::Dumper;
	# print STDERR Dumper $self;
	$self->_debug(api => "run: iterating...");

	$self->_debug(at => "run: hosts at done: ", scalar(keys %$done), " of ", scalar(keys %$hosts));

	return 1 if keys(%$hosts) == keys(%$done);

	$self->_debug(at => "run: hosts at init: ", scalar(keys %$init));
	$self->_at_init($_) for keys %$init;

	$self->_at_connecting($_) for keys %$connecting;
	$self->_debug(at => "run: hosts at connecting: ", scalar(keys %$connecting));

	$self->_debug(at => "run: hosts at ready: ", scalar(keys %$ready));
	$self->_at_ready($_) for keys %$ready;

	my $time = ( keys(%$init) ? 0 :
		     keys(%$connecting) ? 0.1 :
		     3.0);

	$self->_debug(at => "run: hosts at running: ", scalar(keys %$running));
	$self->_wait_for_jobs($time) if keys %$running;
    }
}


package Net::OpenSSH::Parallel::Host;
use Carp;

sub new {
    my $class = shift;
    my $label = shift;
    $label =~ /([,*!()<>\/{}])/ and croak "invalid char '$1' in host label";
    my %opts = (@_ & 1 ? (host => @_) : @_);
    $opts{host} = $label unless defined $opts{host};

    my $self = { label => $label,
		 workers => 1,
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
