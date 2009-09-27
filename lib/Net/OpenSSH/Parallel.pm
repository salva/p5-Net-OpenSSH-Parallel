package Net::OpenSSH::Parallel;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp qw(croak carp verbose);

use Net::OpenSSH;
use Net::OpenSSH::Parallel::Constants qw(:error :on_error);

use POSIX qw(WNOHANG);
use Time::HiRes qw(time);

sub new {
    my ($class, %opts) = @_;

    my $debug = delete $opts{debug};
    my $max_workers = delete $opts{workers};
    my $max_conns = delete $opts{connections};
    my $on_error = delete $opts{on_error};

    if ($max_conns) {
	if ($max_workers) {
	    $max_conns < $max_workers and
		croak "connections ($max_conns) < workers ($max_workers)";
	}
	else {
	    $max_workers = $max_conns;
	}
    }

    %opts and croak "unknonwn option(s): ". join(", ", keys %opts);

    my $self = { joins => {},
		 hosts => {},
		 host_by_pid => {},
		 in_state => {
			      connecting => {},
			      ready => {},
			      running => {},
			      done => {},
			      waiting => {},
			      error => {},
			      suspended => {},
			     },
		 connected => { suspended => {},
				waiting => {},
			      },
		 joins => {},
		 debug => $debug || 0,
		 max_workers => $max_workers,
		 max_conns => $max_conns,
		 num_conns => 0,
		 on_error => $on_error,
	       };
    bless $self, $class;
    $self;
}

my %debug_channel = (api => 1, state => 2, select => 4, at => 8,
		     action => 16, join => 32, workers => 64,
		     connect => 128, conns => 256);

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
    my $label = shift;
    $label =~ /([,*!()<>\/{}])/ and croak "invalid char '$1' in host label";
    my %opts = (@_ & 1 ? (host => @_) : @_);
    $opts{host} = $label unless defined $opts{host};

    my $host = { label => $label,
		 workers => 1,
		 opts => \%opts,
		 ssh => undef,
		 state => 'done',
		 queue => []
	       };

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
    delete $self->{connected}{$old}{$label}
	if ($old eq 'suspended' or $old eq 'waiting');

    $self->{in_state}{$state}{$label} = 1;
    $host->{state} = $state;
    $self->_debug(state => "[$label] state changed $old --> $state");

    if ($host->{ssh} and ($state eq 'suspended' or $state eq 'waiting')) {
	$self->{connected}{$state}{$label} = 1;
	$self->_debug(state => "[$label] host is connected");
    }
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

my %action_alias = (get => 'scp_get',
		    put => 'scp_put',
		    cmd => 'command');

sub push {
    my $self = shift;
    my $selector = shift;
    my $action = shift;
    my $in_state = $self->{in_state};
    my %opts = (ref $_[0] eq 'HASH' ? %{shift()} : ());

    if (ref $action eq 'CODE') {
	$action = 'sub';
	unshift @_, $action;
    }

    my $alias = $action_alias{$action};
    $action = $alias if defined $alias;

    $action =~ /^(?:command|scp_get|scp_put|join|sub|_notify)$/
	or croak "bad action '$action'";

    my @labels = $self->_select_labels($selector);

    if (keys %opts and
	($action eq 'join' or
	 $action eq 'sub')) {
	croak "$action action does not accept options";
    }

    if ($action eq 'join') {
	my $notify_selector = shift @_;
	my $join = { id => '#' . $self->{join_seq}++,
		     depends => {},
		     notify => [] };
	my @depends = $self->push($notify_selector, _notify => {}, $join)
	    or do {
		$join->_debug(join => "join $join->{id} does not depend on anything, ignoring!");
		return ();
	    };
	$join->{depends}{$_} = 1 for @depends;

	for my $label (@labels) {
	    my $host = $self->{hosts}{$label};
	    push @{$host->{queue}}, [$action, {}, $join];
	    $self->_debug(api => "[$label] join $join->{id} queued");
	}
    }
    else {
	for my $label (@labels) {
	    my $host = $self->{hosts}{$label};
	    push @{$host->{queue}}, [$action, \%opts, @_];
	    $self->_debug(api => "[$label] action $action queued");
	    $self->_set_host_state($label, 'ready')
		if $in_state->{done}{$label};
	}
    }
    return @labels;
}

sub _audit_conns {
    my $self = shift;
    my $hosts = $self->{hosts};
    my $num = 0;
    $num++ for grep $_->{ssh}, values %$hosts;
    $self->_debug(conns => "audit_conns counted: $num, saved: $self->{num_conns}");
    $num == $self->{num_conns}
	or die "internal error: wrong number of connections, counted: $num, saved: $self->{num_conns}";
    my $in_state = $self->{in_state};
    for my $state (keys %$in_state) {
	my $num = 0;
	$num++ for grep $hosts->{$_}{ssh}, keys %{$in_state->{$state}};
	my $total = keys %{$in_state->{$state}};
	print STDERR "conns in state $state: $num of $total\n";
    }
}

sub _at_error {
    my ($self, $label, $error) = @_;
    my $host = $self->{hosts}{$label};
    my $task = delete $host->{current_task};

    my $on_error;
    if ($error == OSSH_MASTER_FAILED and
	$host->{status} ne 'connecting') {
	# it seems we have just lost the connection to the
	# remote host, retry unconditionally!
	$on_error = OSSH_ON_ERROR_RETRY
    }
    else {
	$on_error = $task->[1]{on_error} if $task;
	$on_error ||= $host->{on_error};
	$on_error ||= $self->{on_error};

	if (ref $on_error eq 'CODE') {
	    if ($error == OSSH_JOIN_FAILED) {
		$on_error = $on_error->($self, $label, $error);
	    }
	    else {
		$on_error = $on_error->($self, $label, $error, $task);
	    }
	}

	$on_error = $on_error->($self, $label, $error, $task)
	    if ref $on_error eq 'CODE';

	$on_error ||= OSSH_ON_ERROR_ABORT;
    }

    if ($on_error == OSSH_ON_ERROR_IGNORE) {
	if ($error == OSSH_MASTER_FAILED) {
	    # stablishing a new connection failed, what we should do?
	    # currently we remove the next task from the queue and
	    # continue.
	    shift @{$host->{queue}};
	    $self->_set_host_status($label, 'ready');
	    $self->_disconnect_host($label);
	}
    }
    elsif ($on_error == OSSH_ON_ERROR_DONE or
	   $on_error == OSSH_ON_ERROR_ABORT or
	   $on_error == OSSH_ON_ERROR_ABORT_ALL) {
	my $queue = $self->{queue};
	my $failed = ($on_error != OSSH_ON_ERROR_DONE);
	while (my $task = shift @$queue) {
	    my ($action, undef, $join) = @$task;
	    $self->_join_notify($label, $join, $failed)
		if $action eq '_notify';
	}

	$on_error == OSSH_ON_ERROR_ABORT_ALL
	    and $self->{abort_all} = 1;

	$self->_set_host_state($label, 'done');
	$self->_disconnect_host($label);
    }
    else {
	die "unknown on_error code $on_error"
    }
}

sub _at_connect {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    $self->_debug(connect => "[$label] _connect, starting SSH connection");
    $host->{ssh} and die "internal error: connecting host is already connected";
    my $ssh = $host->{ssh} = Net::OpenSSH->new(expand_vars => 1,
					       %{$host->{opts}},
					       async => 1);
    $ssh->set_var(LABEL => $label);
    $self->{num_conns}++;
    $self->_set_host_state($label, 'connecting');
    if ($ssh->error) {
	$self->_at_error($label, $ssh->error);
    }
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
	$self->_at_error($label, $ssh->error);
    }
}

sub _join_notify {
    my ($self, $label, $join, $failed) = @_;
    # use Data::Dumper;
    # print STDERR Dumper $join;
    delete $join->{depends}{$label}
	or die "internal error: $join->{id} notified for non dependent label $label";
    $self->_debug(join => "removing dependent $label from join $join->{id}");
    $join->{failed} = 1 if $failed;
    if (not %{$join->{depends}}) {
	$self->_debug(join => "join $join->{id} done");
	$join->{done} = 1;
	my $failed = $join->{failed};
	for my $label (@{$join->{notify}}) {
	    $self->_debug(join => "notifying $label about join $join->{id} done");
	    $self->_set_host_state($label, $failed ? 'join_failed' : 'ready');
	}
    }
    # print STDERR Dumper $join;
}

sub _num_workers {
    my $in_state = shift->{in_state};
    ( keys(%{$in_state->{ready}}) +
      keys(%{$in_state->{running}}) +
      keys(%{$in_state->{connecting}}) );
}

sub _disconnect_host {
    my ($self, $label) = @_;
    my $host = $self->{hosts}{$label};
    my $state = $host->{state};
    $state =~ /^(?:waiting|suspended|done|connecting)$/
	or die "internal error: disconnecting $label in state $state";
    if ($host->{ssh}) {
	$self->_debug(connect => "[$label] disconnecting host");
	undef $host->{ssh};
	$self->{num_conns}--;
	$self->_set_host_state($label, $state);
    }
}

sub _disconnect_any_host {
    my $self = shift;
    my $connected = $self->{connected};
    $self->_debug(conns => "disconnect any host");
    # $self->_audit_conns;
    my $label;
    for my $state (qw(suspended waiting)) {
	# use Data::Dumper;
	# print Dumper $connected;
	$self->_debug(conns => "looking for connected host in state $state");
	($label) = each %{$connected->{$state}};
	keys %{$connected->{$state}}; # reset iterator
	last if defined $label;
    }
    $self->_debug(conns => "[$label] disconnecting");
    defined $label or die "internal error: unable to disconnect any host";
    $self->_disconnect_host($label);
}

sub _at_ready {
    my ($self, $label) = @_;
    if (my $max_workers = $self->{max_workers}) {
	my $in_state = $self->{in_state};
	my $num_workers = $self->_num_workers;
	$self->_debug(workers => "num workers: $num_workers, maximun: $max_workers");
	if ($num_workers > $max_workers) {
	    $self->_debug(workers => "[$label] suspending");
	    $self->_set_host_state($label, 'suspended');
	    return;
	}
    }

    my $host = $self->{hosts}{$label};
    $self->_debug(at => "[$label] at_ready");

    unless ($host->{ssh}) {
	if (my $max_conns = $self->{max_conns}) {
	    $self->_disconnect_any_host() if $self->{num_conns} >= $max_conns;
	}
	$self->_debug(at => "[$label] host is not connected, connecting...");
	$self->_at_connect($label);
	return;
    }

    my $queue = $host->{queue};
    while (my $task = shift @$queue) {
	my $action = shift @$task;
	$self->_debug(at => "[$label] at_ready, starting new action $action");
	if ($action eq 'join') {
	    my (undef, $join) = @$task;
	    if ($join->{done}) {
		if ($join->{failed}) {
		    $self->_at_error($label, OSSH_JOIN_FAILED);
		    return;
		}
		$self->_debug(action => "[$label] join $join->{id} already done");
		next;
	    }
	    CORE::push @{$join->{notify}}, $label;
	    $self->_set_host_state($label, 'waiting');
	}
	elsif ($action eq '_notify') {
	    my (undef, $join) = @$task;
	    $self->_join_notify($label, $join);
	    next;
	}
	elsif ($action eq 'sub') {
	    my (undef, $sub) = @$task;
	    $self->_debug(action => "[$label] calling sub $sub");
	    $sub->($self, $label, @$task);
	    next;
	}
	else {
	    $host->{current_task} = [$action => @$task];
	    my %opts = %{shift @$task};
	    delete $opts{on_error};
	    my $method = "_start_$action";
	    my $pid = $self->$method($label, @$task);
	    $self->_debug(action => "[$label] action pid: ", $pid);
	    unless (defined $pid) {
		$self->_at_error($label, $host->{ssh}->error || OSSH_SLAVE_FAILED);
		return;
	    }
	    $self->{host_by_pid}{$pid} = $label;
	    $self->_set_host_state($label, 'running');
	}
	return;
    }
    $self->_debug(at => "[$label] at_ready, queue_is_empty, we are done!");
    $self->_set_host_state($label, 'done');
    $self->_disconnect_host($label);
}

sub _start_command {
    my $self = shift;
    my $label = shift;
    my $opts = shift;
    my $host = $self->{hosts}{$label};
    my $ssh = $host->{ssh};
    $self->_debug(action => "[$label] start command action [@_]");
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

sub _start_join {
    my $self = shift;
    my $label = shift;
}

sub _finish_action {
    my ($self, $pid) = @_;
    my $label = delete $self->{host_by_pid}{$pid};
    if (defined $label) {
	$self->_debug(action => "[$label] action finished pid: $pid, rc: $?");
	$self->_set_host_state($label, 'ready');
	if ($?) {
	    $self->_at_error($label,
			     dualvar(OSSH_SLAVE_FAILED, "child exited with non-zero return code"));
	}
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
	if (%{$self->{in_state}{running}}) {
	    $self->_debug(at => "_wait_for_jobs reaping children");
	    while (1) {
		my $pid = waitpid(-1, WNOHANG);
		last if $pid <= 0;
		$self->_debug(action => "waitpid caught pid: $pid, rc: $?");
		$dontwait = 1;
		$self->_finish_action($pid);
	    }
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
    my $max_workers = $self->{max_workers};
    my ($connecting, $ready, $running, $waiting, $suspended, $done) =
	@{$self->{in_state}}{qw(connecting ready running waiting suspended done)};
    my ($connected_waiting, $connected_suspended) =
	@{$self->{connected}}{qw(waiting suspended)};
    while (1) {
	# use Data::Dumper;
	# print STDERR Dumper $self;
	$self->_debug(api => "run: iterating...");

	$self->_debug(at => "run: hosts at connecting: ", scalar(keys %$connecting));
	$self->_at_connecting($_) for keys %$connecting;

	$self->_debug(at => "run: hosts at ready: ", scalar(keys %$ready));

	# $self->_audit_conns;
	$self->_at_ready($_) for keys %$ready;
	# $self->_audit_conns;

	if ($max_workers) {
	    $self->_debug(at => "run: hosts at suspended:", scalar(keys %$suspended));
	    if (%$suspended) {
		my $awake = $max_workers - $self->_num_workers;
		my @labels;
		for my $hash ($connected_suspended, $suspended) {
		    while ($awake > 0) {
			my ($label) = each %$hash or last;
			CORE::push @labels, $label;
			$awake--;
		    }
		    for my $label (@labels) {
			$self->_debug(workers => "[$label] awaking");
			$self->_set_host_state($label, 'ready');
		    }
		    keys %$hash; # do we really need to reset the each iterator?
		}
	    }
	}

	$self->_debug(at => "run: hosts at waiting: ", scalar(keys %$waiting));
	$self->_debug(at => "run: hosts at running: ", scalar(keys %$running));
	$self->_debug(at => "run: hosts at done: ", scalar(keys %$done), " of ", scalar(keys %$hosts));

	return 1 if keys(%$hosts) == keys(%$done);

	my $time = ( %$ready      ? 0   :
		     %$connecting ? 0.1 :
		                    3.0 );
	$self->_wait_for_jobs($time);
    }
}

1;
__END__

=head1 NAME

Net::OpenSSH::Parallel - Run SSH jobs in parallel

=head1 SYNOPSIS

  use Net::OpenSSH::Parallel;

  my $pssh = Net::OpenSSH::Parallel->new();
  $pssh->add_host($_) for @hosts;

  $pssh->push('*', scp_put => '/local/file/path', '/remote/file/path');
  $pssh->push('*', command => 'gurummm',
              '/remote/file/path', '/tmp/output');
  $pssh->push($special_host, command => 'prumprum', '/tmp/output');
  $pssh->push('*', scp_get => '/tmp/output', 'logs/%HOST%/output');

  $pssh->run;

=head1 DESCRIPTION

Run this here, that there, etc.

  ***
  *** Note: This is an early release!
  ***
  *** The module design and particularly the public API has not yet
  *** stabilized. Future versions of the module are not guaranteed to
  *** remain compatible with this one.
  ***

C<Net::OpenSSH::Parallel> is a parallel scheduler that can run
commands in a set of hosts through SSH in parallel.

This module tries to find a compromise between being simple to use,
efficient and covering a good part of the problem space of parallel
process execution via SSH.

Common usage of the module is as follows:

=over

=item *

create a C<Net::OpenSSH::Parallel> object

=item *

register the hosts where you want to run commands with the
L</add_host> method

=item *

queue the actions you want to run (commands, file copy operations,
etc.) using the L</push> method.

=item *

call the L</run> method and let the parallel scheduler take care of
everything!

=back

=head2 Labelling hosts

Every host is identified by an unique label that is given when the
host is registered into the parallel scheduller. Usually, the host
name is used also as the label, but this is not required by the
module.

The rationale behind using labels is that a hostname does not
necessarily identify unique "remote processors" (for instance,
sometimes your logical "remote processors" may be user accounts
distributed over a set of hosts: C<foo1@bar1>, C<foo2@bar1>,
C<foo3@bar2>, ...; a set of hosts that are accesible behind an unique
IP, listening in different ports; etc.)

=head2 Selecting hosts

Several of the methods of this module accept a selector string to
determine which of the registered hosts should be affected by the
operation.

For instance, in...

  $pssh->push('*', command => 'ls')

the first argument is the selector. In this case C<*> means all the
registered hosts.

Other possible selectors are:

  'bar*'                # selects everything beginning by 'bar'
  'foo1,foo3,foo6'      # selects the hosts of the given names
  'bar*,foo1,foo3,foo6' # both
  '*doz*'               # everything containing 'doz'

I<Note: I am still considering how the selector mini-language should
be, don't hesitate to send your suggestions!>

=head2 Local resource usage

When the number of hosts managed by the scheduler is too high, the
local node can become overloaded.

Roughly, every SSH connection requires two local C<ssh> processes
(one to run the SSH connection and another one to launch the remote
command) that results in around 5MB of RAM usage per host.

CPU usage varies greatly depending on the tasks carried out. The most
expensive are short remote tasks (because of the local process
creation and destruction overhead) and tasks that transfer big
ammounts of data through SSH (because of the encryption going on).

In practice, CPU usage doesn't matter too much (mostly because the OS
would be able to manage it but also because there is not too many
things we can do to reduce it) and usually it is RAM about what we
should be more concerned.

The module accepts two parameters to limit resource usage:

=over

=item * C<maximum_workers>

is the maximun number of remote commands that can be running
concurrently.

=item * C<maximum_connections>

is the maximum number of SSH connections that can be active
concurrently.

=back

In practice, limiting C<maximum_connections> indirectly limits RAM
usage and limiting the C<maximum_workers> indirectly limits CPU usage.

The module requires C<maximum_connections> to be at least equal
or bigger than C<maximum_workers>, and it is recomended that
C<maximum_connections E<gt>= 2 * maximum_workers> (otherwise the
scheduler will not be able to reuse connections efficiently).

You will have to experiment to find out which combinations give the
best results in your particular scenarios.

Also, for small sets of hosts you can just let these parameters
unlimited.

=head2 Variable expansion

This module activates L<Net::OpenSSH> L<variable
expansion|Net::OpenSSH/Variable expansion> by default. That way, it is
possible to parametrice easily the actions executed on every host in
base to some of its properties.

For instance:

  $pssh->queue('*', scp_get => "/var/log/messages", "messages.%HOST%");

copies the remote log files appending the origin host name to the
local file names.

The variables C<HOST>, C<USER>, C<PORT> and C<LABEL> are predefined.

=head2 API

These are the methods supported by this class:

=over

=item $pssh = Net::OpenSSH::Parallel->new(%opts)

creates a new object.

The accepted options are:

=over

=item workers => $maximum_workers

sets the maximum number of operations that can be carried out in
parallel.

=item connections => $maximum_connections

sets the maximum number of SSH connections that can be stablished
simultaneously.

$maximum_connections must be equal or bigger than $maximum_workers

=item debug => $debug

select the level of debugging you want (0 => nothing, ~0 => maximum).

=back

=item $pssh->add_host($label, %opts)

=item $pssh->add_host($label, $host, %opts)

registers a new host into the C<$pssh> object.

C<$label> is the name used to refer to the registered host afterwards.

When the hostname argument is ommited, the label is used also as the
hostname.

Currently, L<Net::OpenSSH::Parallel> does not consumes any option and
the contents of C<%opts> are passed to L<Net::OpenSSH> constructor.

=item $pssh->push($selector, $action, \%opts, @action_args)

=item $pssh->push($selector, $action, @action_args)

pushes a new action into the queues selected by C<$selector>.

The supported actions are:

=over

=item command => @cmd

queue the given shell command on the selected hosts.

Example:

  $self->push('*', 'command'
              { stdout_fh => $find_fh, stderr_to_stdout => 1 },
              'find', '/my/dir');

=item scp_get => @remote, $local

=item scp_put => @local, $remote

These methods queue an SCP remote file copy operation in the selected
hosts.

=item sub { ... }

Queues a call to a perl subroutine that will be executed locally.

=back

When given, the C<\%opts> argument can contain the following options:

=over 4

=item on_error => sub { }

not implemented yet!

=item on_error => $fail_mode

not implemented yet!

=item timeout => $seconds

not implemented yet!

=item on_done => sub { }

not implemented yet!

=back

Any other option will be passed to the corresponding L<Net::OpenSSH>
method (L<spawn|Net::OpenSSH/spawn>, L<scp_put|Net::OpenSSH/scp_put>,
etc.).

=item $pssh->run

runs the queued operations.

=back

=head1 TODO

=over

=item * implement better error handling

now is an all or nothing approach, when something fails the full
process is aborted.

=item * run N processes per host concurrently

allow running more than one process per remote server concurrently

=back

=head1 SEE ALSO

L<Net::OpenSSH> is used to manage the SSH connections to the remote
hosts.

L<SSH::Batch> has a similar focus as this module. In my opinion it is
simpler to use but rather more limited.

L<GRID::Machine> allows to run perl code distributed in a cluster via
SSH.

If your application requires orchestating workflows more complex that
those supported by L<Net::OpenSSH::Parallel>, you should probably
consider some L<POE> based solution.

=head1 COPYRIGHT AND LICENSE

Copyright E<copy> 2009 by Salvador FandiE<ntilde>o
(sfandino@yahoo.com).

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
