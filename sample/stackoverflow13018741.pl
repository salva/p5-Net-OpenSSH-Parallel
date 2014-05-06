#!/usr/bin/perl -w

use Net::OpenSSH::Parallel;
use Term::ReadKey;


print "please enter filename:\n";
$filename = ReadLine;
chomp $filename;

print "please enter user ID:\n";
$userID = ReadLine;
chomp $userID;

print "please enter password:\n";
ReadMode 'noecho';
$passwordforuser = ReadLine 0;
chomp $passwordforuser;
ReadMode 'normal';

open READFILE,"<","$filename" or die "Could not open file listofmachines\n";

my @listofmachines = <READFILE>;
chomp @listofmachines;

my $pssh = Net::OpenSSH::Parallel->new(connections => 10);
$pssh->add_host($_,
                user => $userID, password => $passwordforuser,
                master_opts => [-o => 'StrictHostKeyChecking=no'])
    for @listofmachines;

sub do_ssh_task {
    my ($host, $ssh) = @_;
    my $output = $ssh->capture('uptime');
    print "$host: $output";
}

$pssh->all(parsub => \&do_ssh_task);
$pssh->run;

for my $host (@listofmachines) {
    if (my $error = $pssh->get_error($host)) {
        print STDERR "remote task failed for host $host: $error\n";
    }
}
