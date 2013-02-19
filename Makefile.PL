
use ExtUtils::MakeMaker;

WriteMakefile( NAME => 'Net::OpenSSH::Parallel',
	       VERSION_FROM => 'lib/Net/OpenSSH/Parallel.pm',
	       PREREQ_PM => { 'Net::OpenSSH' => 0.60 },
	       AUTHOR => 'Salvador Fandino <sfandino@yahoo.com>',
);
