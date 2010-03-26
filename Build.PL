use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::Squid::Auth::Plugin::SimpleLDAP',
    license             => 'perl',
    dist_author         => 'Alexei Znamensky <russoz@cpan.org>',
    dist_version_from   => 'lib/Net/Squid/Auth/Plugin/SimpleLDAP.pm',
    requires => {
        'Net::LDAP'  => 0,
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'Net-Squid-Auth-Plugin-SimpleLDAP-*' ],
);

$builder->create_build_script();
