#
# THIS FILE IS NOT BEING MAINTAINED!!!
#
# USE ./Build.PL INSTEAD!!
#
use inc::Module::Install;

name     'Net-Squid-Auth-Plugin-SimpleLDAP';
all_from 'lib/Net/Squid/Auth/Plugin/SimpleLDAP.pm';
author   'Alexei Znamensky <russoz@cpan.org>';

requires 'Net::LDAP';

build_requires 'Test::More';

auto_install;

WriteAll;

