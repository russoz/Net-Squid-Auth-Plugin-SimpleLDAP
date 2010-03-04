#!perl -T

use Test::More tests => 2;

use Net::Squid::Auth::Plugin::SimpleLDAP;

my $p1 = Net::Squid::Auth::Plugin::SimpleLDAP->new();
ok( !defined($p1) );

my $p2 = Net::Squid::Auth::Plugin::SimpleLDAP->new( { t => 1, u => 2 } );
ok( defined($p2) );

