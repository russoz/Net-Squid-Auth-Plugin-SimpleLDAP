#!perl -T

use Test::More tests => 2;

use Net::Squid::Auth::Plugins::SimpleLDAP;

my $p1 = Net::Squid::Auth::Plugins::SimpleLDAP->new();
ok( !defined($p1) );

my $p2 = Net::Squid::Auth::Plugins::SimpleLDAP->new( { t => 1, u => 2 } );
ok( defined($p2) );

