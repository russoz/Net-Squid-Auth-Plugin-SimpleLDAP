#!perl -T

use Test::More tests => 5;

use Net::Squid::Auth::Plugin::SimpleLDAP;

sub check_failure {
    my $param = shift;

    my $p = eval { Net::Squid::Auth::Plugin::SimpleLDAP->new($param) };
    ok( not $p );
}

check_failure( {} );
check_failure( { binddn => 1, bindpw => 2, basedn => 3 } );
check_failure( { binddn => 1, bindpw => 2, server => 4 } );
check_failure( { binddn => 1, basedn => 3, server => 4 } );
check_failure( { bindpw => 2, basedn => 3, server => 4 } );

