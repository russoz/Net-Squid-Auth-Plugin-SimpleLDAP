#!perl -T

use Test::More tests => 5;

use Net::Squid::Auth::Plugin::SimpleLDAP;

sub check_failure {
  my $param = shift;

  my $p = Net::Squid::Auth::Plugin::SimpleLDAP->new( $param );
  return 0 unless $p;

  eval { $p->initialize() };
  ok( $@,  );
}

check_failure( { } );
check_failure( { binddn => 1, bindpw => 2, basedn => 3 } );
check_failure( { binddn => 1, bindpw => 2, server => 4 } );
check_failure( { binddn => 1, basedn => 3, server => 4 } );
check_failure( { bindpw => 2, basedn => 3, server => 4 } );




