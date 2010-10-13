#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok('Net::Squid::Auth::Plugin::SimpleLDAP');
}

diag(
"Testing Net::Squid::Auth::Plugin::SimpleLDAP $Net::Squid::Auth::Plugin::SimpleLDAP::VERSION, Perl $], $^X"
);
