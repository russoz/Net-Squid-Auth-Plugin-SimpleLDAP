package Net::Squid::Auth::Plugin::SimpleLDAP;

use warnings;
use strict;
use Carp;
use Net::LDAP;

=head1 NAME

Net::Squid::Auth::Plugin::SimpleLDAP - A simple LDAP-based credentials validation plugin for Net::Squid::Auth::Engine

=head1 VERSION

Version 0.01.03

=cut

use version; our $VERSION = qv('0.01.03');

=head1 SYNOPSIS

If you're a system administrator trying to use Net::Squid::Auth::Engine to
validate your user's credentials using a LDAP server as a credentials
repository, do as described here:

On C<$Config{InstallScript}/squid-auth-engine>'s configuration file:

    plugin = SimpleLDAP
    <SimpleLDAP>
      server = myldap.server.somewhere
      basedn = ou=mydept,o=mycompany.com
      binddn = cn=joedoe
      bindpw = secretpassword
      objclass = inetOrgPerson (optional, defaults to "person")
      userattr = uid (optional, defaults to "cn")
      passattr = password (optional, defaults to "userPassword")
    </SimpleLDAP>

This module will presume the users in your LDAP directory belong to the
object class C<person>, as defined in section 3.12 of RFC 4519, and the user
and password information will be looked for in the C<cn> and C<userPassword>
attributes, respectively.

On your Squid HTTP Cache configuration:

    auth_param basic /usr/bin/squid-auth-engine /etc/squid-auth-engine.conf

And you're ready to use this module.

If you're a developer, you might be interested in reading through the source
code of this module, in order to learn about it's internals and how it works.
It may give you ideas about how to implement other plugin modules for
L<Net::Squid::Auth::Engine>. 


=head1 FUNCTIONS

=head2 new( $config_hash )

Constructor. Expects a hash reference with all the configuration under the
section I<< <SimpleLDAP> >> in the C<$Config{InstallScript}/squid-auth-engine> as
parameter. Returns a plugin instance.

=cut

sub new {
	my ( $class, $config ) = @_;
	foreach $_ qw(server basedn binddn bindpw) {
		croak "$/Missing config parameter \'" . $_ . "'"
		  unless $config->{$_};
	}
	return unless UNIVERSAL::isa( $config, 'HASH' );
	return bless { _config => $config }, $class;
}

=head2 initialize()

=cut

sub initialize {
	my $self = shift;
	$self->{_config}{userattr} = 'cn' unless $self->{_config}{userattr};
	$self->{_config}{passattr} = 'userPassword'
	  unless $self->{_config}{passattr};
	$self->{_config}{objclass} = 'person' unless $self->{_config}{objclass};

	return;
}

=head2 _search

Searches the LDAP server. It expects one parameter with a search string for the username.
The search string must conform with the format used in LDAP queries, as defined in section 3
of RFC 4515.

=cut

sub _search {
	my ( $self, $search ) = @_;

	# connect
	my $ldap = Net::LDAP->new( $self->{_config}{server} )
	  || croak "Cannot connect to LDAP server: " . $self->{_config}{server};

	# bind
	my $mesg = $ldap->bind( "$self->{_config}{binddn}",
		password => "$self->{_config}{bindpw}" );
	$mesg->code && croak "Error binding to LDAP server: " . $mesg->error;

	# search
	$mesg = $ldap->search(
		base   => "$self->{_config}{basedn}",
		scope  => 'sub',
		filter => '(&(objectClass='
		  . $self->{_config}{objclass} . ')('
		  . $self->{_config}{userattr} . '='
		  . "$search" . '))',
		attrs => [ $self->{_config}{userattr}, $self->{_config}{passattr} ]
	);

	# if errors
	if ( $mesg->code ) {
		$mesg = $ldap->unbind;
		$mesg->code && croak "Error searching LDAP server:" . $mesg->error;
	}

	# get results
	my $entry;
	my %result;
	foreach $entry ( $mesg->entries() ) {
		my $user = $entry->get_value( $self->{_config}{userattr} );
		my $pw   = $entry->get_value( $self->{_config}{passattr} );

		$result{$user} = ${pw};

		undef $user;
		undef $pw;
	}
	$mesg = $ldap->unbind;
	$mesg->code && croak $mesg->error;

	return %result;
}

=head2 is_valid( $username, $password )

This is the credential validation interface. It expects a username and password
as parameters and returns a boolean indicating if the credentials are valid
(i.e., are listed in the configuration file) or not.

=cut

sub is_valid {
	my ( $self, $username, $password ) = @_;
	my %result = $self->_search("$username");
	return 0 unless exists $result{$username};

	return $result{$username} eq $password;
}

=head1 AUTHOR

Alexei Znamensky, C<< <russoz at gmail.com> >>


=head1 BUGS

Please report any bugs or feature requests to C<bug-net-squid-auth-plugin-simpleldap at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Squid-Auth-Plugin-SimpleLDAP>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Squid::Auth::Plugin::SimpleLDAP


You can also look for information at:

=over 4

=item * RFC 4515 - Lightweight Directory Access Protocol (LDAP): String Representation of Search Filters

L<http://www.faqs.org/rfcs/rfc4515.html>

=item * RFC 4519 - Lightweight Directory Access Protocol (LDAP): Schema for User Applications

L<http://www.faqs.org/rfcs/rfc4519.html>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Squid-Auth-Plugin-SimpleLDAP>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Squid-Auth-Plugin-SimpleLDAP>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Squid-Auth-Plugin-SimpleLDAP>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Squid-Auth-Plugin-SimpleLDAP>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2008 Alexei Znamensky, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1;    # End of Net::Squid::Auth::Plugin::SimpleLDAP
