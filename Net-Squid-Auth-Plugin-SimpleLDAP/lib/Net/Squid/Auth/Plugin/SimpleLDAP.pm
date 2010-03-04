package Net::Squid::Auth::Plugin::SimpleLDAP;

use warnings;
use strict;
use Carp;
use Net::LDAP;

=head1 NAME

Net::Squid::Auth::Plugin::SimpleLDAP - A simple LDAP-based credentials validation plugin for 
L<Net::Squid::Auth::Engine>

=head1 VERSION

Version 0.01.04

=cut

use version; our $VERSION = qv('0.01.04');

=head1 SYNOPSIS

If you're a system administrator trying to use Net::Squid::Auth::Engine to
validate your user's credentials using a LDAP server as a credentials
repository, do as described here:

On C<$Config{InstallScript}/squid-auth-engine>'s configuration file:

  plugin = SimpleLDAP
  <SimpleLDAP>
    # LDAP server
    server = myldap.server.somewhere       # mandatory

    # connection options
    <net_ldap_options>                     # optional section with
      port = N                             #   Net::LDAP's
      scheme = 'ldap' | 'ldaps' | 'ldapi'  #     constructor
      ...                                  #     options
    </net_ldap_options>

    # bind options
    binddn = cn=joedoe                     # mandatory
    bindpw = secretpassword                # mandatory

    # search options
    basedn = ou=mydept,o=mycompany.com     # mandatory
    objclass = inetOrgPerson               # opt, default "person"
    userattr = uid                         # opt, default "cn"
    passattr = password                    # opt, default "userPassword"
  </SimpleLDAP>

Unless configured otherwise, this module will assume the users in your LDAP 
directory belong to the object class C<person>, as defined in section 3.12 of 
RFC 4519, and the B<user> and B<password> information will be looked for in the 
C<cn> and C<userPassword> attributes, respectively.

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
section I<< <SimpleLDAP> >> in the C<$Config{InstallScript}/squid-auth-engine> 
as parameter. Returns a plugin instance.

=cut

sub new {
    my ( $class, $config ) = @_;

    return unless UNIVERSAL::isa( $config, 'HASH' );
    return bless { _cfg => $config }, $class;
}

=head2 initialize()

Initialization method called upon instantiation. This provides an opportunity 
for the plugin initialize itself, stablish database connections and ensure it 
have all the necessary resources to verify the credentials presented. It 
receives no parameters and expect no return values.

=cut

sub initialize {
    my $self = shift;

    # some reasonable defaults
    $self->{_cfg}{userattr} = 'cn' unless $self->{_cfg}{userattr};
    $self->{_cfg}{passattr} = 'userPassword'
      unless $self->{_cfg}{passattr};
    $self->{_cfg}{objclass} = 'person' unless $self->{_cfg}{objclass};

    # required information
    foreach my $_ qw(binddn bindpw basedn server) {
        croak "$/Missing config parameter \'" . $_ . "'" unless $self->{_cfg}{$_};
    }

    # connect
    $self->{ldap} = Net::LDAP->new( $self->{_cfg}{server}, $self->{_cfg}{net_ldap_options} )
      || croak "Cannot connect to LDAP server: " . $self->{_cfg}{server};

    # bind
    my $mesg = $self->{ldap}->bind( "$self->{_cfg}{binddn}",
        password => "$self->{_cfg}{bindpw}" );
    $mesg->code && croak "Error binding to LDAP server: " . $mesg->error;

    return;
}

=head2 _search()

Searches the LDAP server. It expects one parameter with a search string for the username.
The search string must conform with the format used in LDAP queries, as defined in section 3
of RFC 4515.

=cut

sub _search {
    my ( $self, $search ) = @_;

    # search
    my $mesg = $self->{ldap}->search(
        base   => "$self->{_cfg}{basedn}",
        scope  => 'sub',
        filter => '(&(objectClass='
          . $self->{_cfg}{objclass} . ')('
          . $self->{_cfg}{userattr} . '='
          . "$search" . '))',
        attrs => [ $self->{_cfg}{userattr}, $self->{_cfg}{passattr} ],
    );

    # if errors
    if ( $mesg->code ) {
        $mesg = $self->{ldap}->unbind;
        $mesg->code && croak "Error searching LDAP server: " . $mesg->error;
    }

    # get results
    my @entries = $mesg->entries();
    my $result = {};

    my $entry = shift @entries;
    return $result unless $entry;

    my $user = $entry->get_value( $self->{_cfg}{userattr} );
    my $pw   = $entry->get_value( $self->{_cfg}{passattr} );

    $result->{$user} = ${pw};

    carp "Found more than 1 entry for user ($user)" if shift @entries;

    return $result;
}

=head2 is_valid( $username, $password )

This is the credential validation interface. It expects a username and password
as parameters and returns a boolean indicating if the credentials are valid
(i.e., are listed in the configuration file) or not.

=cut

sub is_valid {
    my ( $self, $username, $password ) = @_;
    my $result = $self->_search("$username");
    return 0 unless exists $result->{$username};

    return $result->{$username} eq $password;
}

=head1 AUTHOR

Alexei Znamensky, C<< <russoz at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to 
C<bug-net-squid-auth-plugin-simpleldap at rt.cpan.org>, or through 
the web interface at 
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Squid-Auth-Plugin-SimpleLDAP>.  
I will be notified, and then you'll automatically be notified of progress on 
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Squid::Auth::Plugin::SimpleLDAP

Or take a look at the github site to be up to date:

=over 4

L<http://russoz.github.com/Net-Squid-Auth-Plugin-SimpleLDAP>

=back

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

=head1 SEE ALSO

L<Net::Squid::Auth::Engine>, L<Net::LDAP>

=head1 ACKNOWLEDGEMENTS

Luis "Fields" Motta Campos C<< <lmc at cpan.org> >>, who could now say:

"The circle is now complete. When I left you, I was but the learner; now *I* am the master."

To what I'd reply:

"Only a master of Perl, Fields"


=head1 COPYRIGHT & LICENSE

Copyright 2008,2010 Alexei Znamensky, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

42;    # End of Net::Squid::Auth::Plugin::SimpleLDAP

