package Net::Squid::Auth::Plugin::SimpleLDAP;

use warnings;
use strict;

# ABSTRACT: A simple LDAP-based credentials validation plugin for Net::Squid::Auth::Engine

# VERSION

use Carp;
use Net::LDAP 0.4001;
use Scalar::Util qw/reftype/;

sub new {
    my ( $class, $config ) = @_;

    my $reftype = reftype($config) || '';
    croak 'Must pass a config hash' unless $reftype eq 'HASH';

    # some reasonable defaults
    $config->{userattr} = 'cn' unless $config->{userattr};
    $config->{passattr} = 'userPassword'
      unless $config->{passattr};
    $config->{objclass} = 'person' unless $config->{objclass};

    # required information
    foreach my $required qw(binddn bindpw basedn server) {
        croak qq{Missing config parameter '$required'}
          unless $config->{$required};
    }

    return bless { _cfg => $config }, $class;
}

sub initialize {
    my $self = shift;

    # connect
    $self->{ldap} =
         Net::LDAP->new( $self->config('server'), $self->config('NetLDAP') )
      || croak "Cannot connect to LDAP server: " . $self->config()->{server};

    # bind
    my $mesg =
      $self->{ldap}
      ->bind( $self->config('binddn'), password => $self->config('bindpw') );
    $mesg->code && croak "Error binding to LDAP server: " . $mesg->error;

    return;
}

sub _search {
    my ( $self, $search ) = @_;

    # search
    my $mesg = $self->{ldap}->search(
        base   => $self->config('basedn'),
        scope  => 'sub',
        filter => '(&(objectClass='
          . $self->config('objclass') . ')('
          . $self->config('userattr') . '='
          . "$search" . '))',
        attrs => [ $self->config('userattr'), $self->config('passattr') ],
    );

    # if errors
    if ( $mesg->code ) {
        $mesg = $self->{ldap}->unbind;
        $mesg->code && croak "Error searching LDAP server: " . $mesg->error;
    }

    # get results
    my @entries = $mesg->entries();
    my $result  = {};

    my $entry = shift @entries;
    return $result unless $entry;

    my $user;
    if ( $self->config('userattr') =~ m/dn/i ) {
        $user = $entry->dn();
    }
    else {
        $user = $entry->get_value( $self->config('userattr') );
    }
    my $pw = $entry->get_value( $self->config('passattr') );

    $result->{$user} = $pw;

    carp "Found more than 1 entry for user ($user)" if shift @entries;

    return $result;
}

sub is_valid {
    my ( $self, $username, $password ) = @_;
    my $result = $self->_search("$username");
    return 0 unless exists $result->{$username};

    return $result->{$username} eq $password;
}

sub config {
    my ( $self, $key ) = @_;

    return $self->{_cfg}->{$key};
}

1;    # End of Net::Squid::Auth::Plugin::SimpleLDAP

__END__

=pod

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
    <NetLDAP>                              # optional section with
      port = N                             #   Net::LDAP's
      scheme = 'ldap' | 'ldaps' | 'ldapi'  #     constructor
      ...                                  #     options
    </NetLDAP>

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
C<cn> and C<userPassword> attributes, respectively. Although you can choose
to use any other pair of attributes, the C<userattr> can be set to C<DN>,
while the C<passattr> can not.

On your Squid HTTP Cache configuration:

    auth_param basic /usr/bin/squid-auth-engine /etc/squid-auth-engine.conf

And you're ready to use this module.

If you're a developer, you might be interested in reading through the source
code of this module, in order to learn about it's internals and how it works.
It may give you ideas about how to implement other plugin modules for
L<Net::Squid::Auth::Engine>.

=head1 METHODS

=head2 new( $config_hash )

Constructor. Expects a hash reference with all the configuration under the
section I<< <SimpleLDAP> >> in the C<$Config{InstallScript}/squid-auth-engine>
as parameter. Returns a plugin instance.

=head2 initialize()

Initialization method called upon instantiation. This provides an opportunity
for the plugin initialize itself, stablish database connections and ensure it
have all the necessary resources to verify the credentials presented. It
receives no parameters and expect no return values.

=head2 _search()

Searches the LDAP server. It expects one parameter with a search string for
the username. The search string must conform with the format used in LDAP
queries, as defined in section 3 of RFC 4515.

=head2 is_valid( $username, $password )

This is the credential validation interface. It expects a username and password
as parameters and returns a boolean indicating if the credentials are valid
(i.e., are listed in the configuration file) or not.

=head2 config( $key )

Accessor for a configuration setting given by key.

=head1 SEE ALSO

=over 4

=item *
L<Net::Squid::Auth::Engine>, L<Net::LDAP>, L<Scalar::Util>

=item *
RFC 4515 - Lightweight Directory Access Protocol (LDAP): String Representation of Search Filters

L<http://www.faqs.org/rfcs/rfc4515.html>

=item *
RFC 4519 - Lightweight Directory Access Protocol (LDAP): Schema for User Applications

L<http://www.faqs.org/rfcs/rfc4519.html>

=back

=head1 ACKNOWLEDGEMENTS

Luis "Fields" Motta Campos C<< <lmc at cpan.org> >>, who could now say:

"The circle is now complete. When I left you, I was but the learner; now *I* am the master."

To what I'd reply:

"Only a master of Perl, Fields"

=cut

