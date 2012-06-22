# Perl representation of a WebAuth cred token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Cred;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub subject    ($;$) { my $t = shift; $t->_attr ('subject',    @_) }
sub type       ($;$) { my $t = shift; $t->_attr ('type',       @_) }
sub service    ($;$) { my $t = shift; $t->_attr ('service',    @_) }
sub data       ($;$) { my $t = shift; $t->_attr ('data',       @_) }
sub creation   ($;$) { my $t = shift; $t->_attr ('creation',   @_) }
sub expiration ($;$) { my $t = shift; $t->_attr ('expiration', @_) }

1;

__END__

=head1 NAME

WebAuth::Token::Cred - WebAuth cred tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::Cred->new;
    $token->subject ('user');
    $token->type ('krb5');
    $token->service ('service/foo@EXAMPLE.COM');
    $token->data ($ticket);
    $token->creation (time);
    $token->expiration (time + 3600);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth cred token, which holds a credential for some other service,
usually a Kerberos service ticket.  It is sent back by the WebKDC to a
WebAuth Application Server when requested using a proxy token, and the WAS
also uses it to store the credentials in cookies.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::Cred.  At least some attributes will
have to be set using the accessor methods described below before the token
can be used.

=back

=head1 INSTANCE METHODS

As with WebAuth module functions, failures are signalled by throwing
WebAuth::Exception rather than by return status.

=head1 General Methods

=over 4

=item encode (KEYRING)

Generate the encoded and encrypted form of this token using the provided
KEYRING.  The encryption key used will be the one returned by the
best_key() method of WebAuth::Keyring on that KEYRING.

=back

=head1 Accessor Methods

=over 4

=item subject ([SUBJECT])

Get or set the subject, which holds the identity of the user for which
this token contains credentials.

=item type ([TYPE])

Get or set the type of credential stored in this token.  Currently, this
is always C<krb5> (but still must be explicitly set if creating a new
token).

=item service ([SERVICE])

Get or set the service for which this token stores a credential.  For
tokens of type C<krb5>, this is the fully-qualified principal name of
the service ticket stored in this token.

=item data ([CREDENTIAL])

Get or set the credential stored in this token.  This is currently always
a Kerberos ticket in the form created by the krb5_export_tgt() or
krb5_export_ticket() functions of the WebAuth module.

=item creation ([TIMESTAMP])

Get or set the creation timestamp for this token in seconds since epoch.
If not set, the encoded token will have a creation time set to the time of
encoding.

=item expiration ([TIMESTAMP])

Get or set the expiration timestamp for this token in seconds since epoch.

=back

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
