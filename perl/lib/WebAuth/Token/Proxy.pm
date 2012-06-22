# Perl representation of a WebAuth proxy token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Proxy;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub subject         ($;$) { my $t = shift; $t->_attr ('subject',         @_) }
sub type            ($;$) { my $t = shift; $t->_attr ('type',            @_) }
sub webkdc_proxy    ($;$) { my $t = shift; $t->_attr ('webkdc_proxy',    @_) }
sub initial_factors ($;$) { my $t = shift; $t->_attr ('initial_factors', @_) }
sub session_factors ($;$) { my $t = shift; $t->_attr ('session_factors', @_) }
sub loa             ($;$) { my $t = shift; $t->_attr ('loa',             @_) }
sub creation        ($;$) { my $t = shift; $t->_attr ('creation',        @_) }
sub expiration      ($;$) { my $t = shift; $t->_attr ('expiration',      @_) }

1;

__END__

=head1 NAME

WebAuth::Token::Proxy - WebAuth proxy tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::Proxy->new;
    $token->subject ('user');
    $token->type ('krb5');
    $token->webkdc_proxy ($raw);
    $token->expiration (time + 3600);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth proxy token, used by a WebAuth Application Server to request
other tokens from the WebKDC.  This is returned by the WebKDC to a WebAuth
Application Server if the WAS may need to request various tokens
(particularly credential tokens).

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::Proxy.  At least some attributes will
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

Get or set the subject, which holds the authenticated identity of the user
whose credentials and id tokens can be retrieved using this token.

=item type ([TYPE])

Get or set the type of proxy token, which specifies the type of
webkdc-proxy token is included in it.  This is currently always C<krb5>.

=item webkdc_proxy ([DATA])

Get or set the embedded webkdc-proxy token.  This is an opaque blob of
data from the perspective of the WebAuth Application Server.  It is
decrypted and used by the WebKDC to fulfill a token request and consists
of a webkdc-proxy token without the base64 encoding.

=item initial_factors ([FACTORS])

Get or set a comma-separated list of authentication factors used by the
user during initial authentication (the single sign-on transaction).  For
a list of possible factors and their meaning, see the WebAuth protocol
specification.

=item session_factors ([FACTORS])

Get or set a comma-separated list of authentication factors used by the
user to authenticate this session (this particular visit to this WebAuth
Application Server).  For a list of possible factors and their meaning,
see the WebAuth protocol specification.

=item loa ([LOA])

Get or set the level of assurance established for this user
authentication.  This is a number whose values are site-defined but for
which increasing numbers represent increasing assurance for the
authentication.

=item creation ([TIMESTAMP])

Get or set the creation timestamp for this token in seconds since epoch.
If not set, the encoded token will have a creation time set to the time
of encoding.

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
