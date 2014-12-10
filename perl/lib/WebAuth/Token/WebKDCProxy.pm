# Perl representation of a WebAuth webkdc-proxy token.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

package WebAuth::Token::WebKDCProxy;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# Accessor methods.
sub subject         { my $t = shift; $t->_attr ('subject',         @_) }
sub proxy_type      { my $t = shift; $t->_attr ('proxy_type',      @_) }
sub proxy_subject   { my $t = shift; $t->_attr ('proxy_subject',   @_) }
sub data            { my $t = shift; $t->_attr ('data',            @_) }
sub initial_factors { my $t = shift; $t->_attr ('initial_factors', @_) }
sub loa             { my $t = shift; $t->_attr ('loa',             @_) }
sub creation        { my $t = shift; $t->_attr ('creation',        @_) }
sub expiration      { my $t = shift; $t->_attr ('expiration',      @_) }

1;

__END__

=for stopwords
WebAuth WebKDC reauthenticating KEYRING webkdc-proxy TGT loa timestamp
Allbery

=head1 NAME

WebAuth::Token::WebKDCProxy - WebAuth webkdc-proxy tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::WebKDCProxy->new;
    $token->subject ('user');
    $token->proxy_type ('webkdc');
    $token->proxy_subject ('WEBKDC:remuser');
    $token->expiration (time + 3600);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth webkdc-proxy token, which stores user credentials or
authentication information for later use by the WebKDC.  This is the token
that's stored as a single sign-on cookie in the user's browser, allowing
the user to authenticate to subsequent web sites without reauthenticating.
This token is also returned inside a proxy token to a WAS, which can then
present it back to the WebKDC to obtain id or cred tokens.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::WebKDCProxy.  At least some attributes
will have to be set using the accessor methods described below before the
token can be used.

=back

=head1 INSTANCE METHODS

As with WebAuth module functions, failures are signaled by throwing
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
holding this token.

=item proxy_type ([TYPE])

Get or set the type of webkdc-proxy token this token represents, which
generally represents the authentication mechanism.  The values in common
use are C<krb5>, for a webkdc-proxy token that contains a Kerberos TGT,
and C<remuser>, for a webkdc-proxy token created via an assertion from an
external authentication mechanism.

=item proxy_subject ([SUBJECT])

Get or set the subject to which this webkdc-proxy token was granted.  For
tokens created internally by the WebKDC for its own use, this will start
with C<WEBKDC:> and then include an identifier for the WebKDC.  For tokens
provided to a WebAuth Application Server as part of a proxy token, this
will contain the identity of the WebAuth Application Server.  When the
webkdc-proxy token is checked, this subject is verified and only the named
entity is permitted to use the token.

=item data ([DATA])

Get or set any data associated with the webkdc-proxy token.  For a token
with proxy_type C<krb5>, this will be a Kerberos TGT encoded in the format
created by the export_cred() function of the WebAuth::Krb5 module.

=item initial_factors ([FACTORS])

Get or set a comma-separated list of authentication factors used by the
user during initial authentication (the single sign-on transaction).  For
a list of possible factors and their meaning, see the WebAuth protocol
specification.

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

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Krb5(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
