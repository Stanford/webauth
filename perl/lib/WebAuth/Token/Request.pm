# Perl representation of a WebAuth request token.
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

package WebAuth::Token::Request;

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
sub type            { my $t = shift; $t->_attr ('type',            @_) }
sub auth            { my $t = shift; $t->_attr ('auth',            @_) }
sub proxy_type      { my $t = shift; $t->_attr ('proxy_type',      @_) }
sub state           { my $t = shift; $t->_attr ('state',           @_) }
sub return_url      { my $t = shift; $t->_attr ('return_url',      @_) }
sub options         { my $t = shift; $t->_attr ('options',         @_) }
sub initial_factors { my $t = shift; $t->_attr ('initial_factors', @_) }
sub session_factors { my $t = shift; $t->_attr ('session_factors', @_) }
sub loa             { my $t = shift; $t->_attr ('loa',             @_) }
sub command         { my $t = shift; $t->_attr ('command',         @_) }
sub creation        { my $t = shift; $t->_attr ('creation',        @_) }

1;

__END__

=for stopwords
WebAuth WebKDC KEYRING auth authenticator loa timestamp Allbery

=head1 NAME

WebAuth::Token::Request - WebAuth request tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::Request->new;
    $token->type ('id');
    $token->auth ('webkdc');
    $token->return_url ($url);
    $token->creation (time);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth request token, sent by the WebAuth Application Server to the
WebKDC to initiate a request.

This token has two forms.  The first is sent by the WAS to the WebKDC via
a redirect to request either an id or a proxy token for the user,
depending on whether the WAS will need credentials.  The second is sent to
the WebKDC as part of a request for a service token and contains only the
command and creation time.  If the command() attribute is set, most other
attributes must not be set.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::Request.  At least some attributes
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

=item type ([TYPE])

Get or set the type of token requested.  This can be either C<id> to
request only an id token, or C<proxy> to request a proxy token that
can be used to retrieve other types of tokens later.

=item auth ([TYPE])

Get or set the type of id token requested.  This attribute is only used if
the type() attribute is C<id>.  It should be set to either C<webkdc> to
request a bearer token or C<krb5> to request a token with a Kerberos
authenticator.

=item proxy_type ([TYPE])

Get or set the type of proxy token requested.  This attribute is only used
if the type() attribute is C<proxy>.  It currently will always be set to
C<krb5>, but must still be explicitly set when creating a new token.

=item state ([DATA])

Get or set the optional state data.  If this data is provided, it will be
returned by the WebKDC to the WebAuth Application Server as a second
element in the URL.  It is normally used to hold an app token that
contains the session key used for WebKDC communication, encrypted in the
private key of a WebAuth Application Server pool.

=item return_url ([URL])

Get or set the return URL, which specifies the URL to which the user
should be sent after successful authentication.

=item options ([OPTIONS])

Get or set an optional comma-separated list of request options.  For a
complete list of supported options and their meanings, see the WebAuth
protocol specification.

=item initial_factors ([FACTORS])

Get or set a comma-separated list of authentication factors that the user
is required to use for initial authentication (the single sign-on
transaction).  For a list of possible factors and their meaning, see the
WebAuth protocol specification.

=item session_factors ([FACTORS])

Get or set a comma-separated list of authentication factors that the user
is required to use to authenticate this session (this particular visit to
this WebAuth Application Server).  For a list of possible factors and
their meaning, see the WebAuth protocol specification.

=item loa ([LOA])

Get or set the level of assurance required for the user authentication.
This is a number whose values are site-defined but for which increasing
numbers represent increasing assurance for the authentication.

=item command ([ELEMENT])

Get or set the XML element for which this token provides an authenticator.
If this attribute is set, no other attributes other than creation() should
be set.  This type of token is used inside an XML request to the WebKDC to
authenticate that request via an encrypted token in the shared key
established between the WebAuth Authentication Server and the WebKDC.

=item creation ([TIMESTAMP])

Get or set the creation timestamp for this token in seconds since epoch.
If not set, the encoded token will have a creation time set to the time
of encoding.

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
