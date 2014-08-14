# Generic base class for WebAuth tokens.
#
# This class holds some helper methods and shared code for all of the separate
# WebAuth token classes.  It is not usable directly.  More explicitly, it is
# not a representation of a generic WebAuth token; it is only an abstract base
# class.
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

package WebAuth::Token;

require 5.006;
use strict;
use warnings;

use Carp qw(croak);
use WebAuth 3.06;

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# Constructor.  Requires a WebAuth context and optionally can take an encoded
# token and keyring to create a new object via decoding.
#
# Reject attempts to create this class directly except via an existing token,
# which will return one of our subclasses.  Constructing an empty object is
# only intended for use by subclasses, since an empty generic WebAuth::Token
# has no meaning.
sub new {
    my ($type, $ctx, $token, $keyring) = @_;
    if ($type eq 'WebAuth::Token' && !defined ($token)) {
        croak ('WebAuth::Token cannot be used directly');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    my $self;
    if (defined $token) {
        $self = $ctx->token_decode ($token, $keyring);
    } else {
        $self = { ctx => $ctx };
        bless ($self, $type);
    }
    return $self;
}

# Shared code for all accessor methods.  Takes the object, the attribute name,
# and the value.  Sets the value if one was given, and returns the current
# value of that attribute.
sub _attr {
    my ($self, $attr, $value) = @_;
    $self->{$attr} = $value if defined ($value);
    return $self->{$attr};
}

1;

__END__

=for stopwords
WebAuth WebKDC username WebLogin reauthenticating WebKDC's WEBAUTH KEYRING
decrypt subclasses Allbery

=head1 NAME

WebAuth::Token - Generic WebAuth token handling

=head1 SYNOPSIS

    use WebAuth;

    my $wa = WebAuth->new;
    eval {
        $token = WebAuth->token_decode ($wa, $data, $keyring);
        print ref ($token), " received\n";
        print "Encoded: ", $token->encode, "\n";
    };
    if ($@) {
        # handle exception
    }

=head1 DESCRIPTION

WebAuth::Token is the parent class for all WebAuth token objects.  Other
than when creating a new token by decoding an encrypted token, this class
will never be used directly.  Instead, it is the base class for all other
WebAuth::Token::* classes, each of which represents a specific type of
protocol token.

The following token classes are currently supported:

=over 4

=item WebAuth::Token::App

Used by a WebAuth Application Server to store data, such as the identity
of an authenticated user or the session key for that identity information.

=item WebAuth::Token::Cred

Holds a credential for some other service, usually a Kerberos service
ticket.  It is sent back by the WebKDC to a WebAuth Application Server
when requested using a proxy token, and the WAS also uses it to store the
credentials in cookies.

=item WebAuth::Token::Error

Returned by the WebKDC in response to a request token if some error
occurred in processing that request.

=item WebAuth::Token::Id

Identifies a user to a WebAuth Authentication Server.  This token is sent
from the WebKDC to the WAS following a user authentication to communicate
the authentication information.

=item WebAuth::Token::Login

Used to communicate the user's username and password or other
authentication secret from the WebLogin server to the WebKDC.

=item WebAuth::Token::Proxy

Used by a WebAuth Application Server to request other tokens from the
WebKDC.  This is returned by the WebKDC to a WebAuth Application Server if
the WAS may need to request various tokens (particularly credential
tokens).

=item WebAuth::Token::Request

Sent by the WebAuth Application Server to the WebKDC to initiate a request.

This token has two forms.  The first is sent by the WAS to the WebKDC via
a redirect to request either an id or a proxy token for the user,
depending on whether the WAS will need credentials.  The second is sent to
the WebKDC as part of a request for a service token and contains only the
command and creation time.

=item WebAuth::Token::WebKDCProxy

Stores user credentials or authentication information for later use by the
WebKDC.  This is the token that's stored as a single sign-on cookie in the
user's browser, allowing the user to authenticate to subsequent web sites
without reauthenticating.  This token is also returned inside a proxy
token to a WAS, which can then present it back to the WebKDC to obtain id
or cred tokens.

=item WebAuth::Token::WebKDCService

Sent by the WebKDC to a WAS and returned by the WAS to the WebKDC as part
of the request token.  The purpose of this token is to store the session
key used for encrypting the request token and its responses.  It's
encrypted in the WebKDC's long-term key, and is therefore used by the
WebKDC to recover the session key without having local state.

=back

Each of these tokens have different data elements and therefore different
accessor functions, and each has its own separate documentation.  See that
individual documentation for the available operations on each type of
token.

=head1 CLASS METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item new (WEBAUTH, TOKEN, KEYRING)

Given an encrypted and base64-encoded TOKEN, decode and decrypt it using
the provided WebAuth::Keyring object.  The return value will be a subclass
of WebAuth::Token as described above in L</DESCRIPTION>.

Callers will normally want to check via isa() whether the returned token
is of the type that the caller expected.  Not performing that check can
lead to security issues.

This is a convenience wrapper around the WebAuth token_decode() method.

=back

The subclasses of WebAuth::Token also have a traditional new() constructor
to create a new, empty token of that type.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token::App(3),
WebAuth::Token::Cred(3), WebAuth::Token::Error(3), WebAuth::Token::Id(3),
WebAuth::Token::Login(3), WebAuth::Token::Proxy(3),
WebAuth::Token::Request(3), WebAuth::Token::WebKDCProxy(3),
WebAuth::Token::WebKDCService(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
