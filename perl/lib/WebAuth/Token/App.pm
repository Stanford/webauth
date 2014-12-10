# Perl representation of a WebAuth app token.
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

package WebAuth::Token::App;

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
sub authz_subject   { my $t = shift; $t->_attr ('authz_subject',   @_) }
sub last_used       { my $t = shift; $t->_attr ('last_used',       @_) }
sub session_key     { my $t = shift; $t->_attr ('session_key',     @_) }
sub initial_factors { my $t = shift; $t->_attr ('initial_factors', @_) }
sub session_factors { my $t = shift; $t->_attr ('session_factors', @_) }
sub loa             { my $t = shift; $t->_attr ('loa',             @_) }
sub creation        { my $t = shift; $t->_attr ('creation',        @_) }
sub expiration      { my $t = shift; $t->_attr ('expiration',      @_) }

1;

__END__

=for stopwords
WebAuth WebKDC KEYRING timestamp decrypt loa Allbery

=head1 NAME

WebAuth::Token::App - WebAuth app tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::App->new;
    $token->subject ('user');
    $token->expiration (time + 3600);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth application token, used by a WebAuth Application Server to store
data, such as the identity of an authenticated user or the session key for
that identity information.

There are two basic forms of this token: one that contains only the
session_key attribute and one that contains the other attributes.  The
first form is used to communicate the session key for WebKDC communication
across a pool of WebAuth Application Servers that the user may visit
interchangeably while accessing the same URL.  The second form is used to
record the authenticated identity of the user for a session on a WebAuth
Application Server.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::App.  At least some attributes will
have to be set using the accessor methods described below before the token
can be used.

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

=item authz_subject ([SUBJECT])

Get or set the authorization subject, which holds the asserted
authorization identity of the user holding this token.  The authorization
identity may not match the authenticated identity.  It represents a
request to use the authorization identity instead of the authentication
subject when applying ACLs or determining identity in the application.

=item last_used ([TIMESTAMP])

Get or set the last-used timestamp in seconds since epoch, which is
updated each time the token is presented to the WebAuth Application
Server.  This is used to implement inactivity timeouts.

=item session_key ([DATA])

Get or set the session key for communication with the WebKDC.  An app
token containing a session key is used to allow any system in a pool of
WebAuth Application Servers sharing the same private key can decrypt this
app token and then use the key to decrypt the tokens returned from the
WebKDC.  The data contained in this attribute is only the raw key
material, not a WebAuth::Key object.

If this attribute is present, none of the other attributes will be
present.

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

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
