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

package WebAuth::Token::WebKDCFactor;

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
sub subject    { my $t = shift; $t->_attr ('subject',    @_) }
sub factors    { my $t = shift; $t->_attr ('factors',    @_) }
sub creation   { my $t = shift; $t->_attr ('creation',   @_) }
sub expiration { my $t = shift; $t->_attr ('expiration', @_) }

1;

__END__

=for stopwords
WebAuth WebKDC KEYRING login webkdc-factor webkdc-proxy timestamp Allbery

=head1 NAME

WebAuth::Token::WebKDCFactor - WebAuth webkdc-factor tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::WebKDCFactor->new;
    $token->subject ('user');
    $token->initial_factors ('d');
    $token->expiration (time + 3600);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth webkdc-factor token, which stores additional factors that will
be combined with valid login or webkdc-proxy tokens but which cannot, by
themselves, authenticate the user.  This token is stored as a separate
cookie in the user's browser, possibly with a longer lifespan than the
single sign-on credentials, and may also be returned by the user
information service for certain types of authentications.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::WebKDCFactor.  At least some
attributes will have to be set using the accessor methods described below
before the token can be used.

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

=item factors ([FACTORS])

Get or set a comma-separated list of authentication factors that this
token should contribute to any further authentications.  For a list of
possible factors and their meaning, see the WebAuth protocol
specification.

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
