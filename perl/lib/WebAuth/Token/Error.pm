# Perl representation of a WebAuth error token.
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

package WebAuth::Token::Error;

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
sub code     { my $t = shift; $t->_attr ('code',     @_) }
sub message  { my $t = shift; $t->_attr ('message',  @_) }
sub creation { my $t = shift; $t->_attr ('creation', @_) }

1;

__END__

=for stopwords
WebAuth WebKDC KEYRING timestamp Allbery

=head1 NAME

WebAuth::Token::Error - WebAuth error tokens

=head1 SYNOPSIS

    use WebAuth qw(WA_PEC_LOGIN_CANCELLED);

    my $token = WebAuth::Token::Error->new;
    $token->code (WA_PEC_LOGIN_CANCELLED);
    $token->message ('user canceled login');
    $token_>creation (time);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth error token, returned by the WebKDC in response to a request
token if some error occurred in processing that request.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::Error.  At least some attributes will
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

=item code ([CODE])

Get or set the error code, which should be one of the WA_PEC_* error
codes exported by the WebAuth module.

=item message ([MESSAGE])

Get or set the error message.

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
