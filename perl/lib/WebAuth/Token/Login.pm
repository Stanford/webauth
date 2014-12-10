# Perl representation of a WebAuth login token.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2013, 2014
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

package WebAuth::Token::Login;

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
sub username    { my $t = shift; $t->_attr ('username',    @_) }
sub password    { my $t = shift; $t->_attr ('password',    @_) }
sub otp         { my $t = shift; $t->_attr ('otp',         @_) }
sub otp_type    { my $t = shift; $t->_attr ('otp_type',    @_) }
sub device_id   { my $t = shift; $t->_attr ('device_id',   @_) }
sub creation    { my $t = shift; $t->_attr ('creation',    @_) }

1;

__END__

=for stopwords
WebAuth WebKDC login username otp timestamp KEYRING WebLogin Allbery

=head1 NAME

WebAuth::Token::Login - WebAuth login tokens

=head1 SYNOPSIS

    my $token = WebAuth::Token::Login->new;
    $token->username ('user');
    $token->password ($password);
    print $token->encode ($keyring), "\n";

=head1 DESCRIPTION

A WebAuth login token, used to communicate the user's username and
password or other authentication secret from the WebLogin server to the
WebKDC.

=head1 CLASS METHODS

=over 4

=item new ()

Create a new, empty WebAuth::Token::Login.  At least some attributes will
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

=item username ([USERNAME])

Get or set the username for which this token holds login credentials.
This is a site-specific identifier and may or may not be a fully-qualified
principal name.

=item password ([PASSWORD])

Get or set the password for this user.  Either this, the otp() attribute,
or the device_id() attribute will be set.

=item otp ([OTP])

Get or set the one-time password code for this user.  Either this, the
password() attribute, or the device_id() attribute will be set.

=item otp_type ([TYPE])

Get or set the one-time password type.  This should be a WebAuth factor
code corresponding to the type of one-time password that this login token
represents.  It may be left unset if the caller doesn't know.

=item device_id ([ID])

Get or set the device ID.  This must be set if the password() and otp()
attributes are not set.  If this is set and otp() is not, it indicates
an attempt to authenticate using that device in some out-of-band way that
does not require a code.

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
