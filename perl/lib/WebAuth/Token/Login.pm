# Perl representation of a WebAuth login token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Login;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub username ($;$) { my $t = shift; $t->_attr ('username', @_) }
sub password ($;$) { my $t = shift; $t->_attr ('password', @_) }
sub otp      ($;$) { my $t = shift; $t->_attr ('otp',      @_) }
sub creation ($;$) { my $t = shift; $t->_attr ('creation', @_) }

1;

__END__

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

=item username ([USERNAME])

Get or set the username for which this token holds login credentials.
This is a site-specific identifier and may or may not be a fully-qualified
principal name.

=item password ([PASSWORD])

Get or set the password for this user.  Either this or the otp() attribute
will be set.


=item otp ([OTP])

Get or set the one-time password code for this user.  Either this or the
password() attribute will be set.

=item creation ([TIMESTAMP])

Get or set the creation timestamp for this token in seconds since epoch.
If not set, the encoded token will have a creation time set to the time
of encoding.

=back

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
