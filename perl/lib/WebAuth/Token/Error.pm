# Perl representation of a WebAuth error token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Error;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub code     ($;$) { my $t = shift; $t->_attr ('code',     @_) }
sub message  ($;$) { my $t = shift; $t->_attr ('message',  @_) }
sub creation ($;$) { my $t = shift; $t->_attr ('creation', @_) }

1;

__END__

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

Russ Allbery <rra@stanford.edu>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3), WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
