# Rich exception object for WebAuth operations.
#
# All WebAuth APIs, including ones on some subsidiary objects, throw a
# WebAuth::Exception on any failure of the underlying WebAuth call.  This is a
# rich exception object that carries the WebAuth library error message,
# failure code, and additional information.  This Perl class defines the
# object and provides accessor methods to extract information from it.
#
# These objects are constructed in the static webauth_croak function defined
# in WebAuth.xs.  Any changes to the code here should be reflected there and
# vice versa.
#
# Written by Roland Schemers
# Copyright 2003, 2005, 2008, 2009, 2011, 2012, 2013
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

package WebAuth::Exception;

use 5.006;

use strict;
use warnings;

use overload '""' => \&to_string, 'cmp' => \&spaceship;

use WebAuth qw(3.02);

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# There is intentionally no constructor.  This object is thrown by the WebAuth
# C API.

# Basic accessors.
sub detail_message { my $self = shift; return $self->{'detail'}  }
sub error_message  { my $self = shift; return $self->{'message'} }
sub status         { my $self = shift; return $self->{'status'}  }

# A full verbose message with all the information from the exception.
sub verbose_message {
    my ($self) = @_;
    my $status = $self->{'status'};
    my $file = $self->{'file'};
    my $line = $self->{'line'};
    my $message = $self->{'message'};
    my $detail = $self->{'detail'};

    my $result = '';
    $result .= "$detail: " if defined $detail;
    $result .= $message;
    if (defined $line) {
        $result .= " at $file line $line";
    }
    return $result;
}

# The string conversion of this exception is the full verbose message.
sub to_string {
    my ($self) = @_;
    return $self->verbose_message;
}

# cmp converts the exception to a string and then compares it to the other
# argument.
sub spaceship {
    my ($self, $other, $swap) = @_;
    my $string = $self->verbose_message;
    if ($swap) {
        return ($other cmp $string);
    } else {
        return ($string cmp $other);
    }
}

1;

__END__

=for stopwords
WebAuth API Allbery

=head1 NAME

WebAuth::Exception - Rich exception for errors from WebAuth API methods

=head1 SYNOPSIS

    my $token;
    my $wa = WebAuth->new;
    eval {
        $token = $wa->token_decode ($input);
        # ...
    };
    if ($@ && ref ($@) eq 'WebAuth::Exception') {
        my $e = $@;
        print 'status: ', $e->status, "\n";
        print 'message: ', $e->error_message, "\n";
        print 'detail: ', $e->detail_message, "\n";
        print "$e\n";
        die $e->verbose_message;
    }

=head1 DESCRIPTION

All WebAuth methods, and most methods in WebAuth::Key, WebAuth::Keyring,
WebAuth::KeyringEntry, and WebAuth::Token::* classes, will throw an
exception on error.  Exceptions produced by the underlying C API call will
be represented by a WebAuth::Exception object.

You can use this object like you would normally use $@ and print it out or
do string comparisons with it and it will convert to the string
representation of the complete error message.  But you can also access the
structured data stored inside the exception by treating it as an object
and using the methods defined below.

=head1 METHODS

=over 4

=item status ()

Returns the WebAuth status code for the exception, which will be one of
the WebAuth::WA_ERR_* constants.

=item error_message ()

Returns the WebAuth error message.  For most WebAuth functions, this will
consist of a generic error message followed by more detail about this
specific error in parentheses.

=item detail_message ()

Returns the "detail" message in the exception.  The detail message is
additional information created with the exception when it was raised and
is usually the name of the WebAuth C function that raised the exception.

=item verbose_message ()

Returns a verbose error message, which consists of all information
available in the exception, including the status code, error message, line
number and file, and any detail message in the exception.

=item to_string ()

This method is called if the exception is interpolated into a string.
It is a wrapper around the verbose_message method.

=item spaceship ([STRING], [SWAP])

This method is called if the exception object is compared to a string
via cmp.  It will compare the given string to the verbose error message
and return the result.  If SWAP is set, it will reverse the order to
compare the given string to the verbose error.

=back

=head1 AUTHORS

Roland Schemers and Russ Allbery <eagle@eyrie.org>.

=head1 SEE ALSO

WebAuth(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
