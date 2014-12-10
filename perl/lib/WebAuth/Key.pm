# Documentation and supplemental methods for WebAuth keys.
#
# The primary implementation of the WebAuth::Key class is done in the WebAuth
# XS module since it's primarily implemented in C.  This file adds some
# supplemental methods that are implemented in terms of other underlying calls
# and provides version and documentation information.
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

package WebAuth::Key;

require 5.006;
use strict;
use warnings;

use Carp qw(croak);
use WebAuth ();

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

# Constructor.  Takes a WebAuth context, a key type, a key size, and optional
# key data and passes that off to WebAuth::key_create.  Note that subclasses
# are not supported since the object is created by the XS module and will
# always be a WebAuth::Keyring.
sub new {
    my ($class, $ctx, $type, $size, $data) = @_;
    if ($class ne 'WebAuth::Key') {
        croak ('subclassing of WebAuth::Key is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    if (defined $data) {
        return $ctx->key_create ($type, $size, $data);
    } else {
        return $ctx->key_create ($type, $size);
    }
}

1;

__END__

=for stopwords
WebAuth keyring WEBAUTH Allbery

=head1 NAME

WebAuth::Key - WebAuth encryption and decryption key

=head1 SYNOPSIS

    use WebAuth qw(WA_KEY_AES WA_AES_128);
    use WebAuth::Key;

    my $wa = WebAuth->new;
    eval {
        $key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
        ...
    };
    if ($@) {
        # handle exception
    }

=head1 DESCRIPTION

A WebAuth::Key object represents a single WebAuth key, which can be used
for encryption or decryption.  Keys are normally stored in
WebAuth::Keyring objects, and token encoding and decoding requires a
keyring rather than a key.

To convert a key to a keyring, see the WebAuth keyring_new() method or
C<< WebAuth::Keyring->new >>.

A WebAuth::Key object will be destroyed when the WebAuth context used to
create it is destroyed, and subsequent accesses to it may cause memory
access errors or other serious bugs.  Be careful not to retain a copy of a
WebAuth::Key object after the WebAuth object that created it has been
destroyed.

=head1 CLASS METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item new (WEBAUTH, TYPE, SIZE[, KEY_MATERIAL])

Create a new WebAuth::Key object within the provided WebAuth context,
which must be a valid WebAuth object.  TYPE currently must be WA_KEY_AES,
and SIZE must be one of WA_AES_128, WA_AES_192, or WA_AES_256.  This may
change in the future if WebAuth gains support for additional key types.

If KEY_MATERIAL is given, it should contain SIZE bytes of data, which
will be used as the key.  If KEY_MATERIAL is not given or is undef, a
new random key of the specified TYPE and SIZE will be generated.

This is a convenience wrapper around the WebAuth key_create() method.

=back

=head1 INSTANCE METHODS

=over 4

=item data ()

Returns the binary key data.

=item length ()

Returns the length of the key, which will currently be one of WA_AES_128,
WA_AES_192, or WA_AES_256.  This is the length of the key in bytes.

=item type ()

Returns the type of the key, which currently will always be WA_KEY_AES.

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Keyring(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
