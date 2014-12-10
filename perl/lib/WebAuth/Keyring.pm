# Documentation and supplemental methods for WebAuth keyrings.
#
# The primary implementation of the WebAuth::Keyring class is done in the
# WebAuth XS module since it's primarily implemented in C.  This file adds
# some supplemental methods that are implemented in terms of other underlying
# calls and provides version and documentation information.
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

package WebAuth::Keyring;

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

# Constructor.  Takes a WebAuth context and either a capacity or a key to wrap
# a keyring around.  Note that subclasses are not supported since the object
# is created by the XS module and will always be a WebAuth::Keyring.
sub new {
    my ($type, $ctx, $key_or_size) = @_;
    if ($type ne 'WebAuth::Keyring') {
        croak ('subclassing of WebAuth::Keyring is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->keyring_new ($key_or_size);
}

# Construct a keyring by decoding it from the serialization format.  Takes the
# WebAuth context and the encoded data.  As above, subclasses are not
# supported since the object is created by the XS module and will always be a
# WebAuth::Keyring.
sub decode {
    my ($type, $ctx, $data) = @_;
    if ($type ne 'WebAuth::Keyring') {
        croak ('subclassing of WebAuth::Keyring is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->keyring_decode ($data);
}

# Construct a keyring by reading it from a file.  Takes the WebAuth context
# and the name of the file to read.  As above, subclasses are not supported
# since the object is created by the XS module and will always be a
# WebAuth::Keyring.
sub read {
    my ($type, $ctx, $file) = @_;
    if ($type ne 'WebAuth::Keyring') {
        croak ('subclassing of WebAuth::Keyring is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->keyring_read ($file);
}

1;

__END__

=for stopwords
WebAuth keyring keyrings WebKDCs WEBAUTH timestamp decrypted Allbery

=head1 NAME

WebAuth::Keyring - WebAuth keyring to hold encryption and decryption keys

=head1 SYNOPSIS

    use WebAuth qw(WA_KEY_AES WA_AES_128);
    use WebAuth::Key;
    use WebAuth::Keyring;

    my $wa = WebAuth->new;
    eval {
        $key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
        $ring = WebAuth::Keyring->new ($wa, $key);
        ...
    };
    if ($@) {
        # handle exception
    }

=head1 DESCRIPTION

This Perl class represents a keyring, which is a set of WebAuth keys with
associated creation times and times after which they become valid.  These
keyrings can be read from and stored to files on disk and are used by
WebAuth Application Servers and WebKDCs to store their encryption keys.

A WebAuth::Keyring object will be destroyed when the WebAuth context used
to create it is destroyed, and subsequent accesses to it may cause memory
access errors or other serious bugs.  Be careful not to retain a copy of a
WebAuth::Keyring object after the WebAuth object that created it has been
destroyed.

=head1 CLASS METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item new (WEBAUTH, KEY)

=item new (WEBAUTH, SIZE)

Create a new keyring attached to the WebAuth context WEBAUTH.

The second argument to this method may be either a WebAuth::Key object or
a numeric size.  If a WebAuth::Key object is provided, a new keyring
containing only that key will be created and returned.  If a size is
provided, a new, empty keyring with space preallocated to hold that many
keys is created and returned.  (Regardless of the allocated size of a
keyring, keyrings will always dynamically expand to hold any new keys that
are added to them.)

This is a convenience wrapper around the WebAuth keyring_new() method.

=item decode (WEBAUTH, FILE)

Create a new WebAuth::Keyring object by decoding its contents from the
provided serialized keyring data.

This is a convenience wrapper around the WebAuth keyring_read() method.

=item read (WEBAUTH, FILE)

Create a new WebAuth::Keyring object by reading its contents from the
provided file.  The created keyring object will have no association with
the file after being created; it won't automatically be saved, or updated
when the file changes.

This is a convenience wrapper around the WebAuth keyring_read() method.

=back

=head1 INSTANCE METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item add (CREATION, VALID_AFTER, KEY)

Add a new KEY to the keyring with CREATION as the creation time and
VALID_AFTER as the valid-after time.  Both of the times should be in
seconds since epoch.  The key must be a WebAuth::Key object.

Keys will not used for encryption until after their valid-after time,
which provides an opportunity to synchronize the keyring between multiple
systems before the keys are used.

=item best_key (USAGE, HINT)

Returns the best key available in the keyring for a particular purpose and
time.  USAGE should be either WebAuth::WA_KEY_DECRYPT or
WebAuth::WA_KEY_ENCRYPT and indicates whether the key will be used for
decryption or encryption.  For decryption keys, HINT is the timestamp of
the data that will be decrypted.

If USAGE is WebAuth::WA_KEY_ENCRYPT, this method will return the valid key
in the keyring that was created most recently, since this is the best key
to use for encryption going forward.  If USAGE is WebAuth::WA_KEY_DECRYPT
is false, this method will return the key most likely to have been used to
encrypt something at the time HINT, where HINT is given in seconds since
epoch.

=item encode ()

Encode the keyring in the same serialization format that is used when
writing it to a file, readable by decode() or read(), and return the
encoded form.

=item entries ()

In a scalar context, returns the number of entries in the keyring.  In an
array context, returns a list of keyring entries as WebAuth::KeyringEntry
objects.

=item remove (INDEX)

Removes the INDEX entry in the keyring, where INDEX is a numeric key
number starting from 0.  The keyring will then be compacted, so all
subsequent entries in the keyring will have their index decreased by one.
If you are removing multiple entries from a keyring, you should therefore
remove them from the end of the keyring (the highest INDEX number) first.

=item write (FILE)

Writes the keyring out to FILE in the format suitable for later reading by
read().

=back

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3), WebAuth::Key(3), WebAuth::KeyringEntry(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
