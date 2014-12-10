# Perl bindings for the WebAuth client library.
#
# This is the Perl boostrap file for the WebAuth module, nearly all of which
# is implemented in XS.  For the actual source, see WebAuth.xs.  This file
# contains the bootstrap and export code and the documentation.
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

package WebAuth;

use 5.008;

use strict;
use warnings;

use base qw(Exporter DynaLoader);

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

our (@EXPORT, @EXPORT_OK, %EXPORT_TAGS);
BEGIN {
    my @constants = qw(
        WA_PEC_SERVICE_TOKEN_EXPIRED
        WA_PEC_SERVICE_TOKEN_INVALID
        WA_PEC_PROXY_TOKEN_EXPIRED
        WA_PEC_PROXY_TOKEN_INVALID
        WA_PEC_INVALID_REQUEST
        WA_PEC_UNAUTHORIZED
        WA_PEC_SERVER_FAILURE
        WA_PEC_REQUEST_TOKEN_STALE
        WA_PEC_REQUEST_TOKEN_INVALID
        WA_PEC_GET_CRED_FAILURE
        WA_PEC_REQUESTER_KRB5_CRED_INVALID
        WA_PEC_LOGIN_TOKEN_STALE
        WA_PEC_LOGIN_TOKEN_INVALID
        WA_PEC_LOGIN_FAILED
        WA_PEC_PROXY_TOKEN_REQUIRED
        WA_PEC_LOGIN_CANCELED
        WA_PEC_LOGIN_FORCED
        WA_PEC_USER_REJECTED
        WA_PEC_CREDS_EXPIRED
        WA_PEC_MULTIFACTOR_REQUIRED
        WA_PEC_MULTIFACTOR_UNAVAILABLE
        WA_PEC_LOGIN_REJECTED
        WA_PEC_LOA_UNAVAILABLE
        WA_PEC_AUTH_REJECTED
        WA_PEC_AUTH_REPLAY
        WA_PEC_AUTH_LOCKOUT
        WA_PEC_LOGIN_TIMEOUT

        WA_ERR_APR
        WA_ERR_BAD_HMAC
        WA_ERR_BAD_KEY
        WA_ERR_CORRUPT
        WA_ERR_FILE_NOT_FOUND
        WA_ERR_FILE_OPENREAD
        WA_ERR_FILE_OPENWRITE
        WA_ERR_FILE_READ
        WA_ERR_FILE_VERSION
        WA_ERR_FILE_WRITE
        WA_ERR_INVALID
        WA_ERR_INVALID_CONTEXT
        WA_ERR_KRB5
        WA_ERR_NONE
        WA_ERR_NOT_FOUND
        WA_ERR_NO_MEM
        WA_ERR_NO_ROOM
        WA_ERR_RAND_FAILURE
        WA_ERR_REMOTE_FAILURE
        WA_ERR_TOKEN_EXPIRED
        WA_ERR_TOKEN_REJECTED
        WA_ERR_TOKEN_STALE
        WA_ERR_UNIMPLEMENTED

        WA_KEY_AES

        WA_AES_128
        WA_AES_192
        WA_AES_256

        WA_KEY_DECRYPT
        WA_KEY_ENCRYPT

        WA_KRB5_CANON_NONE
        WA_KRB5_CANON_LOCAL
        WA_KRB5_CANON_STRIP
    );

    %EXPORT_TAGS = ('const' => [ @constants ]);
    @EXPORT_OK = (@{ $EXPORT_TAGS{'const'} });
    @EXPORT = ();
}

# Our C code also creates WebAuth::Token::* objects and throws
# WebAuth::Exception objects, and callers expect to be able to call methods on
# those objects.  Load all of the Perl classes for the caller so that the
# caller doesn't have to remember to do so.
use WebAuth::Exception;
use WebAuth::Token::App;
use WebAuth::Token::Cred;
use WebAuth::Token::Error;
use WebAuth::Token::Id;
use WebAuth::Token::Login;
use WebAuth::Token::Proxy;
use WebAuth::Token::Request;
use WebAuth::Token::WebKDCProxy;
use WebAuth::Token::WebKDCService;

bootstrap WebAuth $VERSION;

1;

__END__

=for stopwords
WebAuth API keyring keyrings KEYRING CTX ATTRS login Allbery const
Kerberos TGT SPRINC Canonicalization Kerberos-related decrypt decrypted

=head1 NAME

WebAuth - Perl extension for WebAuth

=head1 SYNOPSIS

    use WebAuth;

    my $wa = WebAuth->new;
    eval {
        $key = $wa->random_key(WebAuth::WA_AES_128);
        ...
    };
    if ($@) {
        # handle exception
    }

=head1 DESCRIPTION

WebAuth is a low-level Perl interface into the WebAuth C API.  It mostly
follows the C API but rearranges the calls into an object-oriented
structure and changes the behavior of some methods to be more Perl-like.

Before calling any of the functions, obtain a new WebAuth object with
C<< WebAuth->new >>.  All subsequent functions take that object as their
first parameter, or should be called as methods on that object, and
other returned objects will normally have that context as hidden data.
This object represents the WebAuth context.  If the WebAuth object goes
out of scope, all other objects created from it, such as keys and
keyrings, will also become invalid.  The caller therefore must be careful
to ensure that no references to other objects are kept around after the
WebAuth object is destroyed.

All and methods functions have the potential to croak with a
WebAuth::Exception object, so an eval block should be placed around calls
to WebAuth functions if you intend to recover from errors.  See
L<WebAuth::Exception> for more information.

In some cases, objects in other classes may be returned by methods.  Those
classes are documented in their own manual or POD pages.

=head1 EXPORT

Nothing is exported by default, but the following export tags are
available:

=over 8

=item const

Exports the WA_* constants.  For a complete list, see L</CONSTANTS>.

=back

To import all constants, use:

    use WebAuth qw(:const);

Individual constants can be imported instead, of course.

=head1 CLASS METHODS

As described above, on any error not explicitly documented below, these
methods will throw a WebAuth::Exception object.

=over 4

=item new ()

Create a new WebAuth context object and return it.  Remember that all
other objects created from this context, such as keys, keyrings, and
tokens, will be destroyed when this context is destroyed, even though
Perl isn't aware of this.

=back

=head1 INSTANCE METHODS

As described above, on any error not explicitly documented below, these
methods will throw a WebAuth::Exception object.

=over 4

=item error_message (STATUS)

Returns an error message string corresponding to STATUS, which should be
one of the WA_ERR_* values.  It's rare to need to use this method, since
generally any error return from the WebAuth C API is converted into a
WebAuth::Exception and thrown instead, and the WebAuth::Exception object
will contain a more detailed error message.

=item key_create (TYPE, SIZE[, KEY_MATERIAL])

Create a new WebAuth::Key object.  TYPE currently must be WA_KEY_AES,
and SIZE must be one of WA_AES_128, WA_AES_192, or WA_AES_256.  This
may change in the future if WebAuth gains support for additional key
types.

If KEY_MATERIAL is given, it should contain SIZE bytes of data, which
will be used as the key.  If KEY_MATERIAL is not given or is undef, a
new random key of the specified TYPE and SIZE will be generated.

The WebAuth::Key object will be destroyed when the WebAuth context used to
create it is destroyed, and subsequent accesses to it may cause memory
access errors or other serious bugs.  Be careful not to retain a copy of
a WebAuth::Key object after the WebAuth object that created it has been
destroyed.

=item keyring_new (KEY)

=item keyring_new (SIZE)

Create a new WebAuth::Keyring object.  This object holds WebAuth::Key
objects and is used for token encryption and decryption.

The argument to this method may be either a WebAuth::Key object or a
numeric size.  If a WebAuth::Key object is provided, a new keyring
containing only that key will be created and returned.  If a size is
provided, a new, empty keyring with space preallocated to hold that
many keys is created and returned.  (Regardless of the allocated size
of a keyring, keyrings will always dynamically expand to hold any new
keys that are added to them.)

The WebAuth::Keyring object will be destroyed when the WebAuth context
used to create it is destroyed, and subsequent accesses to it may cause
memory access errors or other serious bugs.  Be careful not to retain a
copy of a WebAuth::Keyring object after the WebAuth object that created it
has been destroyed.

=item keyring_decode (DATA)

Create a new WebAuth::Keyring object by decoding DATA, which should be a
keyring in its serialization format (as read from a file written by
WebAuth::Keyring->write or encoded with WebAuth::Keyring->encode).  All the
caveats about the lifetime of the WebAuth::Keyring object mentioned for
keyring_new() also apply here.

=item keyring_read (FILE)

Create a new WebAuth::Keyring object by reading its contents from the
provided file.  The created keyring object will have no association with
the file after being created; it won't automatically be saved, or updated
when the file changes.  All the caveats about the lifetime of the
WebAuth::Keyring object mentioned for keyring_new() also apply here.

=item krb5_new ()

Create a new WebAuth::Krb5 object and return it.  This is used as a context
for all Kerberos-related WebAuth calls.  See L<WebAuth::Krb5> for supported
methods.

=item token_decode (INPUT, KEYRING)

Given an encrypted and base64-encoded token, decode and decrypt it using
the provided WebAuth::Keyring object.  The return value will be a subclass
of WebAuth::Token.  See L<WebAuth::Token> for common methods and a list of
possible token object types.

Callers will normally want to check via isa() whether the returned token
is of the type that the caller expected.  Not performing that check can
lead to security issues.

=item token_decrypt (INPUT, KEYRING)

Decrypt the input string, which should be raw encrypted token data (not
base64-encoded), using the provided keyring and return the decrypted data.

This provides access to the low-level token decryption routine and should
not normally be used.  It's primarily available to aid in constructing
test suites.  token_decode() should normally be used instead.

=item token_encrypt (INPUT, KEYRING)

Encrypt the input string, which should be raw token attribute data, using
the provided keyring and return the encrypted data.  The encryption key
used will be the one returned by the best_key() method of WebAuth::Keyring
on that KEYRING.

This provides access to the low-level token encryption routine and should
not normally be used.  It's primarily available to aid in constructing
test suites.  A WebAuth::Token subclass and its encode() method should
normally be used instead.

=back

=head1 CONSTANTS

This module also provides a variety of API constants for the WebAuth
library.  WebAuth API status codes used both for API calls and for login
errors and error tokens:

    WA_PEC_SERVICE_TOKEN_EXPIRED
    WA_PEC_SERVICE_TOKEN_INVALID
    WA_PEC_PROXY_TOKEN_EXPIRED
    WA_PEC_PROXY_TOKEN_INVALID
    WA_PEC_INVALID_REQUEST
    WA_PEC_UNAUTHORIZED
    WA_PEC_SERVER_FAILURE
    WA_PEC_REQUEST_TOKEN_STALE
    WA_PEC_REQUEST_TOKEN_INVALID
    WA_PEC_GET_CRED_FAILURE
    WA_PEC_REQUESTER_KRB5_CRED_INVALID
    WA_PEC_LOGIN_TOKEN_STALE
    WA_PEC_LOGIN_TOKEN_INVALID
    WA_PEC_LOGIN_FAILED
    WA_PEC_PROXY_TOKEN_REQUIRED
    WA_PEC_LOGIN_CANCELED
    WA_PEC_LOGIN_FORCED
    WA_PEC_USER_REJECTED
    WA_PEC_CREDS_EXPIRED
    WA_PEC_MULTIFACTOR_REQUIRED
    WA_PEC_MULTIFACTOR_UNAVAILABLE
    WA_PEC_LOGIN_REJECTED
    WA_PEC_LOA_UNAVAILABLE
    WA_PEC_AUTH_REJECTED
    WA_PEC_AUTH_REPLAY
    WA_PEC_AUTH_LOCKOUT
    WA_PEC_LOGIN_TIMEOUT

Status codes used only for API calls:

    WA_ERR_NONE
    WA_ERR_NO_ROOM
    WA_ERR_CORRUPT
    WA_ERR_NO_MEM
    WA_ERR_BAD_HMAC
    WA_ERR_RAND_FAILURE
    WA_ERR_BAD_KEY
    WA_ERR_FILE_OPENWRITE
    WA_ERR_FILE_WRITE
    WA_ERR_FILE_OPENREAD
    WA_ERR_FILE_READ
    WA_ERR_FILE_VERSION
    WA_ERR_NOT_FOUND
    WA_ERR_KRB5
    WA_ERR_INVALID_CONTEXT
    WA_ERR_TOKEN_EXPIRED
    WA_ERR_TOKEN_STALE
    WA_ERR_APR
    WA_ERR_UNIMPLEMENTED
    WA_ERR_INVALID
    WA_ERR_REMOTE_FAILURE
    WA_ERR_FILE_NOT_FOUND
    WA_ERR_TOKEN_REJECTED

Key types for key_create() and C<< WebAuth::Key->new >>:

    WA_KEY_AES

Key sizes for key_create() and C<< WebAuth::Key->new >>:

    WA_AES_128
    WA_AES_192
    WA_AES_256

Key usages for the best_key() method of WebAuth::Keyring:

    WA_KEY_DECRYPT
    WA_KEY_ENCRYPT

Canonicalization modes for the get_principal() and read_auth() methods of
WebAuth::Krb5:

    WA_KRB5_CANON_NONE
    WA_KRB5_CANON_LOCAL
    WA_KRB5_CANON_STRIP

=head1 AUTHOR

Roland Schemers, Jon Robertson <jonrober@stanford.edu>, and Russ Allbery
<eagle@eyrie.org>.

=head1 SEE ALSO

WebAuth::Exception(3), WebAuth::Key(3), WebAuth::Keyring(3),
WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
