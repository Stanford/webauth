# Perl bindings for the WebAuth client library.
#
# This is the Perl boostrap file for the WebAuth module, nearly all of which
# is implemented in XS.  For the actual source, see WebAuth.xs.  This file
# contains the bootstrap and export code and the documentation.
#
# Written by Roland Schemers
# Copyright 2003, 2005, 2008, 2009, 2011, 2012
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

use 5.006;
use strict;
use warnings;

use base qw(Exporter DynaLoader);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION;
BEGIN {
    $VERSION = '3.02';
}

our (@EXPORT, @EXPORT_OK, %EXPORT_TAGS);
BEGIN {
    my @constants = qw(WA_ERR_NONE
                       WA_ERR_NO_ROOM
                       WA_ERR_CORRUPT
                       WA_ERR_NO_MEM
                       WA_ERR_BAD_HMAC
                       WA_ERR_RAND_FAILURE
                       WA_ERR_BAD_KEY
                       WA_ERR_KEYRING_OPENWRITE
                       WA_ERR_KEYRING_WRITE
                       WA_ERR_KEYRING_OPENREAD
                       WA_ERR_KEYRING_READ
                       WA_ERR_KEYRING_VERISON
                       WA_ERR_NOT_FOUND
                       WA_ERR_KRB5
                       WA_ERR_INVALID_CONTEXT
                       WA_ERR_LOGIN_FAILED
                       WA_ERR_TOKEN_EXPIRED
                       WA_ERR_TOKEN_STALE
                       WA_ERR_CREDS_EXPIRED
                       WA_ERR_USER_REJECTED
                       WA_ERR_APR
                       WA_ERR_UNIMPLEMENTED
                       WA_ERR_INVALID
                       WA_ERR_REMOTE_FAILURE

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

                       WA_KEY_AES

                       WA_AES_128
                       WA_AES_192
                       WA_AES_256

                       WA_KEY_DECRYPT
                       WA_KEY_ENCRYPT

                       WA_KRB5_CANON_NONE
                       WA_KRB5_CANON_LOCAL
                       WA_KRB5_CANON_STRIP);

    our %EXPORT_TAGS = ('const' => [ @constants ]);
    our @EXPORT_OK = (@{ $EXPORT_TAGS{'const'} });
    our @EXPORT = ();
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
WebAuth API keyring keyrings KEYRING CTX KDC ATTRS login KEYTAB PRINC
decrypt decrypted EDATA Allbery const krb5 TGT SPRINC Canonicalization

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

The Kerberos functions have not yet been converted to the object-oriented
structure and will be changing in a subsequent release.

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

=item krb5

Exports the krb5_* functions.

=back

To import all of both, use:

    use WebAuth qw(:krb5 :const);

Individual constants or krb5_* functions can be imported instead, of
course.  The krb5_* functions will become object methods and will no
longer be exported in a subsequent release.

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

=item attrs_decode (INPUT)

Given a string representing a set of attributes encoded in the attribute
format used inside WebAuth tokens, decode that string into a hash where
the keys are the attributes and the values are their corresponding values.
Attribute strings that contain the same attribute multiple times are not
supported and will produce undefined results.  (Such strings are not valid
in WebAuth tokens.)

=item attrs_encode (ATTRS)

Given ATTRS, which must be a reference to a hash, take the hash members as
attribute and value pairs and encode them into the attribute format used
inside WebAuth tokens.  The values in the ATTRS hash are converted to
strings if they are not already.  Nested complex data structures, such as
references to other arrays or hashes, are not supported and will produce
undefined results.

=item base64_decode (INPUT)

Decode INPUT as a base64 string and return the result.

This function is deprecated; use decode_base64() from L<MIME::Base64>
instead.

=item base64_encode (INPUT);

Encode INPUT into base64 and return the result.

This function is deprecated; use encode_base64() from L<MIME::Base64>
instead.

=item error_message (STATUS)

Returns an error message string corresponding to STATUS, which should be
one of the WA_ERR_* values.  It's rare to need to use this method, since
generally any error return from the WebAuth C API is converted into a
WebAuth::Exception and thrown instead, and the WebAuth::Exception object
will contain a more detailed error message.

=item hex_decode (INPUT)

Interpret INPUT as a sequence of hexadecimal numbers, with two characters
per number, and convert each number into the corresponding byte, returning
the result.

=item hex_encode (INPUT)

For each byte in INPUT, encode it in two hexadecimal digits, and return
the resulting string.

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

=item keyring_read (FILE)

Create a new WebAuth::Keyring object by reading its contents from the
provided file.  The created keyring object will have no association with
the file after being created; it won't automatically be saved, or updated
when the file changes.  All the caveats about the lifetime of the
WebAuth::Keyring object mentioned for keyring_new() also apply here.

=item krb5_new ()

Create a new WEBAUTH_KRB5_CTXT reference and return it.  This is used as
the first argument to subsequent krb5_* functions, as documented below.

=item token_decode (INPUT, KEYRING)

Given an encrypted and base64-encoded token, decode and decrypt it using
the provided WebAuth::Keyring object.  The return value will be a subclass
of WebAuth::Token.  See L<WebAuth::Token> for common methods and a list of
possible token object types.

Callers will normally want to check via isa() whether the returned token
is of the type that the caller expected.  Not performing that check can
lead to security issues.

=back

=head1 FUNCTIONS

As described above, on any error not explicitly documented below, these
functions will throw a WebAuth::Exception object.

=over 4

=item krb5_change_password (CTX, PASSWORD)

Change the password of the user represented by the Kerberos context to
PASSWORD.  CTX must already contain a kadmin/changepw credential and will
generally be created with krb5_init_via_password() or read from a context
created that way using krb5_init_via_cred().

=item krb5_export_tgt (CTX)

Exports the Kerberos TGT contained in the provided context, which should
have been initialized via one of the krb5_init_via_* functions.  Returns a
list of two values: the encoded Kerberos ticket itself (as binary data)
and the expiration time of the ticket in seconds since epoch.

=item krb5_export_ticket (CTX, PRINC)

Exports a service ticket for the given principal PRINC.  Returns a list of
two values: the encoded Kerberos ticket itself (as binary data) and the
expiration time of the ticket in seconds since epoch.

=item krb5_get_principal (CTX[, LOCAL])

Returns the principal associated with the Kerberos context, which should
have been initialized via one of the krb5_init_via_* functions.  If LOCAL
is a true value, krb5_aname_to_localname will be run on the principal
before returning it.  If krb5_aname_to_localname returns an error, the
fully-qualified principal will be returned.

=item krb5_import_cred (CTX, CRED)

Imports the provided credential, created with krb5_export_*, into the
given Kerberos context.  Normally, krb5_init_via_cred is used instead of
this function, but it may be useful if multiple credentials for the same
principal are available and need to be imported into the same context.

=item krb5_init_via_cache (CTX[, CACHE])

Initializes a Kerberos context from the specified ticket cache.  If CACHE
is not specified, the default Kerberos ticket cache is used.

=item krb5_init_via_cred (CTX, CRED[, CACHE])

Initializes a Kerberos context from an encoded Kerberos credential that
was previously exported using krb5_export_*.  If CACHE is not specified, a
memory cache will be used and destroyed when the context is destroyed.

=item krb5_init_via_keytab (CTX, KEYTAB[, PRINC[, CACHE]])

Initializes a Kerberos context by using the keys in the provided KEYTAB to
get a Kerberos TGT.  If CACHE is not specified, a memory cache will be used
and destroyed when the context is destroyed.

PRINC specifies the principal for which to get tickets.  If it is not
specified, undef, or the empty string, the first principal found in KEYTAB
will be used.

=item krb5_init_via_password (CTX, USER, PASS[, PRINC[, KEYTAB[, SPRINC[, CACHE]]]])

Initializes a Kerberos context using the specified username/password to
obtain a Kerberos TGT.  The TGT will be verified using the principal in
KEYTAB by doing a krb5_mk_req/krb5_rd_req.  If CACHE is not specified, a
memory cache will be used and destroyed when the context is destroyed.

If SPRINC is given, it specifies the principal in KEYTAB to use for the
validation.  If it is not specified, undef, or the empty string, the first
principal found in KEYTAB will be used.

If PRINC is given and defined, obtain credentials for that principal
rather than a TGT.  This is normally used to get a context with a
kadmin/changepw service ticket to use to change the user's password.

If KEYTAB is not given, do not verify the validity of the returned
tickets.  This should only be used when obtaining kadmin/changepw service
tickets to change a password.  Skipping this validation step otherwise
opens one up to KDC impersonation attacks.

Returns the server principal used to verify the TGT.

=item krb5_keep_cred_cache (CTX)

If called before CONTEXT is destroyed, prevents the credential cache
(created via one of the calls to krb5_init_via*) from being destroyed with
the context.  This should only be used you need to keep a file-based
credential cache from being removed.

=item krb5_mk_req (CTX, PRINC[, DATA])

Construct a Kerberos request for the specified principal and return the
request, suitable for passing to krb5_rd_req.  If DATA is provided, it
will be encrypted with krb5_mk_priv, and the return value will be a
two-element list consisting of the request and the encrypted DATA.

=item krb5_rd_req (CTX, REQUEST, KEYTAB[, PRINC[, LOCAL[, EDATA]]])

Read a REQUEST created with krb5_mk_req and returns the principal of the
request.  KEYTAB is used to decode the request, and PRINC must be the
principal for which the REQUEST was encoded.  If PRINC is not provided,
undef, or the empty string, the first principal found in KEYTAB will be
used.

If LOCAL is set to a true value, krb5_aname_to_localname will be run on
the principal before returning it.  If krb5_aname_to_localname returns an
error, the fully-qualified principal will be returned.

If EDATA is provided, it is encrypted with krb5_rd_priv, and the return
value will be a two-element list containing the principal and the
decrypted data.

=back

=head1 CONSTANTS

The following API constants for the WebAuth library are available.
WebAuth error codes used in WebAuth::Exception for API call failures.

    WA_ERR_NONE
    WA_ERR_NO_ROOM
    WA_ERR_CORRUPT
    WA_ERR_NO_MEM
    WA_ERR_BAD_HMAC
    WA_ERR_RAND_FAILURE
    WA_ERR_BAD_KEY
    WA_ERR_KEYRING_OPENWRITE
    WA_ERR_KEYRING_WRITE
    WA_ERR_KEYRING_OPENREAD
    WA_ERR_KEYRING_READ
    WA_ERR_KEYRING_VERISON
    WA_ERR_NOT_FOUND
    WA_ERR_KRB5
    WA_ERR_INVALID_CONTEXT
    WA_ERR_LOGIN_FAILED
    WA_ERR_TOKEN_EXPIRED
    WA_ERR_TOKEN_STALE
    WA_ERR_CREDS_EXPIRED
    WA_ERR_USER_REJECTED
    WA_ERR_APR
    WA_ERR_UNIMPLEMENTED
    WA_ERR_INVALID
    WA_ERR_REMOTE_FAILURE

WebAuth protocol error codes used for login errors:

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
<rra@stanford.edu>.

=head1 SEE ALSO

WebAuth::Exception(3), WebAuth::Key(3), WebAuth::Keyring(3),
WebAuth::Token(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
