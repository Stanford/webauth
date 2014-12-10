# Documentation and supplemental methods for a WebAuth Kerberos context.
#
# The primary implementation of the WebAuth::Krb5 class is done in the WebAuth
# XS module since it's primarily implemented in C.  This file adds some
# supplemental methods that are implemented in terms of other underlying calls
# and provides version and documentation information.
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

package WebAuth::Krb5;

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

# Constructor.  Takes a WebAuth context and wraps a call to krb5_new().  Note
# that subclasses are not supported since the object is created by the XS
# module and will always be a WebAuth::Krb5 object.
sub new {
    my ($type, $ctx) = @_;
    if ($type ne 'WebAuth::Krb5') {
        croak ('subclassing of WebAuth::Krb5 is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->krb5_new;
}

1;

=for stopwords
WebAuth WEBAUTH timestamp Allbery Kerberos username keytab CTX TGT
canonicalization PRINC SPRINC authenticator EDATA canonicalized
Kerberos-related decrypted KDC TGS-REQ kpasswd remctl subcommand

=head1 NAME

WebAuth::Krb5 - WebAuth context for Kerberos calls

=head1 SYNOPSIS

    use WebAuth qw(:const);
    use WebAuth::Krb5;

    my $wa = WebAuth->new;
    eval {
        my $krb5 = WebAuth::Krb5->new ($wa);
        $krb5->init_via_keytab ($path);
        print $krb5->get_principal (WA_KRB5_CANON_LOCAL);
    }
    if ($@) {
        # ... handle exception ...
    }

=head1 DESCRIPTION

This Perl context represents a WebAuth Kerberos context.  This context is
used to make all Kerberos-related calls and can also store a Kerberos
identity and its corresponding ticket cache.  A context is normally
initiated with credentials from a username and password, a keytab, an
existing ticket cache, or an exported credential.

=head1 CLASS METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item new (WEBAUTH)

Create a new WebAuth::Krb5 object attached to the WebAuth context WEBAUTH.
This is a convenience wrapper around the WebAuth krb5_new() method.

=back

=head1 INSTANCE METHODS

As with WebAuth module functions, failures are signaled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item change_password (PASSWORD[, ARGS])

Change the password of the user represented by the Kerberos context to
PASSWORD.  The WebAuth::Krb5 object must already contain the credentials
required to change a password (normally a kadmin/changepw credential
created with krb5_init_via_password() or read from a context created that
way using krb5_init_via_cred()).

By default, the kpasswd protocol is used to do the password change.  This
behavior can be modified using the optional ARGS argument which, if
present, should be a reference to a hash with one or more of the following
keys:

=over 4

=item command

The command to send.  Currently only used for the C<remctl> password
change protocol.

=item host

The host to which to send the password change.  Currently only used for
the C<remctl> password change protocol.

=item identity

The Kerberos principal of the password change service to which this
command will authenticate in order to send the change.  The default
depends on the protocol.  Currently this is only used for the C<remctl>
password change protocol, which defaults to the normal principal used by
remctl clients when sending commands.  However, normally this will be a
principal that disallows TGS-REQ authentications rather than the remctl
default.

If this principal disallows TGS-REQ authentications, credentials for this
principal must already be present in the WebAuth::Krb5 object before
making this call since they cannot be retrieved from the KDC without
additional authentication credentials.

=item port

The port on the password change host to contact.  Currently only used for
the C<remctl> password change protocol.

=item protocol

The password change protocol to use.  Currently supported values are
C<kpasswd> and C<remctl>.  C<kpasswd> is the default and takes no further
parameters, so in that case ARGS should normally be omitted.  This key
should normally always be set.

=item subcommand

The subcommand to send.  Currently only used for the C<remctl> password
change protocol.

=item timeout

How long to wait, in integer seconds, for a reply before giving up.
Currently only used for the C<remctl> password change protocol.

=back

An example of doing a password change via the remctl protocol, using
C<kadmin/changepw> as the service principal and taking the other options
from global configuration, with a ten-second timeout:

    my $wa = WebAuth->new;
    my $krb5 = WebAuth::Krb5->new ($wa);
    $krb5->init_via_password ('user', 'password', 'kadmin/changepw');
    my $args = {
        protocol   => 'remctl',
        host       => $PASSWORD_CHANGE_SERVER,
        port       => $PASSWORD_CHANGE_PORT,
        identity   => 'kadmin/changepw',
        command    => $PASSWORD_CHANGE_COMMAND,
        subcommand => $PASSWORD_CHANGE_SUBCOMMAND,
        timeout    => 10,
    };
    $krb5->change_password ('new-password', $args);

For the C<remctl> protocol, the server must expose a command and
subcommand that takes a single argument, the new password, and changes the
password of the authenticated user.

=item export_cred ([PRINC])

Exports either a Kerberos TGT or a Kerberos service ticket obtained using
the credentials in the WebAuth::Krb5 context, have been initialized via
one of the init_via_* methods or import_cred first.  In a scalar context,
returns the encoded Kerberos ticket (as binary data), suitable for passing
to import_cred() or putting into a WebAuth token.  In a list context,
returns a two-element list consisting of the encoded Kerberos ticket and
the expiration time of the ticket in seconds since epoch.

=item get_principal ([CANON])

Returns the principal associated with the Kerberos context, which should
have been initialized via one of the init_via_* methods or import_cred
first.  CANON should be one of WA_KRB5_CANON_NONE (specifying no principal
canonicalization), WA_KRB5_CANON_LOCAL (specifying that the principal
should be converted to a local name if possible), or WA_KRB5_CANON_STRIP
(specifying that any realm information should be stripped).  These
constants are provided by the WebAuth module.

If WA_KRB5_CANON_LOCAL is specified but krb5_aname_to_localname returns an
error, the fully-qualified principal will be returned.

If CANON is not specified, WA_KRB5_CANON_NONE is the default behavior.

=item import_cred (CRED[, CACHE])

Imports the provided credential, created with export_cred, into the given
Kerberos context.  If the context is not already initialized, it will be
initialized with the identity specified by the credential.  CACHE
specifies where to store the credential cache for this context and will be
used only if the context is not already initialized.  If CACHE is not
specified and the context is not initialized, a memory cache will be used
and destroyed when the context is destroyed.

=item init_via_cache ([CACHE])

Initializes a Kerberos context from an existing ticket cache.  If CACHE is
not specified, the default Kerberos ticket cache is used.

=item init_via_keytab (KEYTAB[, PRINC[, CACHE]])

Initializes a Kerberos context by using the keys in the provided KEYTAB to
get a Kerberos TGT.  If CACHE is not specified, a memory cache will be
used and destroyed when the context is destroyed.

PRINC specifies the principal for which to get tickets.  If it is not
specified, the first principal found in KEYTAB will be used.

=item init_via_password (USER, PASS[, PRINC[, KEYTAB[, SPRINC[, CACHE]]]])

Initializes a Kerberos context using the specified username/password to
obtain a Kerberos TGT.  If KEYTAB is specified and PRINC is not given, the
TGT will be verified using the normal krb5_verify_init_creds function.  If
CACHE is not specified, a memory cache will be used and destroyed when the
context is destroyed.

If SPRINC is given, it specifies the principal in KEYTAB to use for the
validation.  If it is not specified, undef, or the empty string, the first
principal found in KEYTAB will be used.

If PRINC is given and defined, obtain credentials for that principal
rather than a TGT.  This is normally used to get a context with a
C<kadmin/changepw> service ticket to use to change the user's password.
If this is specified, the validity of the acquired credentials will not be
verified.

If KEYTAB is not given, the validity of the returned tickets are not
verified.  This should only be used when obtaining C<kadmin/changepw>
service tickets to change a password.  Skipping this validation step
otherwise opens one up to KDC impersonation attacks.

Returns the server principal used to verify the TGT if KEYTAB is given
and PRINC is not given.  Otherwise, returns undef.

=item make_auth (PRINC[, DATA])

Construct a Kerberos authenticator for the specified principal and return
the authenticator, suitable for passing to krb5_rd_req (possibly by way of
the read_auth method).  If DATA is provided, it will be encrypted with
krb5_mk_priv in the session key of the authenticator.

In a scalar context, returns the authenticator as binary data.  In a list
context, when DATA is given, returns a two-element list consisting of the
authenticator and the encrypted DATA.

=item read_auth (REQUEST, KEYTAB[, PRINC[, CANON[, EDATA]]])

Read a REQUEST created with make_auth and returns the client principal of
the authenticator.  KEYTAB is used to decode the request, and PRINC must
be the principal for which the REQUEST was encoded.  If PRINC is not
provided, undef, or the empty string, the first principal found in KEYTAB
will be used.

The returned client principal is canonicalized following the rule
specified in CANON, following the same rules as in get_principal().  If
CANON is not specified, WA_KRB5_CANON_NONE is the default behavior.

If EDATA is provided, it is decrypted with krb5_rd_priv, and the return
value in a list context will be a two-element list containing the
principal and the decrypted data.

=back

=head1 CAVEATS

A WebAuth::Krb5 object will retain a reference to the WebAuth object that
was used to create it and will prevent the WebAuth context from being
freed until the WebAuth::Krb5 object can be freed.  This ensures that
objects don't disappear at inappropriate times, but it also means that no
memory allocated in the WebAuth context, even if unrelated to the
WebAuth::Krb5 object, will be freed until all objects created from it are
freed.  Creating and holding on to references to WebAuth::Krb5 objects for
long periods may therefore result in unexpected memory usage.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=head1 SEE ALSO

WebAuth(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
