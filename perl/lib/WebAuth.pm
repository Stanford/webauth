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
# See LICENSE for licensing terms.

package WebAuth;

use 5.006;
use strict;
use warnings;

# Our C code also creates WebAuth::Token::* objects, and callers expect to be
# able to call methods on those objects.  Load all of the Perl classes for the
# caller so that the caller doesn't have to remember to do so.
use WebAuth::Token::App;
use WebAuth::Token::Cred;
use WebAuth::Token::Error;
use WebAuth::Token::Id;
use WebAuth::Token::Login;
use WebAuth::Token::Proxy;
use WebAuth::Token::Request;
use WebAuth::Token::WebKDCProxy;
use WebAuth::Token::WebKDCService;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration        use WebAuth ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
                    'attrs' => [ qw(attrs_encode attrs_decode) ],
                    'base64' => [ qw(base64_encode base64_decode) ],
                    'const' => [ qw(WA_ERR_NONE
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
                                    WA_KEY_AES
                                    WA_AES_128
                                    WA_AES_192
                                    WA_AES_256
                                    WA_TK_APP_STATE
                                    WA_TK_COMMAND
                                    WA_TK_CRED_DATA
                                    WA_TK_CRED_SERVICE
                                    WA_TK_CRED_TYPE
                                    WA_TK_CREATION_TIME
                                    WA_TK_ERROR_CODE
                                    WA_TK_ERROR_MESSAGE
                                    WA_TK_EXPIRATION_TIME
                                    WA_TK_INITIAL_FACTORS
                                    WA_TK_SESSION_KEY
                                    WA_TK_LOA
                                    WA_TK_LASTUSED_TIME
                                    WA_TK_OTP
                                    WA_TK_PASSWORD
                                    WA_TK_PROXY_DATA
                                    WA_TK_PROXY_SUBJECT
                                    WA_TK_PROXY_TYPE
                                    WA_TK_REQUEST_OPTIONS
                                    WA_TK_REQUESTED_TOKEN_TYPE
                                    WA_TK_RETURN_URL
                                    WA_TK_SUBJECT
                                    WA_TK_SUBJECT_AUTH
                                    WA_TK_SUBJECT_AUTH_DATA
                                    WA_TK_SESSION_FACTORS
                                    WA_TK_TOKEN_TYPE
                                    WA_TK_USERNAME
                                    WA_TK_WEBKDC_TOKEN
                                    )],
                    'hex' => [ qw(hex_encode hex_decode) ],
                    'key' => [ qw(key_create) ],
                    'krb5' => [ qw(krb5_new krb5_error_code krb5_err_message
                                   krb5_init_via_password
                                   krb5_init_via_keytab
                                   krb5_init_via_cred
                                   krb5_init_via_cache
                                   krb5_import_cred
                                   krb5_export_tgt
                                   krb5_get_principal
                                   krb5_export_ticket
                                   krb5_change_password
                                   krb5_mk_req krb5_rd_req
                                   krb5_keep_cred_cache)],
                    'random' => [ qw(random_bytes random_key) ],
                    'token' => [ qw(token_create token_parse) ],
                    );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'attrs'} },
                   @{ $EXPORT_TAGS{'base64'} },
                   @{ $EXPORT_TAGS{'const'} },
                   @{ $EXPORT_TAGS{'hex'} },
                   @{ $EXPORT_TAGS{'key'} },
                   @{ $EXPORT_TAGS{'krb5'} },
                   @{ $EXPORT_TAGS{'random'} },
                   @{ $EXPORT_TAGS{'token'} },
                   );

our @EXPORT = qw ();
our $VERSION = '3.00';

bootstrap WebAuth $VERSION;

# Preloaded methods go here.

package WebAuth::Exception;

use strict;
use warnings;

use WebAuth;

use overload '""' => \&to_string;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 3.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = ();
}

our @EXPORT_OK;

#sub new {
#    my ($type, $detail, $s, $kc) = @_;
#    my $self = {};
#    bless $self, $type;
#    $self->{'status'} = $s;
#    $self->{'detail'} = $detail;
#    if (defined($kc) && $s == WebAuth::WA_ERR_KRB5) {
#        $self->{'krb5_ec'} = WebAuth::krb5_error_message($kc);
#        $self->{'krb5_em'} = WebAuth::krb5_error_code($kc);
#    }
#    return $self;
#}

sub status {
    my ($self) = @_;
    return $self->{'status'};
}

sub krb5_error_code {
    my ($self) = @_;
    return $self->{'krb5_ec'};
}

sub krb5_error_message {
    my ($self) = @_;
    return $self->{'krb5_em'};
}

sub error_message {
    my ($self) = @_;
    return $self->{'message'};
}

sub detail_message {
    my ($self) = @_;
    return $self->{'detail'};
}

sub verbose_message {
    my ($self) = @_;
    my $s = $self->{'status'};
    my $line = $self->{'line'};
    my $file = $self->{'file'};
    my $msg = $self->{'message'};
    my $detail = $self->{'detail'};
    if (defined $detail) {
        $msg = "WebAuth::Exception $detail: $msg";
    }
    if ($s == &WebAuth::WA_ERR_KRB5) {
        my $kec = $self->{'krb5_ec'};
        my $kem = $self->{'krb5_em'};
        $msg .= ": $kem ($kec)";
    }
    if (defined $line) {
        $msg .= " at $file line $line";
    }
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->verbose_message();
}

sub match {
    my $e = shift;
    return 0 unless ref $e;
    return 0 if !$e->isa("WebAuth::Exception");
    return @_ ? $e->status() == shift : 1;
}

1;

__END__

=head1 NAME

WebAuth - Perl extension for WebAuth (version 3)

=head1 SYNOPSIS

  use WebAuth;

  my $wa = WebAuth->new;
  eval {
    $key = $wa->random_key(WebAuth::WA_AES_128);
    ...
  };
  if (WebAuth::Exception::match($@)) {
    # handle exception
  }

=head1 DESCRIPTION

WebAuth is a low-level Perl interface into the WebAuth C API.  Some
functions have been made more Perl-like, and there is some partial work on
changing the API to be object-oriented.

All functions have the potential to croak with a WebAuth::Exception
object, so an eval block should be placed around calls to WebAuth
functions if you intend to recover from errors.  See the
WebAuth::Exception section for more information.

Nearly all of the functionality is directly in the WebAuth namespace for
right now.  The exceptions are WebAuth::Exception, WebAuth::Keyring, and
WebAuth::KeyringEntry objects, described in L</SUBCLASSES> below.

Before calling any of the functions, obtain a new WebAuth object with
C<< WebAuth->new >>.  All subsequent functions take that object as their
first parameter, or should be called as methods on that object.

=head1 EXPORT

Nothing is exported by default, but the following %EXPORT_TAGS are
available:

  attrs     the attr_* functions
  base64    the base64_* functions
  const     the wA_* constants
  hex       the hex_* functions
  key       the key_* functions
  krb5      the krb5_* functions
  random    the random_* functions
  token     the token_* functions

For example:

  use WebAuth qw(:krb5 :const);

=head1 FUNCTIONS

=over 4

=item error_message(self, status)

 $message = $wa->error_message($status)

Returns an error message for the specified status, which should
be one of the WA_ERR_* values.

=item base64_encode(self, input);

 $output = $wa->base64_encode($input);

base64 encodes the $input string and returns the result.

=item base64_decode(self, input)

 $output = $wa->base64_decode($input);

base64 decodes the $input string and returns the result in $output,
or undef if unable to parse $input.

=item hex_encode(self, input);

 $output = $wa->hex_encode($input);

hex encodes the $input string and returns the result.

=item hex_decode(self, input)

 $output = $wa->hex_decode($input);

hex decodes the $input string and returns the result in $output,
or undef if unable to decode $input.

=item attrs_encode(self, attrs);

 $output = $wa->attrs_encode($attrs);

Takes as input $attrs (which must be a reference to a hash) and returns
a string of the encoded attributes in $output.  The values in the $attrs
hash table get converted to strings if they aren't already.

=item attrs_decode(self, input);

 $attrs = $wa->attrs_decode($input);

attr decodes the $input string and returns the result in $attrs as
a reference to a hash, or croaks in case of an error.

=item random_bytes(self, length)

 $bytes = $wa->random_bytes($length);

Returns the specified number of random bytes, or undef if
random data was unavailable. The returned data is suitable
for nonces, but not necessarily for keys. Use random_key to
generate a suitable random key.

=item random_key(self, length)

 $key_material = $wa->random_key($length);

Returns the specified number of random bytes, or undef if
random data was unavailable. The returned data is suitable
for use as a key. Use the constants WA_AES_128, WA_AES_192, and
WA_AES_256 to specify a 128 bit, 192 bit, or 256 bit AES key respectively.

=item key_create(self, type, key_material)

 $key = $wa->key_create($type, $key_material);

Creates a reference to a WEBAUTH_KEYPtr object, or undef
on error. $type must be WA_KEY_AES, and $key_material must
be a string with a length of
WA_AES_128, WA_AES_192, or WA_AES_256 bytes. $key should be set
to undef when the key is no longer needed.

=item token_create(self, attrs, hint, key_or_ring)

  $token = $wa->token_create($attrs, $hint, $key_or_ring);

Takes as input $attrs (which must be a reference to a hash) and
$key_or_ring (created with keyring_new or key_create) and returns
the encrypted token. If hint is 0, the current time will be used.

The values in the $attrs hash table get converted to strings if they
aren't already.

=item token_parse(self, token, ttl, key_or_ring)

  $attrs = $wa->token_parse($token, $ttl, $key_or_ring);

Takes as input an encrypted token and a key_or_ring (created with
keyring_new or key_create) and returns the attributes.

=item krb5_new(self)

  $context = $wa->krb5_new();

Creates a new WEBAUTH_KRB5_CTXT reference in $context.

=item krb5_keep_cred_cache(context)

  krb5_keep_cred_cache($context);

If called before $context is no longer in use, prevents the credential
cache (created via one of the calls to krb5_init_via*) from being
destroyed. This should only be used you need to keep a file-based
credential cache from being removed.

=item krb5_init_via_password(context, user, password, get_principal, keytab, server_principal[, cache])

   ($principal) = krb5_init_via_password($context, $user, $password,
                                         $get_principal, $keytab,
                                         $server_principal[, $cache]);

Initializes a context using the specified username/password to obtain
a TGT. The TGT will be verified using the principal in the keytab by
doing a krb5_mk_req/krb5_rd_req. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

If $server_princpal is undef or "", then the first principal found in the
keytab will be used.

If $get_principal is definied, then rather than using the principal in the
keytab, we will get a context for the given principal.  This is currently
used to get a context for kadmin/changepw with a given username and password,
in order to then later use that to change the user password.

If $keytab is not defined, then we do not obtain a TGT, but only initialize
the context without verifying its validity.  This is currently only used in
conjunction with $get_principal to get credentials for kadmin/changepw.

Returns the server principal used to verify the TGT.

=item krb5_init_via_keytab(context, keytab, server_princpal, [, cache])

   krb5_init_via_keytab($context, $keytab, $server_princpal[, $cache]);

Initializes a context using the principal in the specified keytab
by getting a TGT. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

If $server_princpal is undef or "", then the first princpal found in the
keytab will be used.

=item krb5_init_via_cache(context[, cache])

   krb5_init_via_cache($context, "/tmp/krb5cc_foo");

Initializes a context using the specified ticket cache. If $cache is not
specified, the default kerberos ticket cache is used.

=item krb5_init_via_cred(context, cred[, cache])

   krb5_init_via_cred($context, $cred[, $cache]);

Initializes a context using a ticket that was previously exported using
krb5_export_*. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_export_tgt(context)

  ($tgt, $expiration) = krb5_export_tgt($context)

Used to "export" a TGT from the specified context, which should have
been initialized via one of the krb5_init_via_* functions. On
success both  $tgt and $expiration get set. $ticket is the ticket
itself (binary data) and $expiration is the expiration time of the ticket.

=item krb5_import_cred(context, cred)

  krb5_import_cred($context, $cred);

Used to "import" a ticket that was created with krb5_export_*.

=item krb5_export_ticket(context, principal);

  ($ticket, $expiration) = krb5_export_ticket($context, $principal);

Used to "export" a ticket for the requested server principal. On success,
both $ticket and $expiration will be set. $ticket is the ticket itself
(binary data) and $expiration is the expiration time of the ticket.

=item krb5_get_principal(context, 1)

    $principal = krb5_getprincipal($context, 1);

Used to get the principal associated with the context. Should only be
called after a successful call to krb5_init_via*. If local is 1, then
krb5_aname_to_localname is called on the principal. If krb5_aname_to_localname
returns an error then the fully-qualified principal name is returned.

=item krb5_mk_req(context, principal[,data])

    ($request[, $edata]) = krb5_mk_req($context, $principal[,$data]);

Used to construct a kerberos V5 request for the specified principal. $request
will be set on success, and will contain the result of the krb5_mk_req call.
If $data is passed in, tben it will be encrypted using krb5_mk_priv and
returned as $edata.

=item krb5_rd_req(context, request, keytab, server_principal, local[, edata])

   ($principal[, $data])
      = krb5_rd_req($context, $request, $keytab,
                              $server_princpal, 1[, $edata]);

Used to read a request created with krb5_mk_req. On success $principal
will be set to the client principal in the request. If local is 1, then
krb5_aname_to_localname is called on the principal. If krb5_aname_to_localname
returns an error then the fully-qualified principal name is returned.

If $server_princpal is undef or "", then the first principal found in the
keytab will be used.

If $edata is passed in, it is decrypted with krb5_rd_priv.

=item krb5_change_password(context, password)

    krb5_change_password($context, $password);

Used to change a principal to a new password.  Requires a context with a
kadmin/changepw credential already formed from that user's current principal
name and password.

=back

=head1 SUBCLASSES

=head2 WebAuth::Exception

The various WebAuth functions can all throw exceptions if something
wrong happens. These exceptions will be of type WebAuth::Exception.

For example:

  eval {
    $data = WebAuth::base64_decode($buffer);
    ...
  };
  if (WebAuth::Exception::match($@)) {
    my $e = $@;
    # you can call the following methods on an Exception object:
    # $e->status()
    # $e->error_message()
    # $e->detail_message()
    # $e->krb5_error_code()
    # $e->krb5_error_message()
    # $e->verbose_message()
  }

=over 4

=item match($exception[, $status])

This class function (not a method) returns true if the given
$exception is a WebAuth::Exception. If $status is specified, then
$exception->status() will also be compared to $status.

=item status()

This method returns the WebAuth status code for the exception,
which will be one of the WA_ERR_* codes.

=item error_message()

This method returns the WebAuth error message for the status code,
using the WebAuth::error_message function.

=item detail_message()

This method returns the "detail" message in the exception. The detail
message is additional information created with the exception when
it is raised, and is usually the name of the WebAuth C function that
raised the exception.

=item krb5_error_code()

If the status of the exception is WA_ERR_KRB5, then this function
will return the Kerberos error code that caused the exception.
There are currently no constants defined for these error codes.

=item krb5_error_message()

If the status of the exception is WA_ERR_KRB5, then this function
will return the Kerberos error message corresponding to the
krb5_error_code.

=item verbose_message()

This method returns a verbose error message, which consists
of all information available in the exception, including the
status code, error message, line number and file, and any detail
message in the exception. It also will include the kerberos
error code and error message if status is WA_ERR_KRB5.

The verbose_message method is also called if the exception is
used as a string.

=back

=head2 WebAuth::Keyring

This Perl class represents a keyring, which is a set of WebAuth keys with
associated creation times and times after which they become valid.  These
keyrings can be read from and stored to files on disk and are used by
WebAuth Application Servers and WebKDCs to store their encryption keys.

=head3 Class Methods

=over 4

=item new([CAPACITY])

Create a new keyring with initial capacity CAPACITY.  The default initial
capacity is 1 if none is given.  Keyrings automatically resize to hold
more keys when necessary, so the capacity is only for efficiency if one
knows in advance roughly how many keys there will be.  Returns a new
WebAuth::Keyring object or throws a WebAuth::Exception.

=item read_file(FILE)

Reads a keyring from the file FILE.  The created keyring object will have
no association with the file after being created; it won't automatically
be saved, or updated when the file changes.  Returns a new
WebAuth::Keyring object or throws a WebAuth::Exception.

=back

=head3 Instance Methods

As with other WebAuth module functions, failures are signalled by throwing
WebAuth::Exception rather than by return status.

=over 4

=item add(CREATION, VALID_AFTER, KEY)

Add a new KEY to the keyring with CREATION as the creation time and
VALID_AFTER as the valid after time.  Both of the times should be in
seconds since epoch, and the key must be a valid WebAuth key, such as is
returned by WebAuth::webauth_random_key().  Keys will not used for
encryption until after their valid after time, which provides an
opportunity to synchronize the keyring between multiple systems before the
keys are used.

=item best_key(ENCRYPTION, HINT)

Returns the best key available in the keyring for a particular purpose and
time.  ENCRYPTION is a boolean and should be true if the key will be used
for encryption and false if it will be used for decryption.  For
decryption keys when ENCRYPTION is false, HINT is the timestamp of the
data that will be decrypted.

If ENCRYPTION is true, this method will return the valid key in the
keyring that was created most recently, since this is the best key to use
for encryption going forward.  If ENCRYPTION is false, this method will
return the key most likely to have been used to encrypt something at the
time HINT, where HINT is given in seconds since epoch.

=item capacity()

Returns the capacity of the keyring (the total number of keys it can hold
without being resized).  This is not usually interesting since keyrings
will automatically resize if necessary.  It is used mostly for testing.

=item entries()

In a scalar context, returns the number of entries in the keyring.  In an
array context, returns a list of keyring entries as WebAuth::KeyringEntry
objects.

=item remove(INDEX)

Removes the INDEX entry in the keyring.  The keyring will then be
compacted, so all subsequent entries in the keyring will have their index
decreased by one.  If you are removing multiple entries from a keyring,
you should therefore remove them from the end of the keyring (the highest
INDEX number) first.

=item write_file(FILE)

Writes the keyring out to FILE in the format suitable for later reading by
read_file().

=back

=head2 WebAuth::KeyringEntry

This object is only used as the return value from the entries() method of
WebAuth::Keyring.  It's a read-only object that has the following methods:

=head3 Instance Methods

=over 4

=item creation()

Returns the creation time of the key in seconds since epoch.

=item key()

Returns the key of this entry.  This will be an opaque object that can be
passed into other WebAuth module functions that take a key.

=item valid_after()

Returns the valid after time of the key in seconds since epoch.

=back

=head1 CONSTANTS

The following constants from webauth.h are available:

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

  WA_KEY_AES
  WA_AES_128
  WA_AES_192
  WA_AES_256

  WA_TK_APP_STATE
  WA_TK_COMMAND
  WA_TK_CRED_DATA
  WA_TK_CRED_SERVICE
  WA_TK_CRED_TYPE
  WA_TK_CREATION_TIME
  WA_TK_ERROR_CODE
  WA_TK_ERROR_MESSAGE
  WA_TK_EXPIRATION_TIME
  WA_TK_INITIAL_FACTORS
  WA_TK_SESSION_KEY
  WA_TK_LOA
  WA_TK_LASTUSED_TIME
  WA_TK_OTP
  WA_TK_PASSWORD
  WA_TK_PROXY_DATA
  WA_TK_PROXY_SUBJECT
  WA_TK_PROXY_TYPE
  WA_TK_REQUEST_OPTIONS
  WA_TK_REQUESTED_TOKEN_TYPE
  WA_TK_RETURN_URL
  WA_TK_SUBJECT
  WA_TK_SUBJECT_AUTH
  WA_TK_SUBJECT_AUTH_DATA
  WA_TK_SESSION_FACTORS
  WA_TK_TOKEN_TYPE
  WA_TK_USERNAME
  WA_TK_WEBKDC_TOKEN

=head1 AUTHOR

Roland Schemers, Jon Robertson <jonrober@stanford.edu>, and Russ Allbery
<rra@stanford.edu>.

=cut
