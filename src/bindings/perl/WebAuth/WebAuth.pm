package WebAuth;

use 5.006;
use strict;
use warnings;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use WebAuth ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
);
our $VERSION = '0.01';

bootstrap WebAuth $VERSION;

# Preloaded methods go here.

1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

WebAuth - Perl extension for WebAuth (version 3)

=head1 SYNOPSIS

  use WebAuth;
  
  $key = WebAuth::random_key(WebAuth::WA_AES_128);

=head1 DESCRIPTION

WebAuth is a low-level Perl interface into the WebAuth C API. 
Some functions have been made more Perl-like, though no attempt
has been made to create an object-oriented interface to the WebAuth library.

=head1 EXPORT

None

=head1 FUNCTIONS

=over 4

=item base64_encoded_length(length)

$base64_len = base64_encoded_length($length)

Given data of the specified length, returns how long the resulting
base64-encoded data would be.

=item base64_decoded_length(input[, status])

$len = base64_decoded_length($input[, $status])

Given the string $input, returns how long the resulting
base64-encoded data would be, or 0 in case of an error.
If $status is specified, then it is set to WA_ERR_NONE or 
WA_ERR_CORRUPT.
Note that this function doesn't actually attempt to ensure 
that $input contains a valid base64-encoded string, though 
it does a sanity check to make sure the length is greater
then 0 and a multiple of 4. Call base64_decode to actually attempt
to parse and decode $input.

=item base64_encode(input);

$output = base64_encode($input);

base64 encodes the $input string and returns the result.

=item base64_decode(input[, status);

 $output = base64_decode($input[, $status] );

base64 decodes the $input string and returns the result, or undef
in the case of an error. $status is optional, and if present will get
set to the result of the webauth_base64_decode C function. 

=item hex_encoded_length(length)

$hex_len = hex_encoded_length($length)

Given data of the specified length, returns how long the resulting
hex-encoded data would be.

=item hex_decoded_length(input[, status])

$len = hex_decoded_length($input[, $status])

Given the string $input, returns how long the resulting
hex-encoded data would be, or 0 in case of an error.
If $status is specified, it is set to WA_ERR_NONE or A_ERR_CORRUPT on error. 
Note that this function doesn't actually attempt to ensure 
that $input contains a valid hex-encoded string, though 
it does a sanity check to make sure the length is greater
then 0 and a multiple of 4. Call hex_decode to actually attempt
to parse and decode $input.

=item hex_encode(input);

$output = hex_encode($input);

hex encodes the $input string and returns the result.

=item hex_decode(input[, status);

 $output = hex_decode($input[, $status] );

hex decodes the $input string and returns the result, or undef in the
case of an error. $status is optional, and if present will get set to
the result of the webauth_hex_decode C function.

=item attrs_encoded_length(attrs)

$len = attrs_encoded_length($attrs)

Takes as input $attrs (which must be a reference to a hash) and returns
the resulting length of encoding the attributes into a string.

=item attrs_encode(attrs);

$output = attrs_encode($attrs);

Takes as input $attrs (which must be a reference to a hash) and returns
a string of the encoded attributes.  The values in the $attrs
hash table get converted to strings if they aren't already.

=item attrs_decode(input[, status);

 $attrs = attrs_decode($input[, $status] );

attr decodes the $input string and returns the result as reference to a
hash, or undef in the case of an error. $status is optional, and if 
present will get set to the result of the webauth_attrs_decode C function.

Note: $input will be modified. Pass in a copy if this in undesirable.

=item random_bytes(length)

 $bytes = random_bytes($length);

Returns the specified number of random bytes, or undef if
random data was unavailable. The returned data is suitable
for nonces, but not necessarily for keys. Use random_key to
generate a suitable random key.

=item random_key(length)

 $key_material = random_key($length);

Returns the specified number of random bytes, or undef if
random data was unavailable. The returned data is suitable
for use as a key. Use the constants WA_AES_128, WA_AES_192, and
WA_AES_256 to specify a 128 bit, 192 bit, or 256 bit AES key respectively.

=item key_create(type, key_material)

 $key = key_create_key($type, $key_material);

Creates a reference to a WEBAUTH_KEYPtr object, or undef
on error. $type must be WA_AES_KEY, and $key_material must 
be a string with a length of
WA_AES_128, WA_AES_192, or WA_AES_256 bytes. $key should be set
to undef when the key is no longer needed.

=item keyring_new(initial_capacity)

 $ring = keyring_new($initial_capacity);

Creates a reference to a WEBAUTH_KEYRINGPtr object, or undef
on error.

=item keyring_add(ring, creation_time, valid_from, valid_till, key)

 $status = keyring_add($ring, $c, $vf, $vt, $key);

Adds a key to the key ring. creation_time and valid_from can both be
0, in which case the current time is used. key is copied internally, and
can be undef'd after calling this function.

=item keyring_write_file(ring, path)

 $status = keyring_write_file($ring, $path);

Writes a key ring to a file. Returns WA_ERR_NONE on success.

=item keyring_read_file(path[, status])

 $ring = keyring_read_file($path[, $status]);

Reads a key ring from a file. Returns undef on error. $status is optional, 
and if  present will get set to the result of the webauth_keyring_read_file C 
function.

=item token_create(attrs, hint, ring[, status])

  $token = token_create($attrs, $hint, $ring[, $status])

Takes as input $attrs (which must be a reference to a hash) and a $ring
(created with keyring_new) and returns the basse64 encrypted token\,
or undef in the case of an error. If hint is 0, the current time will
be used.

The values in the $attrs hash table get converted to strings if they 
aren't already. $status is optional, and if present will get set to the
result of the webauth_token_create C function.

=item token_parse(token, ring[, status])

  $attrs = token_parse($token, $ring[, $status])

Takes as input a base64 encrypted token and a ring (created with 
keyring_new) and returns the attributes, or undef in the case of an error.
$status is optional, and if present will get set to the
result of the webauth_token_parse C function.

=item krb5_new(context)

  $status = krb5_new($context);

Creates a new WEBAUTH_KRB5_CTXT reference in $context, and returns
the webauth status code, which will be WA_ERR_NONE on success.

=item krb5_error_code(context)

  $krb5_error_code = krb5_error_code($context);

Returns the internal kerberos V5 error code from the previous call
using $context. If no error occured, the returned value will be zero.

=item krb5_error_message(context)

  $krb5_error_msg = krb5_error_message($context);

Returns the internal kerberos V5 error message from the previous call
using $context. If no error occured, the returned value will be "success".

=item krb5_keep_cred_cache(context)

  $status = krb5_keep_cred_cache($context);

If called before $context is no longer in use, prevents the credential
cache (created via one of the calls to krb5_init_via*) from being 
destroyed. This should only be used you need to keep a file-based
credential cache from being removed.

=item krb5_init_via_password(context, user, password, keytab[, cache])

  $status = krb5_init_via_password($context, $user, 
                                      $password, $keytab[, $cache]);

Initializes a context using the specified username/password to obtain
a TGT. The TGT will be verified using the principal in the keytab by
doing a krb5_mk_req/krb5_rd_req. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_init_via_keytab(context, keytab[, cache])

  $status = krb5_init_via_keytab($context, $keytab[, $cache]);

Initializes a context using the principal in the specified keytab
by getting a TGT. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_init_via_tgt(context, tgt[, cache])

  $status = krb5_init_via_keytab($context, $tgt[, $cache]);

Initializes a context using a TGT that was previously exported using
krb5_export_tgt. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_export_tgt(context, tgt, expiration)

  $status = krb5_export_tgt($context, $tgt, $expiration);

Used to "export" a TGT from the specified context, which should have
been initialized via one of the krb5_init_via_* functions. On
success both  $tgt and $expiration get set. $ticket is the ticket
itself (binary data) and $expiration is the expiration time of the ticket.

=item krb5_import_ticket(context, ticket)

  $status = krb5_import_ticket($context, $ticket);

Used to "import" a ticket that was created with krb5_export_ticket.

=item krb5_export_ticket(context, principal, ticket, expiration)

  $status = krb5_export_ticket($context, $principal, $ticket, $expiration);

Used to "export" a ticket for the requested server principal. On success,
both $ticket and $expiration will be set. $ticket is the ticket itself
(binary data) and $expiration is the expiration time of the ticket.

=item krb5_service_principal(context, service, hostname, principal)

    $status = krb5_service_principal($context, $service,
                                                  $hostname, $principal);

Used to construct a server principal for use with other calls such as
krb5_mk_req and krb5_export_ticket. On success $principal will be set
to the constructed principal, represented as a string.

=item krb5_mk_req(context, principal, request)

  $status = krb5_mk_req($context, $principal, $request)

Used to construct a kerberos V5 request for the specified principal. $request
will be set on success, and will contain the result of the krb5_mk_req call.

=item krb5_rd_req(context, request, keytab, principal);

  $status = krb5_rd_req($context, $request, $keytab, $principal);

Used to read a request created with krb5_mk_req. On success $principal
will be set to the client principal in the request.

=back

=head1 CONSTANTS

The following constants from webauth.h are available:

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
  WA_ERR_LOGIN_FAILED
  WA_ERR_NONE

  WA_AES_KEY
  WA_AES_128
  WA_AES_192
  WA_AES_256

  WA_TK_APP_NAME
  WA_TK_CRED_DATA
  WA_TK_CRED_TYPE
  WA_TK_CREATION_TIME
  WA_TK_ERROR_CODE
  WA_TK_ERROR_MESSAGE
  WA_TK_EXPIRATION_TIME
  WA_TK_INACTIVITY_TIMEOUT
  WA_TK_SESSION_KEY
  WA_TK_LASTUSED_TIME
  WA_TK_PROXY_TYPE
  WA_TK_PROXY_DATA
  WA_TK_PROXY_OWNER
  WA_TK_POST_URL
  WA_TK_REQUEST_REASON
  WA_TK_REQUESTED_TOKEN_TYPE
  WA_TK_REQUESTED_TOKEN_HASH
  WA_TK_RETURN_URL
  WA_TK_SUBJECT
  WA_TK_SUBJECT_AUTHENTICATOR
  WA_TK_SERVICE_AUTHENTICATOR_NAME
  WA_TK_TOKEN_TYPE
  WA_TK_TOKEN_VERSION

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<perl>.

=cut
