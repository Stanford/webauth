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

package WebAuth::Exception;

use strict;
use warnings;

use WebAuth;

use overload '""' => \&to_string;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

#sub new {
#    my ($type, $detail, $s, $kc) = @_;
#    my $self = {};
#    bless $self, $type;
#    $self->{'status'} = $s;
#    $self->{'detail'} = $detail;
#    if (defined($kc) && $s == WebAuth::WA_ERR_KRB5) {
#	$self->{'krb5_ec'} = WebAuth::krb5_error_message($kc);
#	$self->{'krb5_em'} = WebAuth::krb5_error_code($kc);
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
    my $s = $self->{'status'};
    my $line = $self->{'line'};
    my $file = $self->{'file'};
    my $msg = WebAuth::error_message($s);
    my $detail = $self->{'detail'};
    if (defined($detail)) {
	$msg = "$detail: $msg";
    }
    if ($s == &WebAuth::WA_ERR_KRB5) {
	my $kec = $self->{'krb5_ec'};
	my $kem = $self->{'krb5_em'};
	$msg .= ": $kem ($kec)";
    }
    if (defined($line)) {
	$msg .= " at $file line $line";
    }
    return $msg;
}

sub to_string {
    my ($self) = @_;
    return $self->error_message();
}

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

All functions have the potential to croak with WebAuth::Exception object.

=head1 EXPORT

None

=head1 FUNCTIONS

=over 4

=item error_message(status)

$message = error_message($status)

Returns an error message for the specified status.

=item base64_encode(input);

$output = base64_encode($input);

base64 encodes the $input string and returns the result.

=item base64_decode(input)

 $output = base64_decode($input);

base64 decodes the $input string and returns the result in $output,
or undef if unable to parse $input.

=item hex_encode(input);

$output = hex_encode($input);

hex encodes the $input string and returns the result.

=item hex_decode(input)

 $output = hex_decode($input);

hex decodes the $input string and returns the result in $output,
or undef if unable to decode $input.

=item attrs_encode(attrs);

 $output = attrs_encode($attrs);

Takes as input $attrs (which must be a reference to a hash) and returns
a string of the encoded attributes in $output.  The values in the $attrs
hash table get converted to strings if they aren't already.

=item attrs_decode(input);

 $attrs = attrs_decode($input);

attr decodes the $input string and returns the result in $attrs as 
a reference to a hash, or croaks in case of an error.

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

 $key = key_create($type, $key_material);

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

 keyring_add($ring, $c, $vf, $vt, $key);

Adds a key to the keyring. creation_time and valid_from can both be
0, in which case the current time is used. key is copied internally, and
can be undef'd after calling this function.

=item keyring_write_file(ring, path)

 keyring_write_file($ring, $path);

Writes a key ring to a file.

=item keyring_read_file(path)

 $ring = keyring_read_file($path);

Reads a keyring from a file and returns it in $ring on success.

=item token_create(attrs, hint, key_or_ring)

  $token = token_create($attrs, $hint, $key_or_ring);

Takes as input $attrs (which must be a reference to a hash) and 
$key_or_ring (created with keyring_new or key_create) and returns 
the encrypted token. If hint is 0, the current time will be used.

The values in the $attrs hash table get converted to strings if they 
aren't already.

=item token_parse(token, ttl, key_or_ring)

  $attrs = token_parse($token, $ttl, $key_or_ring);

Takes as input an encrypted token and a key_or_ring (created with 
keyring_new or key_create) and returns the attributes.

=item krb5_new()

  $context = krb5_new();

Creates a new WEBAUTH_KRB5_CTXT reference in $context.

=item krb5_keep_cred_cache(context)

  krb5_keep_cred_cache($context);

If called before $context is no longer in use, prevents the credential
cache (created via one of the calls to krb5_init_via*) from being 
destroyed. This should only be used you need to keep a file-based
credential cache from being removed.

=item krb5_init_via_password(context, user, password, keytab[, cache])

   krb5_init_via_password($context, $user, 
                              $password, $keytab[, $cache]);

Initializes a context using the specified username/password to obtain
a TGT. The TGT will be verified using the principal in the keytab by
doing a krb5_mk_req/krb5_rd_req. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_init_via_keytab(context, keytab[, cache])

   krb5_init_via_keytab($context, $keytab[, $cache]);

Initializes a context using the principal in the specified keytab
by getting a TGT. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_init_via_tgt(context, tgt[, cache])

   krb5_init_via_keytab($context, $tgt[, $cache]);

Initializes a context using a TGT that was previously exported using
krb5_export_tgt. If $cache is not specified, a memory
cache will be used and destroyed when the context is destroyed.

=item krb5_export_tgt(context)

  ($tgt, $expiration) = krb5_export_tgt($context)

Used to "export" a TGT from the specified context, which should have
been initialized via one of the krb5_init_via_* functions. On
success both  $tgt and $expiration get set. $ticket is the ticket
itself (binary data) and $expiration is the expiration time of the ticket.

=item krb5_import_ticket(context, ticket)

  krb5_import_ticket($context, $ticket);

Used to "import" a ticket that was created with krb5_export_ticket.

=item krb5_export_ticket(context, principal);

  ($ticket, $expiration) = krb5_export_ticket($context, $principal);

Used to "export" a ticket for the requested server principal. On success,
both $ticket and $expiration will be set. $ticket is the ticket itself
(binary data) and $expiration is the expiration time of the ticket.

=item krb5_service_principal(context, service, hostname)

    $principal = krb5_service_principal($context, $service, $hostname);

Used to construct a server principal for use with other calls such as
krb5_mk_req and krb5_export_ticket. On success $principal will be set
to the constructed principal, represented as a string.

=item krb5_get_principal(context)

    $principal = krb5_getprincipal($context);

Used to get the principal associated with the context. Should only be
called after a successful call to krb5_init_via*.

=item krb5_mk_req(context, principal)

    $request = krb5_mk_req($context, $principal);

Used to construct a kerberos V5 request for the specified principal. $request
will be set on success, and will contain the result of the krb5_mk_req call.

=item krb5_rd_req(context, request, keytab)

    $principal = krb5_rd_req($context, $request, $keytab);

Used to read a request created with krb5_mk_req. On success $principal
will be set to the client principal in the request.

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
  WA_TK_REQ_TOKEN
  WA_TK_REQ_TOKEN_EXPIRAITON
  WA_TK_REQ_TOKEN_TYPE
  WA_TK_RETURN_URL
  WA_TK_SUBJECT
  WA_TK_SUBJECT_AUTH
  WA_TK_SUBJECT_AUTH_DATA
  WA_TK_TOKEN_TYPE

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<perl>.

=cut
