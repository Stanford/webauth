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
  
  WebAuth::foobar();

=head1 DESCRIPTION

WebAuth is a low-level Perl interface into the WebAuth C API. 
Some functions have been made more Perl-like, though no attempt
has been made to create an object-oriented interface to the WebAuth library.
If such an inteface is needed, it will most likely be developed in Perl,
using these functions.

=head1 EXPORT

None

=head1 CONSTANTS

The following constants from webauth.h are available:

  WA_ERR_NO_ROOM
  WA_ERR_CORRUPT
  WA_ERR_NO_MEM
  WA_ERR_BAD_HMAC
  WA_ERR_RAND_FAILURE
  WA_ERR_NONE

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

=head1 FUNCTIONS

=over 4

=item base64_encoded_length(length)

$base64_len = base64_encoded_length($length)

Given data of the specified length, returns how long the resulting
base64-encoded data would be.

=item base64_decoded_length(input)

$len = base64_decoded_length($input)

Given the string $input, returns how long the resulting
base64-encoded data would be, or an WA_ERR_CORRUPT error. 
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

base64 encodes the $input string and returns the result. $status
is optional, and if present will get set to the result of the
webauth_base64_decode C function.

=back

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<perl>.

=cut
