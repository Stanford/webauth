# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 34 };
use WebAuth;
ok(1); # If we made it this far, we're ok.

#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

########################################
# hardcode a few constant tests
ok(16, WebAuth::WA_AES_128);
ok(24, WebAuth::WA_AES_192);
ok(32, WebAuth::WA_AES_256);
ok("an" eq WebAuth::WA_TK_APP_NAME);

########################################  base64

ok(4, WebAuth::base64_encoded_length(1));
ok(4, WebAuth::base64_encoded_length(2));
ok(4, WebAuth::base64_encoded_length(3));
ok(8, WebAuth::base64_encoded_length(4));
ok(8, WebAuth::base64_encoded_length(5));
ok(8, WebAuth::base64_encoded_length(6));
ok(12, WebAuth::base64_encoded_length(7));
ok(12, WebAuth::base64_encoded_length(8));
ok(12, WebAuth::base64_encoded_length(9));

ok(1, WebAuth::base64_decoded_length(WebAuth::base64_encode('1')));
ok(2, WebAuth::base64_decoded_length(WebAuth::base64_encode('12')));
ok(3, WebAuth::base64_decoded_length(WebAuth::base64_encode('123')));
ok(4, WebAuth::base64_decoded_length(WebAuth::base64_encode('1234')));


ok('aGVsbG8=', WebAuth::base64_encode('hello'));
ok('hello', WebAuth::base64_decode('aGVsbG8='));
ok('\000\001\002', 
   WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')));

# test some failures

ok(WebAuth::WA_ERR_CORRUPT, WebAuth::base64_decoded_length('x'));

ok(undef, WebAuth::base64_decode('axc', $status));
ok(WebAuth::WA_ERR_CORRUPT, $status);

########################################  hex

# basic hex lenth tests
ok(2, WebAuth::hex_encoded_length(1));
ok(6, WebAuth::hex_encoded_length(3));
ok(10, WebAuth::hex_encoded_length(5));

ok(1, WebAuth::hex_decoded_length(2));
ok(3, WebAuth::hex_decoded_length(6));
ok(5, WebAuth::hex_decoded_length(10));

ok('000102030405', WebAuth::hex_encode("\000\001\002\003\004\005"));
ok("\000\001\002\003\004\005", WebAuth::hex_decode('000102030405'));

ok('68656c6c6f', WebAuth::hex_encode('hello'));
ok('hello', WebAuth::hex_decode('68656c6c6f'));

#  $output = webauth_attrs_encode(%attrs, [, $status]);
#  %attrs = webauth_attrs_decode($data [, $status]);
#  $bytes = webauth_random_bytes($num_bytes [, $status]);
#  $key = webauth_random_key($key_len [, $status]);

# $wakey = webauth_key_create($key);
# need a destroy to zap mem?

# 

# $token = webauth_token_create(%attrs, $wakey [, $status]);

# %attrs = webauth_token_parse($token, $wakey [, $status]);
