# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
use UNIVERSAL qw(isa);

BEGIN { plan tests => 73 };
use WebAuth;
ok(1); # If we made it this far, we're ok.

sub compareHashes;


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

$len = WebAuth::base64_decoded_length('x', $status);
ok(WebAuth::WA_ERR_CORRUPT,  $status);

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

# test some failures

$len = WebAuth::hex_decoded_length(3, $status);
ok(WebAuth::WA_ERR_CORRUPT,  $status);

$status = undef;
ok(undef, WebAuth::hex_decode('FOOBAR', $status));
ok(WebAuth::WA_ERR_CORRUPT, $status);

######################################### attr tests

ok(4, WebAuth::attrs_encoded_length({"x"=>"1"}));
ok(5, WebAuth::attrs_encoded_length({"x"=>";"}));
ok(6, WebAuth::attrs_encoded_length({"x"=>"1;"}));
ok(8, WebAuth::attrs_encoded_length({"x"=>"1", "y"=>"2"}));
ok(10, WebAuth::attrs_encoded_length({"x"=>"\000", "y"=>"123"}));

ok("x=1;", WebAuth::attrs_encode({"x"=>"1"}));
ok("x=;;;", WebAuth::attrs_encode({"x"=>";"}));
ok("x=1;;;", WebAuth::attrs_encode({"x"=>"1;"}));
ok("x=1;y=2;", WebAuth::attrs_encode({"x"=>"1", "y"=>"2"}));
ok("x=\000;y=123;", WebAuth::attrs_encode({"x"=>"\000", "y"=>"123"}));

# try and encode, followed by a decode and compare the hashes
$a = {"x"=> "1", "y"=> "hello", "z" => "goodbye"};

$ea = "x=1;y=hello;z=goodbye;";
ok($ea, WebAuth::attrs_encode($a));

$status = undef;
$b = WebAuth::attrs_decode($ea, $status);
ok(WebAuth::WA_ERR_NONE, $status);
ok(1, compareHashes($a,$b));

# some failures
$status = undef;
ok(undef, WebAuth::attrs_decode('x=1;y=23', $status));
ok(WebAuth::WA_ERR_CORRUPT, $status);

$status = undef;
ok(undef, WebAuth::attrs_decode('x=1;zr', $status));
ok(WebAuth::WA_ERR_CORRUPT, $status);

######################################## random

ok(16, length(WebAuth::random_bytes(16)));
ok(1024, length(WebAuth::random_bytes(1024)));

ok(WebAuth::WA_AES_128, length(WebAuth::random_key(WebAuth::WA_AES_128)));
ok(WebAuth::WA_AES_192, length(WebAuth::random_key(WebAuth::WA_AES_192)));
ok(WebAuth::WA_AES_256, length(WebAuth::random_key(WebAuth::WA_AES_256)));

######################################## keys

$key = WebAuth::key_create(WebAuth::WA_AES_KEY,
			   WebAuth::random_key(WebAuth::WA_AES_128));
ok(defined($key));
ok(isa($key, 'WEBAUTH_KEYPtr'));

# invalid key material length
$key = WebAuth::key_create(WebAuth::WA_AES_KEY, WebAuth::random_key(2));
ok(!defined($key));

# $ring = WebAuth::keyring_new($initial_capacity);
# WebAuth::keyring_add($ring, c, vf, vt, $key); # use webauth_key_copy internally
# WebAuth::

######################################## tokens

$key = WebAuth::key_create(WebAuth::WA_AES_KEY,
			   WebAuth::random_key(WebAuth::WA_AES_128));
$attrs = { "a" => "1",  "b" => "hello", "c" => "world" };

$ring = WebAuth::keyring_new(32);
ok(isa($ring, 'WEBAUTH_KEYRINGPtr'));
ok ($ring != undef);

$curr=time();
$s = WebAuth::keyring_add($ring, $curr, $curr, $curr+3600, $key);
ok(WebAuth::WA_ERR_NONE, $s);

$key = undef;
$status = undef;
$token = WebAuth::token_create($attrs, 0, $ring, $status);

ok(length($token));
ok(WebAuth::WA_ERR_NONE, $status);

$status = undef;
$attrs2 = WebAuth::token_parse($token, $ring, $status);

ok(WebAuth::WA_ERR_NONE, $status);
ok(1, compareHashes($attrs, $attrs));

# FIXME: cleanup files, compare them, should probably use temp file names, etc.

# write key ring
$status = WebAuth::keyring_write_file($ring, "webauth_keyring");
ok(WebAuth::WA_ERR_NONE, $status);

# read key ring
$status = undef;
$ring2 = WebAuth::keyring_read_file("webauth_keyring", $status);
ok(isa($ring2, 'WEBAUTH_KEYRINGPtr'));
ok(WebAuth::WA_ERR_NONE, $status);

# write key ring2
$status = WebAuth::keyring_write_file($ring2, "webauth_keyring2");
ok(WebAuth::WA_ERR_NONE, $status);

#print "attrs2($attrs) status($status)\n";

sub compareHashes {
    my $a = shift;
    my $b = shift;

    my @akeys = sort keys %$a;
    my @bkeys = sort keys %$b;

    my $an = scalar @akeys;
    my $bn = scalar @bkeys;

    if ($an != $bn) {
	return 0;
    }
    # compare keys
    for ($i=0; $i < $an; $i++) {
	if ($akeys[$i] ne $bkeys[$i]) {
	    return 0;
	}
    }

    # compare values
    foreach $key (@akeys) {
	if ($$a{$key} ne $$b{$key}) {
	    return 0;
	}
    }
    return 1;
}
