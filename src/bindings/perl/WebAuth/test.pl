# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
use UNIVERSAL qw(isa);

# FIME: need a better way to test kerberos, might need to put
# in another test file. For now, comment/uncomment one or the other.
BEGIN { plan tests => 73 }
$run_kerb = 0;

#BEGIN { plan tests => 91 }
#$run_kerb = 1;

if ($run_kerb) {
    # FIXME: need better way to config these
    # user/password to attempt to login as
    $kuser="schemers";
    $kpass="secret";
    # path to keytab file used to verify tgt and also 
    # used krb5_init_via_keytab and rd_req
    $kkeytab="keytab";
    # service/host to do a krb5_export_ticket only
    $kservice="host";
    $khost="shred.stanford.edu";
    # service/host to use with krb5_mk_req, should be same
    # as the one in the keytab
    $krservice="host";
    $krhost="lichen.stanford.edu";
}

use WebAuth;
ok(1); # If we made it this far, we're ok.

sub compareHashes;


#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

########################################
# hardcode a few constant tests
ok(WebAuth::WA_AES_128, 16);
ok(WebAuth::WA_AES_192, 24);
ok(WebAuth::WA_AES_256, 32);
ok("an" eq WebAuth::WA_TK_APP_NAME);

########################################  base64

ok(WebAuth::base64_encoded_length(1), 4);
ok(WebAuth::base64_encoded_length(2), 4);
ok(WebAuth::base64_encoded_length(3), 4);
ok(WebAuth::base64_encoded_length(4), 8);
ok(WebAuth::base64_encoded_length(5), 8);
ok(WebAuth::base64_encoded_length(6), 8);
ok(WebAuth::base64_encoded_length(7), 12);
ok(WebAuth::base64_encoded_length(8), 12);
ok(WebAuth::base64_encoded_length(9), 12);

ok(WebAuth::base64_decoded_length(WebAuth::base64_encode('1')), 1);
ok(WebAuth::base64_decoded_length(WebAuth::base64_encode('12')), 2);
ok(WebAuth::base64_decoded_length(WebAuth::base64_encode('123')), 3);
ok(WebAuth::base64_decoded_length(WebAuth::base64_encode('1234')), 4);


ok(WebAuth::base64_encode('hello'), 'aGVsbG8=');
ok(WebAuth::base64_decode('aGVsbG8='), 'hello');
ok(WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')), '\000\001\002');

# test some failures

$len = WebAuth::base64_decoded_length('x', $status);
ok($status, WebAuth::WA_ERR_CORRUPT);

ok(WebAuth::base64_decode('axc', $status), undef);
ok($status, WebAuth::WA_ERR_CORRUPT);

########################################  hex

# basic hex lenth tests
ok(WebAuth::hex_encoded_length(1), 2);
ok(WebAuth::hex_encoded_length(3), 6);
ok(WebAuth::hex_encoded_length(5), 10);

ok(WebAuth::hex_decoded_length(2), 1);
ok(WebAuth::hex_decoded_length(6), 3);
ok(WebAuth::hex_decoded_length(10), 5);

ok(WebAuth::hex_encode("\000\001\002\003\004\005"), '000102030405');
ok(WebAuth::hex_decode('000102030405'), "\000\001\002\003\004\005");

ok(WebAuth::hex_encode('hello'), '68656c6c6f');
ok(WebAuth::hex_decode('68656c6c6f'), 'hello');

# test some failures

$len = WebAuth::hex_decoded_length(3, $status);
ok( $status, WebAuth::WA_ERR_CORRUPT);

$status = undef;
ok(WebAuth::hex_decode('FOOBAR', $status), undef);
ok($status, WebAuth::WA_ERR_CORRUPT);

######################################### attr tests

ok(WebAuth::attrs_encoded_length({"x"=>"1"}), 4);
ok(WebAuth::attrs_encoded_length({"x"=>";"}), 5);
ok(WebAuth::attrs_encoded_length({"x"=>"1;"}), 6);
ok(WebAuth::attrs_encoded_length({"x"=>"1", "y"=>"2"}), 8);
ok(WebAuth::attrs_encoded_length({"x"=>"\000", "y"=>"123"}), 10);

ok(WebAuth::attrs_encode({"x"=>"1"}), "x=1;");
ok(WebAuth::attrs_encode({"x"=>";"}), "x=;;;");
ok(WebAuth::attrs_encode({"x"=>"1;"}), "x=1;;;");
ok(WebAuth::attrs_encode({"x"=>"1", "y"=>"2"}), "x=1;y=2;");
ok(WebAuth::attrs_encode({"x"=>"\000", "y"=>"123"}), "x=\000;y=123;");

# try and encode, followed by a decode and compare the hashes
$a = {"x"=> "1", "y"=> "hello", "z" => "goodbye"};

$ea = "x=1;y=hello;z=goodbye;";
ok(WebAuth::attrs_encode($a), $ea);

$status = undef;
$b = WebAuth::attrs_decode($ea, $status);
ok($status, WebAuth::WA_ERR_NONE);
ok(compareHashes($a,$b), 1);

# some failures
$status = undef;
ok(WebAuth::attrs_decode('x=1;y=23', $status), undef);
ok($status, WebAuth::WA_ERR_CORRUPT);

$status = undef;
ok(WebAuth::attrs_decode('x=1;zr', $status), undef);
ok($status, WebAuth::WA_ERR_CORRUPT);

######################################## random

ok(length(WebAuth::random_bytes(16)), 16);
ok(length(WebAuth::random_bytes(1024)), 1024);

ok(length(WebAuth::random_key(WebAuth::WA_AES_128)), WebAuth::WA_AES_128);
ok(length(WebAuth::random_key(WebAuth::WA_AES_192)), WebAuth::WA_AES_192);
ok(length(WebAuth::random_key(WebAuth::WA_AES_256)), WebAuth::WA_AES_256);

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
ok($s, WebAuth::WA_ERR_NONE);

$key = undef;
$status = undef;
$token = WebAuth::token_create($attrs, 0, $ring, $status);

ok(length($token));
ok($status, WebAuth::WA_ERR_NONE);

$status = undef;
$attrs2 = WebAuth::token_parse($token, $ring, $status);

ok($status, WebAuth::WA_ERR_NONE);
ok(compareHashes($attrs, $attrs), 1);

# FIXME: cleanup files, compare them, should probably use temp file names, etc.

# write key ring
$status = WebAuth::keyring_write_file($ring, "webauth_keyring");
ok($status, WebAuth::WA_ERR_NONE);

# read key ring
$status = undef;
$ring2 = WebAuth::keyring_read_file("webauth_keyring", $status);
ok(isa($ring2, 'WEBAUTH_KEYRINGPtr'));
ok($status, WebAuth::WA_ERR_NONE);

# write key ring2
$status = WebAuth::keyring_write_file($ring2, "webauth_keyring2");
ok($status, WebAuth::WA_ERR_NONE);

#print "attrs2($attrs) status($status)\n";



######################################## krb5

if ($run_kerb) {
    $s = WebAuth::krb5_new($c);

    ok($s, WebAuth::WA_ERR_NONE);
    ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

    $code = WebAuth::krb5_error_code($c);
    ok($code, 0);

    $msg = WebAuth::krb5_error_message($c);
    ok($msg eq "success");

    $s = WebAuth::krb5_init_via_password($c, $kuser, $kpass, $kkeytab);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_export_tgt($c, $tgt, $expiration);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_service_principal($c, $kservice, $khost, $princ);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_export_ticket($c, $princ, $ticket, $expiration);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_service_principal($c, $krservice, $krhost, $rprinc);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_mk_req($c, $rprinc, $request);
    ok($s, WebAuth::WA_ERR_NONE);

    $s = WebAuth::krb5_rd_req($c, $request, $kkeytab, $client_princ);
    ok($s, WebAuth::WA_ERR_NONE);
    #print "client = ($client_princ)\n";

    # nuke current context and import from tgt we created
    $c = undef;
    $s = WebAuth::krb5_new($c);
    ok($s, WebAuth::WA_ERR_NONE);
    ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

    $s = WebAuth::krb5_init_via_tgt($c, $tgt);
    ok($s, WebAuth::WA_ERR_NONE);

    # import ticket we exported
    $s = WebAuth::krb5_import_ticket($c, $ticket);
    ok($s, WebAuth::WA_ERR_NONE);

    # nuke current context and get from keytab
    $c = undef;
    $s = WebAuth::krb5_new($c);
    ok($s, WebAuth::WA_ERR_NONE);
    ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

    $s = WebAuth::krb5_init_via_keytab($c, $kkeytab);
    ok($s, WebAuth::WA_ERR_NONE);
}

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
