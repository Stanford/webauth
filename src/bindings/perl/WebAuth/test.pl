# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;

use Test;
use UNIVERSAL qw(isa);

# FIME: need a better way to test kerberos, might need to put
# in another test file. For now, comment/uncomment one or the other.
BEGIN { plan tests => 56 }
my $run_kerb = 0;

#BEGIN { plan tests => 76 }
#my $run_kerb = 1;

my ($kuser, $kpass, $kkeytab, $kservice, $khost, $krservice, $krhost);

if ($run_kerb) {
    # FIXME: need better way to config these
    # user/password to attempt to login as
    $kuser="schemers";
    $kpass="xxxxx";
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

my ($s, $c, $len, $output);

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

ok(WebAuth::base64_encode('hello'), 'aGVsbG8=');
ok(WebAuth::base64_decode('aGVsbG8='), 'hello');

ok(WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')),'\000\001\002');

ok(WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')), '\000\001\002');

# test some failure
ok(WebAuth::base64_decode('axc'), undef);

########################################  hex


ok(WebAuth::hex_encode("\000\001\002\003\004\005"), '000102030405');

ok(WebAuth::hex_decode('000102030405'), "\000\001\002\003\004\005");

ok(WebAuth::hex_encode('hello'), '68656c6c6f');
ok(WebAuth::hex_decode('68656c6c6f'), 'hello');

# test some failure
ok(WebAuth::hex_decode('FOOBAR'), undef);

######################################### attr tests

($s, $output) =WebAuth::attrs_encode({"x"=>"1"});
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq "x=1;");

($s, $output) =WebAuth::attrs_encode({"x"=>";"});
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq "x=;;;");

($s, $output) =WebAuth::attrs_encode({"x"=>"1;"});
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq "x=1;;;");

($s, $output) =WebAuth::attrs_encode({"x"=>"1", "y"=>"2"});
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq "x=1;y=2;");

($s, $output) =WebAuth::attrs_encode({"x"=>"\000", "y"=>"123"});
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq "x=\000;y=123;");

# try and encode, followed by a decode and compare the hashes
my $a = {"x"=> "1", "y"=> "hello", "z" => "goodbye"};

my $ea = "x=1;y=hello;z=goodbye;";

($s, $output) = WebAuth::attrs_encode($a);
ok($s, WebAuth::WA_ERR_NONE);
ok($output eq $ea);

($s, $b) = WebAuth::attrs_decode($ea);
ok($s, WebAuth::WA_ERR_NONE);
ok(compareHashes($a,$b), 1);

# some failures
($s, $b) = WebAuth::attrs_decode('x=1;y=23');
ok($s, WebAuth::WA_ERR_CORRUPT);
ok($b, undef);

($s, $b) = WebAuth::attrs_decode('x=1;zr');
ok($s, WebAuth::WA_ERR_CORRUPT);
ok($b, undef);

######################################## random

ok(length(WebAuth::random_bytes(16)), 16);
ok(length(WebAuth::random_bytes(1024)), 1024);

ok(length(WebAuth::random_key(WebAuth::WA_AES_128)), WebAuth::WA_AES_128);
ok(length(WebAuth::random_key(WebAuth::WA_AES_192)), WebAuth::WA_AES_192);
ok(length(WebAuth::random_key(WebAuth::WA_AES_256)), WebAuth::WA_AES_256);

######################################## keys

my $key = WebAuth::key_create(WebAuth::WA_AES_KEY,
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
my $attrs = { "a" => "1",  "b" => "hello", "c" => "world" };

my $ring = WebAuth::keyring_new(32);
ok(isa($ring, 'WEBAUTH_KEYRINGPtr'));
ok ($ring != undef);

my $curr=time();
$s = WebAuth::keyring_add($ring, $curr, $curr, $curr+3600, $key);
ok($s, WebAuth::WA_ERR_NONE);

$key = undef;
my $token;
($s, $token) = WebAuth::token_create($attrs, 0, $ring);

ok(length($token));
ok($s, WebAuth::WA_ERR_NONE);

my $attrs2 = undef;

($s, $attrs2) = WebAuth::token_parse($token, 0, $ring);

ok($s, WebAuth::WA_ERR_NONE);
ok(compareHashes($attrs, $attrs2), 1);


$key = WebAuth::key_create(WebAuth::WA_AES_KEY,
			   WebAuth::random_key(WebAuth::WA_AES_128));
$attrs = { "a" => "1",  "b" => "hello", "c" => "world" };

($s, $token) = WebAuth::token_create($attrs, 0, $key);

ok(length($token));
ok($s, WebAuth::WA_ERR_NONE);

$attrs2 = undef;
($s, $attrs2) = WebAuth::token_parse($token, 0, $key);

ok($s, WebAuth::WA_ERR_NONE);
ok(compareHashes($attrs, $attrs2), 1);



######################################### key rings

# FIXME: cleanup files, compare them, should probably use temp file names, etc.

# write key ring
$s = WebAuth::keyring_write_file($ring, "webauth_keyring");
ok($s, WebAuth::WA_ERR_NONE);

# read key ring
my $ring2;

($s, $ring2) = WebAuth::keyring_read_file("webauth_keyring");
ok(isa($ring2, 'WEBAUTH_KEYRINGPtr'));
ok($s, WebAuth::WA_ERR_NONE);

# write key ring2
$s = WebAuth::keyring_write_file($ring2, "webauth_keyring2");
ok($s, WebAuth::WA_ERR_NONE);

#print "attrs2($attrs) status($s)\n";



######################################## krb5

if ($run_kerb) {
    ($s, $c) = WebAuth::krb5_new();

    ok($s, WebAuth::WA_ERR_NONE);
    ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

    my $code = WebAuth::krb5_error_code($c);
    ok($code, 0);

    my $msg = WebAuth::krb5_error_message($c);
    ok($msg eq "success");

    my $ctx_princ;

    ($s, $ctx_princ) = WebAuth::krb5_get_principal($c);
    ok($s, WebAuth::WA_ERR_INVALID_CONTEXT);

    $s = WebAuth::krb5_init_via_password($c, $kuser, $kpass, $kkeytab);
    ok($s, WebAuth::WA_ERR_NONE);

    ($s, $ctx_princ) = WebAuth::krb5_get_principal($c);
    ok($s, WebAuth::WA_ERR_NONE);

    my ($tgt, $expiration);
    ($s, $tgt, $expiration) = WebAuth::krb5_export_tgt($c);
    ok($s, WebAuth::WA_ERR_NONE);

    my $princ;
    ($s, $princ) = WebAuth::krb5_service_principal($c, $kservice, $khost);
    ok($s, WebAuth::WA_ERR_NONE);

    my $ticket;
    ($s, $ticket, $expiration) = WebAuth::krb5_export_ticket($c, $princ);
    ok($s, WebAuth::WA_ERR_NONE);

    my $rprinc;
    ($s, $rprinc) = WebAuth::krb5_service_principal($c, $krservice, $krhost);
    ok($s, WebAuth::WA_ERR_NONE);

    my $request;
    ($s, $request) = WebAuth::krb5_mk_req($c, $rprinc);
    ok($s, WebAuth::WA_ERR_NONE);

    my $client_princ;
    ($s, $client_princ) = WebAuth::krb5_rd_req($c, $request, $kkeytab);
    ok($s, WebAuth::WA_ERR_NONE);
    #print "client = ($client_princ)\n";

    # nuke current context and import from tgt we created
    $c = undef;
    ($s, $c) = WebAuth::krb5_new();
    ok($s, WebAuth::WA_ERR_NONE);
    ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

    $s = WebAuth::krb5_init_via_tgt($c, $tgt);
    ok($s, WebAuth::WA_ERR_NONE);

    # import ticket we exported
    $s = WebAuth::krb5_import_ticket($c, $ticket);
    ok($s, WebAuth::WA_ERR_NONE);

    # nuke current context and get from keytab
    $c = undef;
    ($s, $c) = WebAuth::krb5_new();
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

    my $i;

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
