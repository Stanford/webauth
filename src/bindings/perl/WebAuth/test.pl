# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;

use Test;
use UNIVERSAL qw(isa);

# FIME: need a better way to test kerberos, might need to put
# in another test file. For now, comment/uncomment one or the other.
BEGIN { plan tests => 42 }
my $run_kerb = 0;

#BEGIN { plan tests => 46 }
#my $run_kerb = 1;

my ($kuser, $kpass, $kkeytab, $kservice, $khost, $krservice, $krhost);

if ($run_kerb) {
    # FIXME: need better way to config these
    # user/password to attempt to login as
    $kuser="schemers/test";
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

# do it all in an eval block to catch uncaught exceptions

eval {

use WebAuth qw(:const);
ok(1); # If we made it this far, we're ok.

#use WebAuth::Exception;

sub compareHashes;

my ($len, $output);

#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

########################################
# hardcode a few constant tests
ok(WA_AES_128, 16);
ok(WebAuth::WA_AES_192, 24);
ok(WebAuth::WA_AES_256, 32);
ok("t" eq WebAuth::WA_TK_TOKEN_TYPE);

########################################  base64

ok(WebAuth::base64_encode('hello'), 'aGVsbG8=');
ok(WebAuth::base64_decode('aGVsbG8='), 'hello');

ok(WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')),'\000\001\002');

ok(WebAuth::base64_decode(WebAuth::base64_encode('\000\001\002')), '\000\001\002');

# test failure
eval {
    WebAuth::base64_decode('axc');
};

ok (isa($@, "WebAuth::Exception"));
ok (WebAuth::Exception::match($@, WA_ERR_CORRUPT));
ok (WebAuth::Exception::match($@));

########################################  hex


ok(WebAuth::hex_encode("\000\001\002\003\004\005"), '000102030405');

ok(WebAuth::hex_decode('000102030405'), "\000\001\002\003\004\005");

ok(WebAuth::hex_encode('hello'), '68656c6c6f');
ok(WebAuth::hex_decode('68656c6c6f'), 'hello');

# test some failure
eval {
    ok(WebAuth::hex_decode('FOOBAR'), undef);
};
ok (isa($@, "WebAuth::Exception"));
ok (WebAuth::Exception::match($@, WA_ERR_CORRUPT));
ok (WebAuth::Exception::match($@));

######################################### attr tests


ok(WebAuth::attrs_encode({"x"=>"1"}) eq "x=1;");
ok(WebAuth::attrs_encode({"x"=>";"}) eq "x=;;;");
ok(WebAuth::attrs_encode({"x"=>"1;"}) eq "x=1;;;");

#these are bogus unless we sort the hash table internally
#ok(WebAuth::attrs_encode({"x"=>"1", "y"=>"2"}) eq "x=1;y=2;");
#ok(WebAuth::attrs_encode({"x"=>"\000", "y"=>"123"}) eq "x=\000;y=123;");

# try and encode, followed by a decode and compare the hashes
my $a = {"x"=> "1", "y"=> "hello", "z" => "goodbye"};

my $ea = "x=1;y=hello;z=goodbye;";

#also bogus
#ok(WebAuth::attrs_encode($a) eq $ea);
$b = WebAuth::attrs_decode($ea);
ok(compareHashes($a,$b), 1);

# some failures
eval {
    $b = WebAuth::attrs_decode('x=1;y=23');
};
ok (isa($@, "WebAuth::Exception"));
ok($@->status(), WebAuth::WA_ERR_CORRUPT);

eval {
    $b = WebAuth::attrs_decode('x=1;zr');
};
ok (isa($@, "WebAuth::Exception"));
ok($@->status(), WebAuth::WA_ERR_CORRUPT);

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
eval {
    $key = WebAuth::key_create(WebAuth::WA_AES_KEY, WebAuth::random_key(2));
};
ok (isa($@, "WebAuth::Exception"));

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
WebAuth::keyring_add($ring, $curr, $curr, $curr+3600, $key);

$key = undef;
my $token = WebAuth::token_create($attrs, 0, $ring);

ok(length($token));

my $attrs2 = WebAuth::token_parse($token, 0, $ring);

ok(compareHashes($attrs, $attrs2), 1);


$key = WebAuth::key_create(WebAuth::WA_AES_KEY,
			   WebAuth::random_key(WebAuth::WA_AES_128));
$attrs = { "a" => "1",  "b" => "hello", "c" => "world" };

$token = WebAuth::token_create($attrs, 0, $key);

ok(length($token));

$attrs2 = WebAuth::token_parse($token, 0, $key);
ok(compareHashes($attrs, $attrs2), 1);


######################################### key rings

# FIXME: cleanup files, compare them, should probably use temp file names, etc.

# write key ring
WebAuth::keyring_write_file($ring, "webauth_keyring");

# read key ring
my $ring2 = WebAuth::keyring_read_file("webauth_keyring");
ok(isa($ring2, 'WEBAUTH_KEYRINGPtr'));

# write key ring2
WebAuth::keyring_write_file($ring2, "webauth_keyring2");

#print "attrs2($attrs) status($s)\n";

######################################## krb5

if ($run_kerb) {
    eval {
	my $c = WebAuth::krb5_new();

	ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

	#FIXME my $ctx_princ = WebAuth::krb5_get_principal($c);

	my $sp = WebAuth::krb5_init_via_password($c, $kuser, $kpass, $kkeytab);

	my $ctx_princ = WebAuth::krb5_get_principal($c, 1);
	my ($tgt, $expiration) = WebAuth::krb5_export_tgt($c);

	my $princ = WebAuth::krb5_service_principal($c, $kservice, $khost);

	my $ticket;

	($ticket, $expiration) = WebAuth::krb5_export_ticket($c, $princ);

	my $rprinc = WebAuth::krb5_service_principal($c, $krservice, $krhost);

	my $request = WebAuth::krb5_mk_req($c, $rprinc);

	my $client_princ = WebAuth::krb5_rd_req($c, $request, $kkeytab, 1);
	#print "client = ($client_princ)\n";

	# nuke current context and import from tgt we created
	$c = WebAuth::krb5_new();
	ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

	WebAuth::krb5_init_via_tgt($c, $tgt);

	# import ticket we exported
	WebAuth::krb5_import_ticket($c, $ticket);
	# nuke current context and get from keytab
	$c = WebAuth::krb5_new();
	ok(isa($c, 'WEBAUTH_KRB5_CTXTPtr'));

	WebAuth::krb5_init_via_keytab($c, $kkeytab);
    };
    ok (!isa($@, "WebAuth::Exception"));
    if (isa($@, "WebAuth::Exception")) {
	die $@;
    }
}

};
if (isa($@, "WebAuth::Exception")) {
    die $@;
}


sub compareHashes {
    my $a = shift;
    my $b = shift;

    my @akeys = sort keys %$a;
    my @bkeys = sort keys %$b;

    my $an = scalar @akeys;
    my $bn = scalar @bkeys;

    my ($i, $key);

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
