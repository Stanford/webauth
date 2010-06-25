#!/usr/bin/perl -w
#
# webauth.t - Test suite for miscellaneous WebAuth Perl bindings
#
# Written by Roland Schemers
# Rewritten by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2005, 2009, 2010
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;

use Test::More;

use lib ('t/lib', 'lib', 'blib/arch');
use WebAuth qw (:const);

BEGIN { plan tests => 38 }

# Do all tests in an eval block to catch otherwise-uncaught exceptions.
eval {
    sub compareHashes;
    my ($len, $output);

    # Hardcode a few constant tests
    is (WA_AES_128, 16, 'Check for constant WA_AES_128 works');
    is (WebAuth::WA_AES_192, 24, ' and WA_AES_192');
    is (WebAuth::WA_AES_256, 32, ' and WA_AES_256');
    is ('t', WebAuth::WA_TK_TOKEN_TYPE, ' and WA_TK_TOKEN_TYPE');

    # base64 tests
    is (WebAuth::base64_encode ('hello'), 'aGVsbG8=',
        'base64 encoding works');
    is (WebAuth::base64_decode ('aGVsbG8='), 'hello',
        ' as does decoding');
    is (WebAuth::base64_decode (WebAuth::base64_encode ('\000\001\002')),
        '\000\001\002', ' and encoding and decoding in turn');

    # Test failure by feeding a bad base64 string.
    eval {
        WebAuth::base64_decode ('axc');
    };
    ok ($@->isa ('WebAuth::Exception'), 'Decoding a bad base64 string fails');
    ok (WebAuth::Exception::match ($@, WA_ERR_CORRUPT),
        ' with corrupt string error');

    # Hex tests
    is (WebAuth::hex_encode ('\000\001\002\003\004\005'),
        '5c3030305c3030315c3030325c3030335c3030345c303035',
        'hex encoding a number works');
    is (WebAuth::hex_decode ('5c3030305c3030315c3030325c3030335c3030345c303035'),
        '\000\001\002\003\004\005', ' as is decoding');
    is (WebAuth::hex_encode ('hello'), '68656c6c6f',
        'hex encoding a string works');
    is (WebAuth::hex_decode ('68656c6c6f'), 'hello', ' as is decoding');

    # Hex failure by giving a bad Hex value.
    eval {
        WebAuth::hex_decode ('FOOBAR');
    };
    ok ($@->isa ('WebAuth::Exception'), 'hex decoding fails');
    ok (WebAuth::Exception::match ($@, WA_ERR_CORRUPT),
        ' of the correct type');

    # Attr tests
    is (WebAuth::attrs_encode ({'x' => '1' }), 'x=1;',
        'encoding an attr works');
    is (WebAuth::attrs_encode ({'x' => ';' }), 'x=;;;',
        ' and a more difficult attr');
    is (WebAuth::attrs_encode ({'x' => '1;'}), 'x=1;;;',
        ' and one more difficult still');

    # Try and encode attrs, followed by a decode and compare the hashes.
    my $a = {'x' => '1', 'y' => 'hello', 'z' => 'goodbye'};
    my $ea = 'x=1;y=hello;z=goodbye;';
    $b = WebAuth::attrs_decode ($ea);
    is (compareHashes ($a, $b), 1, ' and a multi-value hash');

    # Attr failures.
    eval {
        $b = WebAuth::attrs_decode ('x=1;y=23');
    };
    ok ($@->isa ('WebAuth::Exception'), 'decoding an invalid attr fails');
    is ($@->status (), WebAuth::WA_ERR_CORRUPT, ' with the right error');
    eval {
        $b = WebAuth::attrs_decode('x=1;zr');
    };
    ok ($@->isa ('WebAuth::Exception'), ' and another invalid attr fails');
    is ($@->status (), WebAuth::WA_ERR_CORRUPT,
        ' also with the right error');

    # Tests against random functions.
    is (length (WebAuth::random_bytes (16)), 16,
        'getting a short set of random bytes works');
    is (length (WebAuth::random_bytes (1024)), 1024, ' and a longer one');
    is (length (WebAuth::random_key (WebAuth::WA_AES_128)),
        WebAuth::WA_AES_128, ' and one for AES 128');
    is (length (WebAuth::random_key (WebAuth::WA_AES_192)),
        WebAuth::WA_AES_192, ' and one for AES 192');
    is (length (WebAuth::random_key (WebAuth::WA_AES_256)),
        WebAuth::WA_AES_256, ' and one for AES 256');

    # Key tests.
    my $key = WebAuth::key_create (WebAuth::WA_AES_KEY,
                                   WebAuth::random_key (WebAuth::WA_AES_128));
    ok (defined ($key), 'creating a key works');
    ok ($key->isa ('WEBAUTH_KEYPtr'), ' and is of the right type');

    # Invalid key material length
    eval {
        $key = WebAuth::key_create (WebAuth::WA_AES_KEY,
                                    WebAuth::random_key (2));
    };
    ok ($@->isa ('WebAuth::Exception'),
        ' and creating one of invalid length fails');

    # Token tests
    $key = WebAuth::key_create (WebAuth::WA_AES_KEY,
                                WebAuth::random_key (WebAuth::WA_AES_128));
    my $attrs = { 'a' => '1', 'b' => 'hello', 'c' => 'world' };
    my $ring = WebAuth::keyring_new (32);
    ok (defined ($ring), 'creating a token works');
    ok ($ring->isa ('WEBAUTH_KEYRINGPtr'), ' and is of the right type');

    my $curr = time();
    WebAuth::keyring_add ($ring, $curr, $curr, $key);

    $key = undef;
    my $token = WebAuth::token_create ($attrs, 0, $ring);
    isnt (length ($token), 0, 'creating a token works');

    my $attrs2 = WebAuth::token_parse ($token, 0, $ring);
    is (compareHashes ($attrs, $attrs2), 1, ' as does parsing the token');

    $key = WebAuth::key_create (WebAuth::WA_AES_KEY,
                                WebAuth::random_key (WebAuth::WA_AES_128));
    $attrs = { 'a' => '1', 'b' => 'hello', 'c' => 'world' };

    $token = WebAuth::token_create ($attrs, 0, $key);
    isnt (length ($token), 0, 'creating a token with complex attrs works');

    $attrs2 = WebAuth::token_parse ($token, 0, $key);
    is (compareHashes ($attrs, $attrs2), 1, ' as does parsing the token');

    # Test reading a new keyring file.
    # FIXME: compare files, should probably use temp file names, etc.
    WebAuth::keyring_write_file ($ring, 'webauth_keyring');
    my $ring2 = WebAuth::keyring_read_file ('webauth_keyring');
    ok ($ring2->isa ('WEBAUTH_KEYRINGPtr'), 'reading a new keyring works');
    WebAuth::keyring_write_file ($ring2, 'webauth_keyring2');

    unlink ('webauth_keyring') if -f 'webauth_keyring';
    unlink ('webauth_keyring2') if -f 'webauth_keyring2';
};
if ($@ and $@->isa ('WebAuth::Exception')) {
    die $@;
}

# A short hash comparison function in order to verify that hash output is as
# expected.
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

    # Compare keys
    for ($i=0; $i < $an; $i++) {
	if ($akeys[$i] ne $bkeys[$i]) {
	    return 0;
	}
    }

    # Compare values
    foreach $key (@akeys) {
	if ($$a{$key} ne $$b{$key}) {
	    return 0;
	}
    }
    return 1;
}
