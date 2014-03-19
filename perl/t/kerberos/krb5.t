#!/usr/bin/perl -w
#
# Test suite for WebAuth Perl bindings for krb5 functions.
#
# Written by Roland Schemers
# Updated by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2005, 2009, 2010, 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;

use Test::More;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw(contents get_userinfo);

# Check for kerberos config all good.  Default is yes.
my $kerberos_config = 1;

my ($keytab, $principal, $wa_principal, $princ_type, $princ_host);
if (-f 't/data/test.keytab' && -f 't/data/test.principal'
    && -f 't/data/test.principal-webauth') {

    $keytab = 't/data/test.keytab';
    $principal = contents ('t/data/test.principal');
    $wa_principal = contents ('t/data/test.principal-webauth');
    ($princ_type, $princ_host) = split (/\//, $principal);
} else {
    $kerberos_config = 0;
}

# Get the username we need to change, and its current password.
my $fname_passwd = 't/data/test.password';
my ($username, $password) = get_userinfo ($fname_passwd) if -f $fname_passwd;
unless ($username && $password && $principal && $wa_principal) {
    $kerberos_config = 0;
}

# Skip all tests without a valid kerberos configuration.
if ($kerberos_config) {
    plan tests => 13;
} else {
    plan skip_all => 'Kerberos tests not configured';
}

# Test actually loading WebAuth module.
use WebAuth qw(:const);
ok (1, 'loading WebAuth works');
my $wa = WebAuth->new;

my ($context, $sp, $ctx_princ, $tgt, $expiration, $princ, $ticket, $rprinc,
    $request, $client_princ);

eval { $context = $wa->krb5_new };
isa_ok ($context, 'WebAuth::Krb5');

# We should now be able to drop the WebAuth context without destroying our
# Kerberos context, since the WebAuth::Krb5 object should hold a reference.
undef $wa;

eval {
    $sp = $context->init_via_password($username, $password, '', $keytab);
};
is ($@, '', "init_via_password didn't thrown an exception");
ok ($sp, 'init_via_password works');

eval { $ctx_princ = $context->get_principal (1) };
ok ($ctx_princ, 'get_principal works');

eval { ($tgt, $expiration) = $context->export_cred };
is ($@, '', 'export_cred works');
ok ($expiration, '... and returns an expiration time');

# If our user is in a realm other than our default realm, we can't use the
# results of service_principal by itself, since it's qualified with the wrong
# realm.
eval {
    ($ticket, $expiration)
        = $context->export_cred ($wa_principal);
};
is ($@, '', 'krb5_export_cred works');
ok ($ticket, '... and returns a ticket');
ok ($expiration, '... and an expiration time');

# Nuke current context and import from tgt we created.
eval {
    my $wa = WebAuth->new;
    $context = $wa->krb5_new;
    $context->import_cred ($tgt);
};
is ($@, '', 'import_cred from a tgt works');

# Import ticket we exported
eval { $context->import_cred ($ticket) };
is ($@, '', 'krb5_import_cred to import an exported ticket works');

# Nuke current context and get from keytab
$wa = WebAuth->new;
eval {
    $context = $wa->krb5_new;
    $context->init_via_keytab ($keytab);
};
is ($@, '', 'init_via_keytab to get context from a keytab works');
