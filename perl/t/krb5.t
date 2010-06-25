#!/usr/bin/perl -w
#
# Test suite for WebAuth Perl bindings for krb5 functions
#
# Written by Roland Schemers
# Updated by Jon Robertson <jonrober@stanford.edu>
# Copyright 2002, 2003, 2005, 2009, 2010
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;

use Test::More;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw(contents get_userinfo);

# Check for kerberos config all good.  Default is yes.
my $kerberos_config = 1;

my ($keytab, $principal, $wa_principal, $princ_type, $princ_host,
    $wa_princ_type, $wa_princ_host);
if (-f 't/data/test.keytab' && -f 't/data/test.principal'
    && -f 't/data/test.principal-webauth') {

    $keytab = 't/data/test.keytab';
    $principal = contents ('t/data/test.principal');
    $wa_principal = contents ('t/data/test.principal-webauth');
    ($princ_type, $princ_host) = split (/\//, $principal);
    ($wa_princ_type, $wa_princ_host) = split (/\//, $wa_principal);
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
    plan tests => 11;
} else {
    plan skip_all => 'no kerberos configuration found';
}

# Test actually loading WebAuth module.
use WebAuth qw(:const);
ok (1, 'loading WebAuth works');

my ($context, $sp, $ctx_princ, $tgt, $expiration, $princ, $ticket, $rprinc,
    $request, $client_princ);

eval { $context = WebAuth::krb5_new () };
ok ($context->isa ('WEBAUTH_KRB5_CTXTPtr'), 'krb5_new works');

eval {
    $sp = WebAuth::krb5_init_via_password($context, $username, $password,
                                          '', $keytab, '');
};
print $@, "\n";
ok ($sp, 'krb5_init_via_password works');

eval { $ctx_princ = WebAuth::krb5_get_principal ($context, 1) };
ok ($ctx_princ, 'krb5_get_principal works');

eval { ($tgt, $expiration) = WebAuth::krb5_export_tgt ($context) };
ok (!$@, 'krb5_init_via_password works');
ok ($expiration, ' and returns an expiration time');

eval {
    $princ = WebAuth::krb5_service_principal ($context, $wa_princ_type,
                                              $wa_princ_host);
};
ok (!$@, 'krb5_service_principal works');

eval {
    ($ticket, $expiration) = WebAuth::krb5_export_ticket ($context, $princ);
};
ok (!$@, 'krb5_export_ticket works');

# Nuke current context and import from tgt we created
eval {
    $context = WebAuth::krb5_new ();
    WebAuth::krb5_init_via_cred ($context, $tgt);
};
ok (!$@, 'krb5_init_via_cred from a tgt works');

# Import ticket we exported
eval { WebAuth::krb5_import_cred ($context, $ticket) };
ok (!$@, 'krb5_import_cred to import an exported ticket works');

# Nuke current context and get from keytab
eval {
    $context = WebAuth::krb5_new ();
    WebAuth::krb5_init_via_keytab ($context, $keytab, '');
};
ok (!$@, 'krb5_init_via_keytab to get context from a keytab works');
