#!/usr/bin/perl
#
# Miscellaneous token tests
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents create_keyring getcreds default_weblogin);

use WebKDC::Config ();
use WebLogin;
use Template;
use CGI;

use File::Path qw (rmtree);
use Test::More tests => 2;

# Force a defined order on output.
$| = 1;

my $weblogin = default_weblogin();

mkdir ('./t/tmp');

#############################################################################
# add_*_token tests
#############################################################################

$ENV{REMOTE_USER} = 'testuser@testrealm.org';
$WebKDC::Config::REMUSER_EXPIRES  = 60 * 10;
$WebKDC::Config::KEYRING_PATH     = 't/data/test.keyring';
@WebKDC::Config::REMUSER_PERMITTED_REALMS
    = ('testrealm.org', 'win.testrealm.org');
create_keyring ($WebKDC::Config::KEYRING_PATH);

$WebKDC::Config::WEBKDC_PRINCIPAL = contents ('t/data/test.principal')
    if -f 't/data/test.principal';

# Get a cache for the given principal.
my $oldcache = $ENV{KRB5CCNAME};
if (defined $WebKDC::Config::WEBKDC_PRINCIPAL) {
    $ENV{KRB5CCNAME} = 'krb5cc_test';
    getcreds ('t/data/test.keytab', $WebKDC::Config::WEBKDC_PRINCIPAL);
    $ENV{KRB5CCNAME} = $oldcache;
}

# FIXME: Only works when run on a WebKDC.  When fixed it should run like the
#        test after it does, with a skip for when the test.principal does
#        not exist.
#SKIP: {
my $query;
TODO: {
    todo_skip 'test currently only works on a WebKDC', 1;
    #skip 'kerberos test principal not set up', 1
    #    unless -f ('t/data/test.principal');

    # add_proxy_token
    $query = CGI->new ({});
    $weblogin = WebLogin->new (QUERY => $query);
    $weblogin->{webauth} = WebAuth->new;
    $ENV{KRB5CCNAME} = 'krb5cc_test';
    $weblogin->add_kerberos_proxy_token;
    $ENV{KRB5CCNAME} = $oldcache;
    my $token = $weblogin->{request}->proxy_cookie ('krb5');
    ok ($token, 'add_proxy_token works');
}

SKIP: {
    skip 'kerberos test principal not set up', 1
        unless -f ('t/data/test.principal');

    # add_remuser_token
    $query = CGI->new ({});
    $weblogin = WebLogin->new (QUERY => $query);
    $weblogin->cgiapp_prerun;
    $weblogin->add_remuser_token;
    my $token = $weblogin->{request}->proxy_cookie ('remuser');
    ok ($token, 'add_remuser_token works');
}

unlink ($WebKDC::Config::KEYRING_PATH, "$WebKDC::Config::KEYRING_PATH.lock");
unlink ('krb5cc_test');
rmtree ('./t/tmp');
