#!/usr/bin/perl -w
#
# Miscellaneous tests for WebLogin code.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents create_keyring getcreds);

use WebKDC::Config ();
use WebLogin;
use Template;
use CGI;

use File::Path qw (rmtree);
use Test::More tests => 36;

# Force a defined order on output.
$| = 1;

mkdir ('./t/tmp');

# Load a version of the page templates that just prints out the vars sent.
my %PAGES = (confirm  => 'confirm.tmpl',
             pwchange => 'pwchange.tmpl',
             error    => 'error.tmpl',
            );

# Set up a query with some test data.
$ENV{REQUEST_METHOD} = 'GET';
my $query = CGI->new;

# Fake a weblogin object.
my $weblogin = {};
bless $weblogin, 'WebLogin';
$weblogin->query ($query);
my $resp = new WebKDC::WebResponse;
my $req = new WebKDC::WebRequest;
$req->request_token ('TestReqToken');
$req->service_token ('TestServiceToken');
$weblogin->{response} = $resp;
$weblogin->{request} = $req;
$weblogin->param ('test_cookie', $WebLogin::TEST_COOKIE);
$weblogin->param ('pages', \%PAGES);

# Load some default template options.
$weblogin->tt_config(
                     TEMPLATE_OPTIONS => {
                         STAT_TTL     => 60,
                         COMPILE_DIR  => 't/tmp/ttc',
                         COMPILE_EXT  => '.ttc',
                         INCLUDE_PATH => 't/data/templates',
                     },
                    );

#############################################################################
# token_rights tests
#############################################################################

# Test token_rights with invalid requests.
$WebKDC::Config::TOKEN_ACL = '';
$weblogin->{response}->requester_subject ('webauth/test1.testrealm.org@testrealm.org');
my $rights = WebLogin::token_rights ($weblogin);
ok (!@{$rights}, 'token_rights fails with no TOKEN_ACL file');
$WebKDC::Config::TOKEN_ACL = 't/data/token.acl';
$weblogin->{response}->requester_subject ('nothing');
$rights = WebLogin::token_rights ($weblogin);
ok (!@{$rights}, ' and when given an invalid requester_subject');
$weblogin->{response}->requester_subject ('webauth/*@testrealm.org');
$rights = WebLogin::token_rights ($weblogin);
ok (!@{$rights}, ' and when given a request for a non-cred token');

# And with a request for a known server.
$weblogin->{response}->requester_subject ('webauth/test1.testrealm.org@testrealm.org');
$rights = WebLogin::token_rights ($weblogin);
ok ($rights, 'token_rights gets a response with a valid TOKEN_ACL');
is (${$rights}[0]{'principal'}, 'afs', ' and principal is correct');
is (${$rights}[0]{'realm'}, undef, ' and realm is correct');
is (${$rights}[0]{'name'}, 'afs/testrealm.org', ' and name is correct');
is (${$rights}[0]{'type'}, 'krb5', ' and type is correct');
is (${$rights}[0]{'instance'}, 'testrealm.org', ' and instance is correct');

#############################################################################
# test_* function tests
#############################################################################

# error_password_no_post
# FIXME: Doesn't actually work because we can't set $query->request_method
#        with the CGI module.  We'll have to do something more tricky to
#        fake a request, and can worry about that later.  skip these tests,
#        but leave in to use when that's fixed.
my ($page, $retval);
SKIP: {
    skip 'error_password_no_post tests do not yet work', 3;

    $query = CGI->new;
    $query->param ('password', 'abc');
    $query->request_method ('POST');
    $weblogin->query ($query);
    $retval = WebLogin::error_password_no_post ($weblogin);
    is ($retval, 1, 'Password with POST works');
    $query->param ('password', '');
    $query->request_method ('GET');
    $weblogin->query ($query);
    $retval = WebLogin::error_password_no_post ($weblogin);
    is ($retval, 1, ' and no password with GET works');

    $query->param ('password', 'abc');
    $query->request_method ('GET');
    $weblogin->query ($query);
    $page = WebLogin::error_password_no_post ($weblogin);
    ok (defined ($page), ' and password with GET fails');
}

# error_if_no_cookies tests
# FIXME: Can't easily set a cookie already in the CGI object, so we can't
#        yet test the positive case
SKIP: {
    skip 'error_if_no_cookies existing cookie test does not yet work', 1;

    # error_if_no_cookies tests - cookie is set
    $weblogin->param ('test_cookie', 'testcookie');
    $query = CGI->new;
    $query->cookie (-name  => $weblogin->param ('test_cookie'),
                    -value => 1);
    $weblogin->query ($query);
    $page = WebLogin::error_if_no_cookies ($weblogin);
    is ($page, undef, 'error_if_no_cookies with cookie set works');
}

# error_if_no_cookies after the page has redirected to check for cookies, but
# without the cookie successfully set.  Not testing the code that adjusts
# for old templates.
$query = CGI->new;
$query->param ('test_cookie', 1);
$weblogin->query ($query);
$page = WebLogin::error_if_no_cookies ($weblogin);
ok (defined ($page), 'error_if_no_cookies fails with cookies disabled');
like ($$page, qr/err_cookies_disabled 1/, ' with the correct error message');

# test_cookie without a cookie set, but without the param showing we've
# already redirected to find a cookie.
# FIXME: Need to figure out this case, with headers-only for a redirect.
SKIP: {
    skip 'headers do not yet work right', 2;
    $ENV{REQUEST_METHOD} = 'GET';
    $query = CGI->new;
    $weblogin->query ($query);
    $page = WebLogin::error_if_no_cookies ($weblogin);
    ok (defined ($page), ' and redirects when not yet having tried to get cookie');
    ok ($$page =~ /Status: 302 Moved/, ' with the correct error message');
}

# error_no_request_token success
$query = CGI->new;
$query->param ('RT', 'TestRT');
$query->param ('ST', 'TestST');
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
is ($page, undef, 'error_no_request_token with RT and ST works');

# error_no_request_token without RT and ST
$query = CGI->new;
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with both unset');

# error_no_request_token with only RT
$query = CGI->new;
$query->param ('RT', 'TestRT');
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with only RT set');

# error_no_request_token with only ST
$query = CGI->new;
$query->param ('ST', 'TestST');
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with only ST set');

# error_invalid_pwchange_fields without a username
$ENV{REQUEST_METHOD} = 'POST';
$query = CGI->new ({ });
$query->param ('username', '');
$query->param ('expired', 0);
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), 'test_pwchange without username fails');
ok ($$page =~ /err_username 1/, ' with the correct error');

# error_invalid_pwchange_fields without a password
$query->param ('username', 'testuser');
$query->param ('password', '');
$weblogin->param ('CPT', '');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), ' and test_pwchange without CPT or password fails');
ok ($$page =~ /err_password 1/, ' with the correct error');

# error_invalid_pwchange_fields without either new password field
$query->param ('password', 'abc');
$weblogin->param ('CPT', 'TestCPT');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), ' and test_pwchange without either new password field fails');
ok ($$page =~ /err_newpassword 1/, ' with the correct error');

# error_invalid_pwchange_fields with only first new password field
$query->param ('new_passwd1', 'abc');
$weblogin->param ('CPT', 'TestCPT');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    ' and test_pwchange with only first new password field fails');
ok ($$page =~ /err_newpassword 1/, ' with the correct error');

# error_invalid_pwchange_fields with only second new password field
$query->param ('new_passwd1', '');
$query->param ('new_passwd2', 'abc');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    ' and test_pwchange with only second new password field fails');
ok ($$page =~ /err_newpassword 1/, ' with the correct error');

# error_invalid_pwchange_fields with new password fields not matching
$query->param ('new_passwd1', 'abc');
$query->param ('new_passwd2', 'xyz');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    ' and test_pwchange with new password fields not matching fails');
ok ($$page =~ /err_newpassword_match 1/, ' with the correct error');

# error_invalid_pwchange_fields with everything good
$query->param ('new_passwd1', 'abc');
$query->param ('new_passwd2', 'abc');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
is ($page, undef, ' and test_pwchange with all fields correct works');

#############################################################################
# add_*_token tests
#############################################################################

$ENV{REMOTE_USER} = 'testuser@testrealm.org';
$WebKDC::Config::REMUSER_EXPIRES  = 60 * 10;
@WebKDC::Config::REMUSER_REALMS   = ('testrealm.org', 'win.testrealm.org');
$WebKDC::Config::KEYRING_PATH     = 't/data/test.keyring';
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
TODO: {
    todo_skip 'test currently only works on a WebKDC', 1;
    #skip 'kerberos test principal not set up', 1
    #    unless -f ('t/data/test.principal');

    # add_proxy_token
    $query = CGI->new;
    $weblogin = WebLogin->new;
    $weblogin->query ($query);
    $ENV{KRB5CCNAME} = 'krb5cc_test';
    $weblogin->add_proxy_token;
    $ENV{KRB5CCNAME} = $oldcache;
    my $token = $weblogin->{request}->proxy_cookie ('krb5');
    ok ($token, 'add_proxy_token works');
}

SKIP: {
    skip 'kerberos test principal not set up', 1
        unless -f ('t/data/test.principal');

    # add_remuser_token
    $query = CGI->new ({ });
    $weblogin = WebLogin->new;
    $weblogin->query ($query);
    $weblogin->add_remuser_token;
    my $token = $weblogin->{request}->proxy_cookie ('remuser');
    ok ($token, 'add_remuser_token works');
}

unlink ($WebKDC::Config::KEYRING_PATH);
unlink ('krb5cc_test');
rmtree ('./t/tmp');
