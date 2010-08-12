#!/usr/bin/perl -w
#
# Miscellaneous tests for WebLogin code.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents create_keyring getcreds);

use WebKDC::Config ();
use WebLogin;
use HTML::Template;
use CGI;

use Test::More tests => 36;

# Force a defined order on output.
$| = 1;

# Load a version of the page templates that just prints out the vars sent.
my %pages = (confirm  => 'confirm.tmpl',
             pwchange => 'pwchange.tmpl',
             error    => 'error.tmpl',
            );
%pages = map {
    $_    => HTML::Template->new (filename => $pages{$_},
    cache => 1,
    path  => 't/data/templates')
} keys %pages;

# Set up a query with some test data.
$ENV{REQUEST_METHOD} = 'GET';
my $query = CGI->new;

# Fake a weblogin object.
my $weblogin = {};
bless $weblogin, 'WebLogin';
$weblogin->{query} = $query;
$weblogin->{pages} = \%pages;
$weblogin->{response} = new WebKDC::WebResponse;
$weblogin->{request} = new WebKDC::WebRequest;
$weblogin->{request}->request_token ('TestReqToken');
$weblogin->{request}->service_token ('TestServiceToken');
$weblogin->{test_cookie} = $WebLogin::TEST_COOKIE;

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

# test_password_no_post
# FIXME: Doesn't actually work because we can't set $query->request_method
#        with the CGI module.  We'll have to do something more tricky to
#        fake a request, and can worry about that later.  skip these tests,
#        but leave in to use when that's fixed.
my ($page, $retval);
SKIP: {
    skip 'test_password_no_post tests do not yet work', 3;

    $weblogin->{query}->param ('password', 'abc');
    $weblogin->{query}->request_method ('POST');
    $retval = WebLogin::test_password_no_post ($weblogin);
    is ($retval, 1, 'Password with POST works');
    $weblogin->{query}->param ('password', '');
    $weblogin->{query}->request_method ('GET');
    $retval = WebLogin::test_password_no_post ($weblogin);
    is ($retval, 1, ' and no password with GET works');

    $weblogin->{query}->param ('password', 'abc');
    $weblogin->{query}->request_method ('GET');
    open (PAGE, '>', \$page) or die "could not open string for writing";
    select PAGE;
    $retval = WebLogin::test_password_no_post ($weblogin);
    select STDOUT;
    close PAGE;
    is ($retval, 0, ' and password with GET fails');
}

# test_cookies tests
# FIXME: Can't easily set a cookie already in the CGI object, so we can't
#        yet test the positive case
SKIP: {
    skip 'test_cookies existing cookie test does not yet work', 1;

    # test_cookies tests - cookie is set
    $weblogin->{query} = new CGI;
    $weblogin->{test_cookie} = 'testcookie';
    $weblogin->{query}->cookie (-name => $weblogin->{test_cookie},
                                -value => 1);
    $retval = WebLogin::test_cookies ($weblogin);
    is ($retval, 1, 'test_cookies with cookie set works');
}

# test_cookies after the page has redirected to check for cookies, but
# without the cookie successfully set.  Not testing the code that adjusts
# for old templates.
$weblogin->{query} = new CGI;
$weblogin->{query}->param ('test_cookie', 1);
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_cookies ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, 'test_cookies fails with cookies disabled');
like ($page, qr/err_cookies_disabled 1/, ' with the correct error message');

# test_cookie without a cookie set, but without the param showing we've
# already redirected to find a cookie.
$ENV{REQUEST_METHOD} = 'GET';
$weblogin->{query} = new CGI;
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_cookies ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and redirects when not yet having tried to get cookie');
ok ($page =~ /Status: 302 Moved/, ' with the correct error message');

# test_request_token success
$weblogin->{query} = new CGI;
$weblogin->{query}->param ('RT', 'TestRT');
$weblogin->{query}->param ('ST', 'TestST');
$retval = WebLogin::test_request_token ($weblogin);
is ($retval, 1, 'test_request_token with RT and ST works');

# test_request_token without RT and ST
$weblogin->{query} = new CGI;
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_request_token ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and fails with both unset');

# test_request_token with only RT
$weblogin->{query} = new CGI;
$weblogin->{query}->param ('RT', 'TestRT');
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_request_token ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and fails with only RT set');

# test_request_token with only ST
$weblogin->{query} = new CGI;
$weblogin->{query}->param ('ST', 'TestST');
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_request_token ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and fails with only ST set');

# test_pwchange_fields without a username
$ENV{REQUEST_METHOD} = 'POST';
$weblogin->{query} = new CGI;
$weblogin->{query}->param ('username', '');
$weblogin->{query}->param ('expired', 0);
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, 'test_pwchange without username fails');
ok ($page =~ /err_username 1/, ' with the correct error');

# test_pwchange_fields without a password
$weblogin->{query}->param ('username', 'testuser');
$weblogin->{query}->param ('password', '');
$weblogin->{CPT} = '';
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and test_pwchange without CPT or password fails');
ok ($page =~ /err_password 1/, ' with the correct error');

# test_pwchange_fields without either new password field
$weblogin->{query}->param ('password', 'abc');
$weblogin->{CPT} = 'TestCPT';
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0, ' and test_pwchange without either new password field fails');
ok ($page =~ /err_newpassword 1/, ' with the correct error');

# test_pwchange_fields with only first new password field
$weblogin->{query}->param ('new_passwd1', 'abc');
$weblogin->{CPT} = 'TestCPT';
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0,
    ' and test_pwchange with only first new password field fails');
ok ($page =~ /err_newpassword 1/, ' with the correct error');

# test_pwchange_fields with only second new password field
$weblogin->{query}->param ('new_passwd1', '');
$weblogin->{query}->param ('new_passwd2', 'abc');
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0,
    ' and test_pwchange with only second new password field fails');
ok ($page =~ /err_newpassword 1/, ' with the correct error');

# test_pwchange_fields with new password fields not matching
$weblogin->{query}->param ('new_passwd1', 'abc');
$weblogin->{query}->param ('new_passwd2', 'xyz');
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 0,
    ' and test_pwchange with new password fields not matching fails');
ok ($page =~ /err_newpassword_match 1/, ' with the correct error');

# test_pwchange_fields with everything good
$weblogin->{query}->param ('new_passwd1', 'abc');
$weblogin->{query}->param ('new_passwd2', 'abc');
open (PAGE, '>', \$page) or die "could not open string for writing";
select PAGE;
$retval = WebLogin::test_pwchange_fields ($weblogin);
select STDOUT;
close PAGE;
is ($retval, 1, ' and test_pwchange with all fields correct works');

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
    $query = new CGI;
    $weblogin = WebLogin->new ($query, \%pages);
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
    $query = new CGI;
    $weblogin = WebLogin->new ($query, \%pages);
    $weblogin->add_remuser_token;
    my $token = $weblogin->{request}->proxy_cookie ('remuser');
    ok ($token, 'add_remuser_token works');
}

unlink ($WebKDC::Config::KEYRING_PATH);
unlink ('krb5cc_test');
