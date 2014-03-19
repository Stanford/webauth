#!/usr/bin/perl
#
# Miscellaneous error tests that belong less to one specific page
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2012, 2013, 2014
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
use Test::More tests => 12;

# Force a defined order on output.
$| = 1;

mkdir ('./t/tmp');

# Load a version of the page templates that just prints out the vars sent.
my %PAGES = (confirm  => 'confirm.tmpl',
             pwchange => 'pwchange.tmpl',
             error    => 'error.tmpl',
            );
$WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
$WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

# Set up a query with some test data.
$ENV{REQUEST_METHOD} = 'GET';
my $query = CGI->new ({});

# Set up the testing WebLogin object.
my $weblogin = WebLogin->new;
$weblogin->query ($query);
my $resp = WebKDC::WebResponse->new;
my $req = WebKDC::WebRequest->new;
$req->request_token ('TestReqToken');
$req->service_token ('TestServiceToken');
$weblogin->{response} = $resp;
$weblogin->{request} = $req;
$weblogin->param('pages', \%PAGES);
$weblogin->param('logging', 0);

# error_no_request_token success
$query = CGI->new ({});
$query->param ('RT', 'TestRT');
$query->param ('ST', 'TestST');
$weblogin->query ($query);
my $page = WebLogin::error_no_request_token ($weblogin);
is ($page, undef, 'error_no_request_token with RT and ST works');

# error_no_request_token without RT and ST
$query = CGI->new ({});
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with both unset');

# error_no_request_token with only RT
$query = CGI->new ({});
$query->param ('RT', 'TestRT');
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with only RT set');

# error_no_request_token with only ST
$query = CGI->new ({});
$query->param ('ST', 'TestST');
$weblogin->query ($query);
$page = WebLogin::error_no_request_token ($weblogin);
ok (defined ($page), ' and fails with only ST set');

# error_password_no_post
# FIXME: Doesn't actually work because we can't set $query->request_method
#        with the CGI module.  We'll have to do something more tricky to
#        fake a request, and can worry about that later.  skip these tests,
#        but leave in to use when that's fixed.
my $retval;
SKIP: {
    skip 'error_password_no_post tests do not yet work', 3;

    $query = CGI->new ({});
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
    $query = CGI->new ({});
    $query->cookie (-name  => $weblogin->param ('test_cookie'),
                    -value => 1);
    $weblogin->query ($query);
    $page = WebLogin::error_if_no_cookies ($weblogin);
    is ($page, undef, 'error_if_no_cookies with cookie set works');
}

# error_if_no_cookies after the page has redirected to check for cookies, but
# without the cookie successfully set.  Not testing the code that adjusts
# for old templates.
$query = CGI->new ({});
$query->param ('test_cookie', 1);
$weblogin->query ($query);
$page = WebLogin::error_if_no_cookies ($weblogin);
ok (defined ($page), 'error_if_no_cookies fails with cookies disabled');
like ($$page, qr/err_cookies_disabled 1/, '... with the correct error message');

# test_cookie without a cookie set, but without the param showing we've
# already redirected to find a cookie.
# FIXME: Need to figure out this case, with headers-only for a redirect.
SKIP: {
    skip 'headers do not yet work right', 2;
    $ENV{REQUEST_METHOD} = 'GET';
    $query = CGI->new ({});
    $weblogin->query ($query);
    $page = WebLogin::error_if_no_cookies ($weblogin);
    ok (defined ($page),
        '... and redirects when not yet having tried to get cookie');
    ok ($$page =~ /Status: 302 Moved/, '... with the correct error message');
}

unlink ($WebKDC::Config::KEYRING_PATH, "$WebKDC::Config::KEYRING_PATH.lock");
unlink ('krb5cc_test');
rmtree ('./t/tmp');
