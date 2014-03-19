#!/usr/bin/perl
#
# Tests on WebLogin::token_rights
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
use Test::More tests => 9;

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
$weblogin->query($query);
my $resp = WebKDC::WebResponse->new;
my $req  = WebKDC::WebRequest->new;
$req->request_token('TestReqToken');
$req->service_token('TestServiceToken');
$weblogin->{response} = $resp;
$weblogin->{request} = $req;
$weblogin->param('pages', \%PAGES);
$weblogin->param('logging', 0);

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
ok (!@{$rights}, '... and when given an invalid requester_subject');
$weblogin->{response}->requester_subject ('webauth/*@testrealm.org');
$rights = WebLogin::token_rights ($weblogin);
ok (!@{$rights}, '... and when given a request for a non-cred token');

# And with a request for a known server.
$weblogin->{response}->requester_subject ('webauth/test1.testrealm.org@testrealm.org');
$rights = WebLogin::token_rights ($weblogin);
ok ($rights, 'token_rights gets a response with a valid TOKEN_ACL');
is (${$rights}[0]{'principal'}, 'afs', '... and principal is correct');
is (${$rights}[0]{'realm'}, undef, '... and realm is correct');
is (${$rights}[0]{'name'}, 'afs/testrealm.org', '... and name is correct');
is (${$rights}[0]{'type'}, 'krb5', '... and type is correct');
is (${$rights}[0]{'instance'}, 'testrealm.org', '... and instance is correct');

unlink ($WebKDC::Config::KEYRING_PATH, "$WebKDC::Config::KEYRING_PATH.lock");
unlink ('krb5cc_test');
rmtree ('./t/tmp');
