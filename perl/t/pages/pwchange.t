#!/usr/bin/perl
#
# Tests for output and warnings for password change page
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010-2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');

use WebLogin;
use CGI;
use Template;

use File::Path qw (rmtree);
use Test::More tests => 57;

mkdir ('./t/tmp');

# Load a version of the page templates that just prints out the vars sent.
my %PAGES = (pwchange => 'pwchange.tmpl');
$WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
$WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

# Set up a query with some test data.
my $query = CGI->new;
$query->param ('username', 'testuser');
$query->param ('expired', 1);

# Fake a weblogin object.
my $weblogin = {};
bless $weblogin, 'WebLogin';
$weblogin->query ($query);
$weblogin->param ('pages', \%PAGES);
$weblogin->param ('test_cookie', $WebLogin::TEST_COOKIE);
$weblogin->tt_include_path (['t/data/templates']);

# Move stdout to a string so we can check the page output.
my $page = WebLogin::print_pwchange_page ($weblogin, 'TestRT', 'TestST');
my @output = split (/[\r\n]+/, $$page);

# Check to make sure the page printed as we expected.
ok ($page, 'pwchange page was printed');
is ($output[0], 'error ', '... and error was not set');
is ($output[1], 'err_username ', '... and err_username was not set');
is ($output[2], 'err_password ', '... and err_password was not set');
is ($output[3], 'err_newpassword ', '... and err_newpassword was not set');
is ($output[4], 'err_newpassword_match ',
    '... and err_newpassword_match was not set');
is ($output[5], 'err_loginfailed ', '... and err_loginfailed was not set');
is ($output[6], 'err_rejected ', '... and err_rejected was not set');
is ($output[7], 'err_pwweak ', '... and err_pwweak was not set');
is ($output[8], 'err_pwchange ', '... and err_pwchange was not set');
is ($output[9], 'err_msg ', '... and err_msg was not set');
is ($output[10], 'RT TestRT', '... and RT was set');
is ($output[11], 'ST TestST', '... and ST was set');
is ($output[12], 'CPT ', '... and CPT was not set');
is ($output[13], 'username testuser', '... and username was set');
is ($output[14], 'password ', '... and password was not set');
is ($output[15], 'new_passwd1 ', '... and new_passwd1 was not set');
is ($output[16], 'new_passwd2 ', '... and new_passwd2 was not set');
is ($output[17], 'changepw ', '... and changepw was not set');
is ($output[18], 'expired 1', '... and expired was set');
is ($output[19], 'skip_username ', '... and skip_username was not set');
is ($output[20], 'skip_password ', '... and skip_password was not set');

# Once more, testing CPT suppressing the username and password.
$weblogin->param ('CPT', 'TestCPT');
$page = WebLogin::print_pwchange_page ($weblogin, 'TestRT2', 'TestST2');
@output = split (/[\r\n]+/, $$page);
ok ($page, 'pwchange page was printed with CPT');
is ($output[0], 'error ', '... and error was not set');
is ($output[1], 'err_username ', '... and err_username was not set');
is ($output[2], 'err_password ', '... and err_password was not set');
is ($output[3], 'err_newpassword ', '... and err_newpassword was not set');
is ($output[4], 'err_newpassword_match ',
    '... and err_newpassword_match was not set');
is ($output[5], 'err_loginfailed ', '... and err_loginfailed was not set');
is ($output[6], 'err_rejected ', '... and err_rejected was not set');
is ($output[7], 'err_pwweak ', '... and err_pwweak was not set');
is ($output[8], 'err_pwchange ', '... and err_pwchange was not set');
is ($output[9], 'err_msg ', '... and err_msg was not set');
is ($output[10], 'RT TestRT2', '... and RT was set');
is ($output[11], 'ST TestST2', '... and ST was set');
is ($output[12], 'CPT TestCPT', '... and CPT was set');
is ($output[13], 'username testuser', '... and username was set');
is ($output[14], 'password ', '... and password was not set');
is ($output[15], 'new_passwd1 ', '... and new_passwd1 was not set');
is ($output[16], 'new_passwd2 ', '... and new_passwd2 was not set');
is ($output[17], 'changepw ', '... and changepw was not set');
is ($output[18], 'expired 1', '... and expired was set');
is ($output[19], 'skip_username 1', '... and skip_username was set');
is ($output[20], 'skip_password 1', '... and skip_password was set');

# Now various attempts at making the password change page error check go off.
# error_invalid_pwchange_fields without a username
$ENV{REQUEST_METHOD} = 'POST';
$query = CGI->new ({ });
$query->param ('username', '');
$query->param ('expired', 0);
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), 'test_pwchange without username fails');
ok ($$page =~ /err_username 1/, '... with the correct error');

# error_invalid_pwchange_fields without a password
$query->param ('username', 'testuser');
$query->param ('password', '');
$weblogin->param ('CPT', '');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), '... and test_pwchange without CPT or password fails');
ok ($$page =~ /err_password 1/, '... with the correct error');

# error_invalid_pwchange_fields without either new password field
$query->param ('password', 'abc');
$weblogin->param ('CPT', 'TestCPT');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page), '... and test_pwchange without either new password field fails');
ok ($$page =~ /err_newpassword 1/, '... with the correct error');

# error_invalid_pwchange_fields with only first new password field
$query->param ('new_passwd1', 'abc');
$weblogin->param ('CPT', 'TestCPT');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    '... and test_pwchange with only first new password field fails');
ok ($$page =~ /err_newpassword 1/, '... with the correct error');

# error_invalid_pwchange_fields with only second new password field
$query->param ('new_passwd1', '');
$query->param ('new_passwd2', 'abc');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    '... and test_pwchange with only second new password field fails');
ok ($$page =~ /err_newpassword 1/, '... with the correct error');

# error_invalid_pwchange_fields with new password fields not matching
$query->param ('new_passwd1', 'abc');
$query->param ('new_passwd2', 'xyz');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
ok (defined ($page),
    '... and test_pwchange with new password fields not matching fails');
ok ($$page =~ /err_newpassword_match 1/, '... with the correct error');

# error_invalid_pwchange_fields with everything good
$query->param ('new_passwd1', 'abc');
$query->param ('new_passwd2', 'abc');
$weblogin->query ($query);
$page = WebLogin::error_invalid_pwchange_fields ($weblogin);
is ($page, undef, '... and test_pwchange with all fields correct works');


rmtree ('./t/tmp');
