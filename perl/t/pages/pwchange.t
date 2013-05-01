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
use Util qw (init_weblogin read_outputfile index_wrapper);

use File::Path qw (rmtree);
use Test::More tests => 17;

#############################################################################
# Support functions
#############################################################################

# Wrapper around WebLogin::index to grab the page output into a string and
# return that output.  To make all the index runmode tests look cleaner.
sub page_wrapper {
    my ($weblogin, $rt, $st) = @_;
    my %output;

    my $page = $weblogin->print_pwchange_page ($rt, $st);
    for my $line (split (/[\r\n]+/, $$page)) {
        my ($key, $value) = split (m{\s+}, $line);
        $output{$key} = $value;
    }
    return %output;
}

#############################################################################
# Environment setup
#############################################################################

mkdir ('./t/tmp');

my $query;
my $user = 'testuser';
my $weblogin = init_weblogin ($user, '', 'TestST', 'TestRT');
$weblogin->query->param ('expired', 1);
$weblogin->param ('test_cookie', $WebLogin::TEST_COOKIE);

#############################################################################
# Testing
#############################################################################

# Test the basic pwchange page.
my %output = page_wrapper ($weblogin, 'TestRT', 'TestST');
my %check = read_outputfile ('t/data/pages/pwchange/bare');
ok (%output, 'pwchange was printed');
is_deeply (\%output, \%check, '... and the output matches what is expected');

# Once more, testing CPT suppressing the username and password, and adding a
# remember_login setting.
$weblogin->param ('CPT', 'TestCPT');
$weblogin->query->param ('remember_login', 'yes');
%output = page_wrapper ($weblogin, 'TestRT2', 'TestST2');
%check = read_outputfile ('t/data/pages/pwchange/cpt');
ok (%output, 'pwchange page was printed with CPT');
is_deeply (\%output, \%check, '... and the output matches what is expected');

# Now various attempts at making the password change page error check go off.
# error_invalid_pwchange_fields without a username
$ENV{REQUEST_METHOD} = 'POST';
$query = CGI->new ({ });
$query->param ('username', '');
$query->param ('expired', 0);
$weblogin->query ($query);
my $page = WebLogin::error_invalid_pwchange_fields ($weblogin);
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
