#!/usr/bin/perl -w
#
# Test the password change functions in WebLogin module.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (get_userinfo create_keyring);

use CGI;
use Template;

use WebAuth qw(:const);
use WebLogin;
use WebKDC ();
use WebKDC::Config ();

use Test::More;

# Obtain Kerberos credentials for a user to verify that a password change
# actually worked.  Takes the username and password.
sub verify_password {
    my ($username, $password) = @_;
    my $wa = WebAuth->new;
    my $krb5 = $wa->krb5_new;
    eval { $krb5->init_via_password ($username, $password) };
    return !$@;
}

# Whether we've found a valid kerberos config.
my $kerberos_config = 0;

# Get the username we need to change, and its current password.
my $fname_passwd = 't/data/test.password';
my ($username, $password) = get_userinfo ($fname_passwd) if -f $fname_passwd;
if ($username && $password) {
    $kerberos_config = 1;
}

if ($kerberos_config) {
    plan tests => 15;
} else {
    plan skip_all => 'Kerberos tests not configured';
}

# New password to try changing the user to.
# FIXME: Should we use apg to generate each time?  Adds a testing requirement.
my $newpassword = 'dujPifecvij3';

# Set up a query with some test data.
my $query = new CGI;
my $weblogin = new WebLogin;
$weblogin->cgiapp_prerun;
$weblogin->param ('logging', 0);

# Create the keyring to use.
$WebKDC::Config::KEYRING_PATH = 't/data/test.keyring';
create_keyring ($WebKDC::Config::KEYRING_PATH);

# If the username is fully qualified, set a default realm.
if ($username =~ /\@(\S+)/) {
    $WebKDC::Config::DEFAULT_REALM = $1;
}

# Test a successful password change.
$weblogin->query->param ('username', $username);
$weblogin->query->param ('password', $password);
$weblogin->query->param ('new_passwd1', $newpassword);
$weblogin->add_changepw_token;
my ($status, $error) = $weblogin->change_user_password;

# If this test is being run behind NAT, the Kerberos password change protocol
# may fail.  MIT returns "Incorrect net address" and Heimdal returns "Unable
# to reach any changepw server".  Detect those errors and skip the remaining
# tests that require talking to the server.
#
# It looks like the password is often changed despite the error reported to
# the client, so if this looks like what happened, also change the password
# back just in case.
SKIP: {
    if ($error &&
        ($error =~ /Incorrect net address/
         || $error =~ /Unable to reach any changepw server/)) {
        $weblogin->query->param ('password', $newpassword);
        $weblogin->query->param ('new_passwd1', $password);
        ($status, $error) = $weblogin->change_user_password;
        skip 'Password change fails (behind NAT?)', 13;
    }

    is ($status, WebKDC::WK_SUCCESS, 'changing the password works');
    is ($error, undef, '... with no error');
    ok (verify_password ($username, $newpassword),
        '... and password was changed');

    # And undo it.
    $weblogin->query->param ('password', $newpassword);
    $weblogin->query->param ('new_passwd1', $password);
    ($status, $error) = $weblogin->change_user_password;
    is ($status, WebKDC::WK_SUCCESS, '... as does changing it back');
    is ($error, undef, '... with no error');
    ok (verify_password ($username, $password),
        '... and password was changed');

    # Test going to change_user_password with password but not CPT (should
    # work)
    $weblogin->param ('CPT', '');
    $query = new CGI;
    $weblogin->query ($query);
    $weblogin->query->param ('username', $username);
    $weblogin->query->param ('password', $password);
    $weblogin->query->param ('new_passwd1', $newpassword);
    ($status, $error) = $weblogin->change_user_password;
    is ($status, WebKDC::WK_SUCCESS,
        'changing the password with old password but no CPT works');
    is ($error, undef, '... with no error');
    ok (verify_password ($username, $newpassword),
        '... and password was changed');

    # And undo it.
    $weblogin->query->param ('password', $newpassword);
    $weblogin->query->param ('new_passwd1', $password);
    ($status, $error) = $weblogin->change_user_password;
    is ($status, WebKDC::WK_SUCCESS, '... as does changing it back');
    is ($error, undef, '... with no error');
    ok (verify_password ($username, $password),
        '... and password was changed');

    # Test trying a simple password 'abc' (should not work)
    # FIXME: Test exact error code, not isn't.  Allow success or failure if
    # it's not strong enough password (and if success, change the password
    # back).
    $query = new CGI;
    $weblogin->query ($query);
    $weblogin->query->param ('username', $username);
    $weblogin->query->param ('password', $password);
    $weblogin->query->param ('new_passwd1', 'cat');
    $weblogin->add_changepw_token;
    ($status, $error) = $weblogin->change_user_password;
    isnt ($status, WebKDC::WK_SUCCESS,
          'changing the password to dictionary word fails');
}

# Test going to change_user_password no CPT or password (should not work).
$query = new CGI;
$weblogin->query ($query);
$weblogin->query->param ('username', $username);
$weblogin->query->param ('new_passwd1', $newpassword);
$weblogin->param ('CPT', '');
($status, $error) = $weblogin->change_user_password;
isnt ($status, WebKDC::WK_SUCCESS,
      'changing the password without password or CPT fails');

# Test creating CPT, then sending different username to change_user_password
# (should not work)
$query = new CGI;
$weblogin->query ($query);
$weblogin->query->param ('username', $username);
$weblogin->query->param ('password', $password);
$weblogin->query->param ('new_passwd1', $newpassword);
$weblogin->add_changepw_token;
$weblogin->query->param ('username', $username.'_doe');
($status, $error) = $weblogin->change_user_password;
isnt ($status, WebKDC::WK_SUCCESS, 'changing the password of a user fails');

# Clean up the keyring.
unlink ($WebKDC::Config::KEYRING_PATH);
