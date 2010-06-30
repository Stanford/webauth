#!/usr/bin/perl -w
#
# Tests for proper handling of the pwexpire remctl checks.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib ('t/lib', 'lib', 'blib/arch');
use Util qw (contents remctld_spawn remctld_stop getcreds);

use WebKDC::Config ();
use WebKDC::WebResponse;
use HTML::Template;
use CGI;

use Test::More;

# We need remctld and Net::Remctl.
my $no_remctl = 0;
my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
$no_remctl = 1 unless $remctld;
eval { require Net::Remctl };
$no_remctl = 1 if $@;

# Also, other modules that we need for the remctl tests.
eval { require Date::Parse };
$no_remctl = 1 if $@;
eval { require Time::Duration };
$no_remctl = 1 if $@;

# Now try loading WebLogin, with the expiring password remctl server set if
# the remctl checks succeeded.
$WebKDC::Config::EXPIRING_PW_SERVER = 'localhost' unless $no_remctl;
require WebLogin;

# Check for a valid kerberos config.
if (! -f 't/data/test.principal') {
    plan skip_all => 'no kerberos configuration found';
} elsif ($no_remctl) {
    plan skip_all => 'Net::Remctl not available';
} else {
    plan tests => 3;
}

# Set up a query with some test data.
my $query = CGI->new;

# Fake a weblogin object.
my $weblogin = {};
bless $weblogin, 'WebLogin';
$weblogin->{query} = $query;

# Set a few things for remctl.
$WebKDC::Config::EXPIRING_PW_SERVER = 'localhost';
$WebKDC::Config::EXPIRING_PW_PORT   = 14373;
my $principal = contents ('t/data/test.principal');
unlink ('krb5cc_test', 'test-acl');
open (ACL, '>', 'test-acl') or die "cannot create test-acl: $!\n";
print ACL "$principal\n";
close ACL;

# Now spawn our remctld server and get a ticket cache.
remctld_spawn ($remctld, $principal, 't/data/test.keytab',
               't/data/kadmin.conf');
my $oldcache = $ENV{KRB5CCNAME};
$ENV{KRB5CCNAME} = 'krb5cc_test';
getcreds ('t/data/test.keytab', $principal);
$ENV{KRB5CCNAME} = $oldcache;
$WebKDC::Config::EXPIRING_PW_TGT = 'krb5cc_test';
$WebKDC::Config::EXPIRING_PW_PRINC = $principal;

$weblogin->{query}->param ('username', 'testuser1');
my $expiration = WebLogin::time_to_pwexpire ($weblogin);
ok ($expiration =~ /^\d+$/, 'got response for user with expiration time');

$weblogin->{query}->param ('username', 'testuser3');
$expiration = WebLogin::time_to_pwexpire ($weblogin);
is ($expiration, undef, 'got response for user with no expiration time');

$WebKDC::Config::EXPIRING_PW_SERVER = '';
$weblogin->{query}->param ('username', 'testuser3');
$expiration = WebLogin::time_to_pwexpire ($weblogin);
is ($expiration, undef, 'skipped check without a remctl server');

remctld_stop;
unlink ('krb5cc_test', 'test-acl');
