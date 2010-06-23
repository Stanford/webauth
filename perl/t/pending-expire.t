#!/usr/bin/perl -w
#
# pending-expire.t - Tests for proper handling of the pwexpire remctl checks
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use lib 'lib';
use lib 't/lib';
use Util qw (contents remctld_spawn remctld_stop getcreds);

use WebKDC::WebResponse;
use WebLogin;
use HTML::Template;

use Test::More tests => 3;

# Set up a query with some test data.
my $query = CGI::Fast->new;

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

# We need remctld and Net::Remctl.
my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
skip 'remctld not found', 12 unless $remctld;
eval { require Net::Remctl };
skip 'Net::Remctl not available', 12 if $@;

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
