#!/usr/bin/perl -w
#
# Basic tests for WebKDC::WebResponse.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use Test::More tests => 63;

BEGIN {
    use_ok ('WebKDC::WebResponse');
}

# Test all the basic accessors to make sure they're sane.  This will need
# modification later if we ever do any sort of type checking on the values.
my $resp = WebKDC::WebResponse->new;
for my $method (qw(app_state authz_subject default_device default_factor
                   login_canceled_token requester_subject response_token
                   response_token_type return_url subject password_expiration
                   user_message)) {
    is ($resp->$method, undef, "$method starts undef");
    is ($resp->$method ('foo'), 'foo', '... and can be set to foo');
    is ($resp->$method, 'foo', '... and is now set to foo');
}

# The proxy cookie setting interface is more complex.
is ($resp->cookie ('krb5'), undef, 'Proxy cookie for krb5 is undef');
is ($resp->cookie ('krb5', 'foo'), 'foo', '... and can be set');
is ($resp->cookie ('krb5'), 'foo', '... and has the right value');
is ($resp->cookie ('remuser'), undef, '... and remuser is still undef');
my %test_cookie = (krb5 => { value      => 'foo',
                             expiration => 0});
is_deeply ($resp->cookies, \%test_cookie,
           'cookies returns the correct hash');

# Test the devices, factor, and login settings, which return arrays and which
# only append values, never remove them.
for my $method (qw(devices factor_configured factor_needed login_history)) {
    is ($resp->$method, undef, "$method starts undef");
    is_deeply ($resp->$method ('foo'), [ 'foo' ], '... and can take a value');
    is_deeply ($resp->$method ('bar', 'baz'), [ 'foo', 'bar', 'baz' ],
               '... and appends values');
    is_deeply ($resp->$method, [ 'foo', 'bar', 'baz' ],
               '... and returns all values');
}

# Test the permitted_authz interface, which accepts and returns a list of
# identities.
is ($resp->permitted_authz, 0, 'permitted_authz starts empty');
is_deeply ([ $resp->permitted_authz ('foo') ], [ 'foo' ],
           '... and can be set to foo');
is_deeply ([ $resp->permitted_authz ], [ 'foo' ],
           '... and is now set to foo');
is_deeply ([ $resp->permitted_authz ('bar', 'baz') ], [ 'bar', 'baz' ],
           '... and can be set to (bar, baz)');
is_deeply ([ $resp->permitted_authz ], [ 'bar', 'baz' ],
           '... and returns all values');
