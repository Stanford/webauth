#!/usr/bin/perl -w
#
# Basic tests for WebKDC::WebRequest.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use Test::More tests => 50;

BEGIN {
    use_ok ('WebKDC::WebRequest');
}

# Test all the basic accessors to make sure they're sane.  This will need
# modification later if we ever do any sort of type checking on the values.
my $req = WebKDC::WebRequest->new;
for my $method (qw(authz_subject device_id local_ip_addr local_ip_port
                   remote_ip_addr remote_ip_port otp otp_type pass
                   remote_user request_token service_token factor_token
                   user)) {
    is ($req->$method, undef, "$method starts undef");
    is ($req->$method ('foo'), 'foo', '... and can be set to foo');
    is ($req->$method, 'foo', '... and is now set to foo');
}

# The proxy cookie setting interface is more complex.
is ($req->proxy_cookie ('krb5'), undef, 'Proxy cookie for krb5 is undef');
is_deeply ($req->proxy_cookie ('krb5', 'bleh', 'u'),
           { cookie => 'bleh', session_factor => 'u' },
           '... and setting krb5 works');
is_deeply ($req->proxy_cookie ('remuser', 'blah', 'k'),
           { cookie => 'blah', session_factor => 'k' },
           '... and setting remuser works');
my $cookies = $req->proxy_cookies;
is_deeply ($cookies, { krb5 => 'bleh', remuser => 'blah' },
           'proxy_cookies returns the stripped hash');
$cookies->{krb5} = 'foo';
is_deeply ($req->proxy_cookies, { krb5 => 'bleh', remuser => 'blah' },
           '... and that hash is a copy');
$cookies = { krb5    => { cookie => 'bar', session_factor => 'p' },
             remuser => { cookie => 'aba', session_factor => 'x1' } };
is ($req->proxy_cookies_rich ($cookies), $cookies,
    'Setting cookies with proxy_cookies_rich works');
is_deeply ($req->proxy_cookies_rich, $cookies,
           '... and retrieving it works');
