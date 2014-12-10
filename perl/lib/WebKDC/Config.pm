# Configuration for the WebLogin script.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2004, 2005, 2006, 2007, 2008, 2009, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

package WebKDC::Config;

use strict;
use warnings;

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

my $conf = $ENV{WEBKDC_CONFIG} || '/etc/webkdc/webkdc.conf';

our $KEYRING_PATH = "../conf/webkdc/keyring";
our $TEMPLATE_PATH = "/usr/local/share/weblogin/generic/templates";
our $TEMPLATE_COMPILE_PATH = "/usr/local/share/weblogin/generic/templates/ttc";
our $URL = "https://localhost/webkdc-service/";

our $BYPASS_CONFIRM;
our $DEFAULT_REALM;
our $FATAL_PAGE;
our $LOGIN_URL;
our @SHIBBOLETH_IDPS;
our $TOKEN_ACL;
our $WEBKDC_PRINCIPAL;

our @MEMCACHED_SERVERS;
our $RATE_LIMIT_THRESHOLD;
our $RATE_LIMIT_INTERVAL = 5 * 60;
our $REPLAY_TIMEOUT;

our $EXPIRING_PW_WARNING;
our $EXPIRING_PW_URL;
our $EXPIRING_PW_RESEND_PASSWORD = 1;

our $REMEMBER_FALLBACK = 'no';

our $MULTIFACTOR_COMMAND;
our $MULTIFACTOR_TGT;
our $MULTIFACTOR_SERVER;
our $MULTIFACTOR_PORT = 0;
our $MULTIFACTOR_PRINC = '';

our $PASSWORD_CHANGE_COMMAND;
our $PASSWORD_CHANGE_PORT = 0;
our $PASSWORD_CHANGE_PRINC = '';
our $PASSWORD_CHANGE_SERVER;
our $PASSWORD_CHANGE_SUBCOMMAND;

our $REMUSER_ENABLED;
our $REMUSER_EXPIRES = 60 * 60 * 8;
our @REMUSER_REALMS;
our @REMUSER_PERMITTED_REALMS;
our @REMUSER_LOCAL_REALMS;
our $REMUSER_REDIRECT;

our $LOGIN_STATE_UNSERIALIZE;

our $FACTOR_WARNING  = 60 * 60 * 24 * 2;

# Obsolete variables supported for backward compatibility.
our $HONOR_REMOTE_USER;
our $REALM;
our @REALMS;
our $REMOTE_USER_REDIRECT;

if (-f $conf) {
    my $ret = do $conf;
    die "failed to parse $conf: $@" if $@;
    die "failed to read $conf: $!" if not defined $ret and $!;
}

# Merge obsolete variables into the ones we now use.
if ($HONOR_REMOTE_USER and not defined $REMUSER_ENABLED) {
    $REMUSER_ENABLED = 1;
}
if (defined ($REMOTE_USER_REDIRECT) and not defined ($REMUSER_REDIRECT)) {
    $REMUSER_REDIRECT = $REMOTE_USER_REDIRECT;
}
if (@REALMS and not @REMUSER_REALMS) {
    @REMUSER_REALMS = @REALMS;
}
if (defined ($REALM)) {
    push (@REMUSER_REALMS, $REALM);
}
if (@REMUSER_REALMS and not @REMUSER_PERMITTED_REALMS) {
    @REMUSER_PERMITTED_REALMS = @REMUSER_REALMS;
}
if (@REMUSER_REALMS and not @REMUSER_LOCAL_REALMS) {
    @REMUSER_LOCAL_REALMS = @REMUSER_REALMS;
}

1;

__END__

=for stopwords
WebAuth WebLogin Allbery

=head1 NAME

WebKDC::Config - Configuration for the WebAuth WebLogin service

=head1 SYNOPSIS

    use WebKDC::Config;
    my $keyring = $WebKDC::Config::KEYRING_PATH;

=head1 DESCRIPTION

WebKDC::Config encapsulates all the site-specific configuration for the
WebLogin component of the WebAuth web authentication system.  It is
implemented as a Perl class that declares and sets the defaults for
various configuration variables and then, if it exists, loads the file
specified by the WEBKDC_CONFIG environment variable or
F</etc/webkdc/webkdc.conf> if that environment variable isn't set.  That
file should contain any site-specific overrides to the defaults.

This file must be valid Perl.  To set a variable, use the syntax:

    $VARIABLE = <value>;

where VARIABLE is the variable name (always in all-capital letters) and
<value> is the value.  If setting a variable to a string and not a number,
you should normally enclose <value> in C<''>.  For example, to set the
variable KEYRING_PATH to C</var/lib/webkdc/keyring>, use:

    $KEYRING_PATH = '/var/lib/webkdc/keyring';

There are some settings that take arrays instead of strings or numbers;
for those, see the description of the setting for its syntax.

It is also possible to customize WebLogin by defining some Perl functions
in the configuration file.

All the configuration settings are documented in F<docs/weblogin-config>
in the WebAuth source tree.  This is also available on-line at
L<http://webauth.stanford.edu/weblogin-config.html>.

=head1 AUTHORS

Roland Schemers and Russ Allbery <eagle@eyrie.org>.

=head1 SEE ALSO

WebKDC(3), WebLogin(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
