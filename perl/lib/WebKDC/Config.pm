# Configuration for the WebLogin script.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2004, 2005, 2006, 2007, 2008, 2009, 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC::Config;

use strict;
use warnings;

my $conf = $ENV{WEBKDC_CONFIG} || '/etc/webkdc/webkdc.conf';

our $KEYRING_PATH = "../conf/webkdc/keyring";
our $TEMPLATE_PATH = "/usr/local/share/weblogin/generic/templates";
our $TEMPLATE_COMPILE_PATH = "/usr/local/share/weblogin/generic/templates/ttc";
our $URL = "https://localhost/webkdc-service/";
our $BYPASS_CONFIRM;
our $DEFAULT_REALM;
our $REMUSER_ENABLED;
our $REMUSER_EXPIRES = 60 * 60 * 8;
our @REMUSER_REALMS;
our $REMUSER_REDIRECT;
our @SHIBBOLETH_IDPS;
our $TOKEN_ACL;
our $WEBKDC_PRINCIPAL;
our $LOGIN_URL;
our $FATAL_PAGE = '';

our $EXPIRING_PW_SERVER;
our $EXPIRING_PW_WARNING;
our $EXPIRING_PW_URL;
our $EXPIRING_PW_TGT;
our $EXPIRING_PW_PRINC = '';
our $EXPIRING_PW_PORT = 0;
our $EXPIRING_PW_RESEND_PASSWORD = 1;

our $MULTIFACTOR_COMMAND;
our $MULTIFACTOR_TGT;
our $MULTIFACTOR_SERVER;
our $MULTIFACTOR_PORT = 0;
our $MULTIFACTOR_PRINC = '';

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

1;

__END__

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

Roland Schemers and Russ Allbery <rra@stanford.edu>.

=head1 SEE ALSO

WebKDC(3), WebLogin(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
