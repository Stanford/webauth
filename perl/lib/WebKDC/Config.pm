# Configuration for the WebLogin script.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2004, 2005, 2006, 2007, 2008, 2009
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
our $EXPIRING_PW_SERVER;
our $EXPIRING_PW_WARNING;
our $EXPIRING_PW_URL;
our $EXPIRING_PW_TGT;
our $EXPIRING_PW_PRINC = '';
our $EXPIRING_PW_PORT  = 0;
our $EXPIRING_PW_RESEND_PASSWORD = 1;
our $FATAL_PAGE = '';

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
