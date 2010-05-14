# Configuration for the WebLogin script.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2004, 2005, 2006, 2007, 2008, 2009
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

package WebKDC::Config;

use strict;
use warnings;

my $conf = "/etc/webkdc/webkdc.conf";

our $KEYRING_PATH = "../conf/webkdc/keyring";
our $TEMPLATE_PATH = "/usr/local/share/weblogin/generic/templates";
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
our $EXPIRED_PW_SERVER;
our $EXPIRED_PW_WARNING;

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
