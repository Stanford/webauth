package WebKDC::Config;

use strict;
use warnings;

my $conf = "/etc/webkdc/webkdc.conf";

our $KEYRING_PATH = "../conf/webkdc/keyring";
our $TEMPLATE_PATH = "./generic/templates";
our $URL = "https://localhost/webkdc-service/";
our $HONOR_REMOTE_USER = 0;
our $REMUSER_EXPIRES = 60 * 60 * 8;
our $REALM;
our @REALMS;
our $REMOTE_USER_REDIRECT;
our @SHIBBOLETH_IDPS;

if (-f $conf) {
    my $ret = do $conf;
    die "failed to parse $conf: $@" if $@;
    die "failed to read $conf: $!" if not defined $ret and $!;
}

1;
