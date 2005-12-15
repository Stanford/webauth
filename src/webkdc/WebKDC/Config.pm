package WebKDC::Config;

use strict;
use warnings;

my $conf = "/etc/webkdc/webkdc.conf";

our $KEYRING_PATH = "../conf/webkdc/keyring";
our $TEMPLATE_PATH = "./generic/templates";
our $URL = "https://localhost/webkdc-service/";
our $HONOR_REMOTE_USER = 0;

if (-f $conf) {
    my $ret = do $conf;
    die "failed to parse $conf: $@" if $@;
    die "failed to read $conf: $!" if not defined $ret and $!;
}

1;
