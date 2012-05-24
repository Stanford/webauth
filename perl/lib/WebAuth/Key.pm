# Documentation and supplemental methods for WebAuth keys.
#
# The primary implementation of the WebAuth::Key class is done in the WebAuth
# XS module since it's primarily implemented in C.  This file adds some
# supplemental methods that are implemented in terms of other underlying calls
# and provides version and documentation information.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Key;

require 5.006;
use strict;
use warnings;

use Carp qw(croak);
use WebAuth ();

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Constructor.  Takes a WebAuth context, a key type, a key size, and optional
# key data and passes that off to WebAuth::key_create.  Note that subclasses
# are not supported since the object is created by the XS module and will
# always be a WebAuth::Keyring.
sub new ($$$$;$) {
    my ($class, $ctx, $type, $size, $data) = @_;
    if ($class ne 'WebAuth::Key') {
        croak ('subclassing of WebAuth::Key is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    if (defined $data) {
        return $ctx->key_create ($type, $size, $data);
    } else {
        return $ctx->key_create ($type, $size);
    }
}

1;
