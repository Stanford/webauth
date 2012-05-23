# Documentation and supplemental methods for WebAuth keyrings.
#
# The primary implementation of the WebAuth::Keyring class is done in the
# WebAuth XS module since it's primarily implemented in C.  This file adds
# some supplemental methods that are implemented in terms of other underlying
# calls and provides version and documentation information.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Keyring;

require 5.006;
use strict;
use warnings;

use Carp qw(croak);
use WebAuth ();

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Constructor.  Takes a WebAuth context and either a capacity or a key to wrap
# a keyring around.  Note that subclasses are not supported since the object
# is created by the XS module and will always be a WebAuth::Keyring.
sub new ($$$) {
    my ($type, $ctx, $key_or_size) = @_;
    if ($type ne 'WebAuth::Keyring') {
        croak ('subclassing of WebAuth::Keyring is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->keyring_new ($key_or_size);
}

# Construct a keyring by reading it from a file.  Takes the WebAuth context
# and the name of the file to read.  As above, subclasses are not supported
# since the object is created by the XS module and will always be a
# WebAuth::Keyring.
sub read ($$$) {
    my ($type, $ctx, $file) = @_;
    if ($type ne 'WebAuth::Keyring') {
        croak ('subclassing of WebAuth::Keyring is not supported');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument must be a WebAuth object');
    }
    return $ctx->keyring_read ($file);
}

1;
