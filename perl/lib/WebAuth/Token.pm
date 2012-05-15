# Generic base class for WebAuth tokens.
#
# This class holds some helper methods and shared code for all of the separate
# WebAuth token classes.  It is not usable directly.  More explicitly, it is
# not a representation of a generic WebAuth token; it is only an abstract base
# class.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token;

require 5.006;
use strict;
use warnings;

use Carp qw(croak);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Constructor.  Reject attempts to create this class directly.  This is only
# intended for use by subclasses.
sub new ($$) {
    my ($type, $ctx) = @_;
    if ($type eq 'WebAuth::Token') {
        croak ('WebAuth::Token cannot be used directly');
    }
    unless (ref ($ctx) eq 'WebAuth') {
        croak ('second argument to constructor must be a WebAuth object');
    }
    my $self = { ctx => $ctx };
    bless ($self, $type);
    return $self;
}

# Shared code for all accessor methods.  Takes the object, the attribute name,
# and the value.  Sets the value if one was given, and returns the current
# value of that attribute.
sub _attr {
    my ($self, $attr, $value) = @_;
    $self->{$attr} = $value if defined ($value);
    return $self->{$attr};
}

1;
