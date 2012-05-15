# Perl representation of a WebAuth error token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Error;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub code     { my $self = shift; $self->_attr ('code',     @_) }
sub message  { my $self = shift; $self->_attr ('message',  @_) }
sub creation { my $self = shift; $self->_attr ('creation', @_) }

1;
