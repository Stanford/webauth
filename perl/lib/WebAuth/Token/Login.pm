# Perl representation of a WebAuth login token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Login;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub username { my $self = shift; $self->_attr ('username', @_) }
sub password { my $self = shift; $self->_attr ('password', @_) }
sub otp      { my $self = shift; $self->_attr ('otp',      @_) }
sub creation { my $self = shift; $self->_attr ('creation', @_) }

1;
