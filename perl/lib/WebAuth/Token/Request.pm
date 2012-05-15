# Perl representation of a WebAuth request token.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Token::Request;

require 5.006;
use strict;
use warnings;

use base qw(WebAuth::Token);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
our $VERSION = '1.00';

# Accessor methods.
sub type            { my $self = shift; $self->_attr ('type',            @_) }
sub auth            { my $self = shift; $self->_attr ('auth',            @_) }
sub proxy_type      { my $self = shift; $self->_attr ('proxy_type',      @_) }
sub state           { my $self = shift; $self->_attr ('state',           @_) }
sub return_url      { my $self = shift; $self->_attr ('return_url',      @_) }
sub options         { my $self = shift; $self->_attr ('options',         @_) }
sub initial_factors { my $self = shift; $self->_attr ('initial_factors', @_) }
sub session_factors { my $self = shift; $self->_attr ('session_factors', @_) }
sub loa             { my $self = shift; $self->_attr ('loa',             @_) }
sub command         { my $self = shift; $self->_attr ('command',         @_) }
sub creation        { my $self = shift; $self->_attr ('creation',        @_) }

1;
