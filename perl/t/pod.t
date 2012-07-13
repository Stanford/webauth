#!/usr/bin/perl -w
#
# Test POD formatting for the wallet Perl modules.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2010
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use Test::More;
eval 'use Test::Pod 1.00';
plan skip_all => 'Test::Pod 1.00 required for testing POD' if $@;
all_pod_files_ok ();
