#!/usr/bin/perl
#
# Build script for WebAuth distribution.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2003, 2004, 2005, 2006, 2009, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use 5.008;
use strict;
use warnings;

use Module::Build;

# Basic package configuration.
my $build = Module::Build->new(
    module_name          => 'WebAuth',
    dist_author          => 'Russ Allbery <eagle@eyrie.org>',
    license              => 'mit',
    recursive_test_files => 1,
    add_to_cleanup       => [qw(webauth_keyring webauth_keyring2)],

    # XS configuration.  For in-tree builds, we override this to add the full
    # list of dependency libraries, which will work on more systems.
    extra_linker_flags => [qw(-lwebauth)],

    # Other package relationships.
    configure_requires => { 'Module::Build' => 0.28 },
    requires           => {
        'CGI::Application'                      => 0,
        'CGI::Application::Plugin::AutoRunmode' => 0,
        'CGI::Application::Plugin::Forward'     => 0,
        'CGI::Application::Plugin::Redirect'    => 0,
        'CGI::Application::Plugin::TT'          => 0,
        'IO::Socket::SSL'                       => 0,
        'LWP::UserAgent'                        => 0,
        'Template'                              => 0,
        'URI'                                   => 0,
        'XML::Parser'                           => 0,
        perl                                    => '5.008',
    },
    recommends => {
        'Cache::Memcached' => 0,
        'Date::Parse'      => 0,
        'Digest::SHA'      => 0,
        'Net::Remctl'      => 0,
        'Time::Duration'   => 0,
    },
);

# Work around a bug in the version of Module::Build that shipped with RHEL 5.
if ($Module::Build::VERSION <= 0.2807) {
    for my $param (qw(extra_compiler_flags extra_linker_flags)) {
        my $value = $build->$param;
        if (ref($value) eq 'ARRAY' && @{$value} == 1) {
            $build->$param($build->split_like_shell($value->[0]));
        }
    }
}

# Generate the build script.
$build->create_build_script;
