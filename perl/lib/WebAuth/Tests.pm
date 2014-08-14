# Utility functions for mod_webauth tests.
#
# Written by Roland Schemers
# Rewritten as a module by Jon Robertson <jonrober@stanford.edu>
# Copyright 2003, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

package WebAuth::Tests;

use 5.006;
use strict;
use warnings;

use Carp;
use CGI qw(:standard);
use CGI::Cookie;
use Data::Dumper;
use Template;

use Exporter qw(import);
our @EXPORT_OK = qw(build_page run_test app_lifetime_test last_used_test);

our $VERSION;

# This version matches the version of WebAuth with which this module was
# released, but with two digits for the minor and patch versions.
BEGIN {
    $VERSION = '4.0700';
}

#############################################################################
# Internal tests
#############################################################################

# Creates an array of hash records for all of our regular tests, suited to be
# passed into our template.
sub _standard_tests {
    my $webauth_token_creation   = $ENV{WEBAUTH_TOKEN_CREATION};
    my $webauth_token_expiration = $ENV{WEBAUTH_TOKEN_EXPIRATION};
    my $webauth_user             = $ENV{WEBAUTH_USER};
    my $remote_user              = $ENV{REMOTE_USER};
    my $auth_type                = $ENV{AUTH_TYPE};

    my @standard_tests;

    my $record = run_test('AUTH_TYPE',
                          $auth_type eq 'WebAuth',
                          'WebAuth',
                          "not WebAuth, it's $auth_type",
                          1);
    push (@standard_tests, $record);

    $record = run_test('REMOTE_USER',
                       $remote_user ne '',
                       $remote_user,
                       'not set!',
                       1);
    push (@standard_tests, $record);

    $record = run_test('WEBAUTH_USER',
                       $webauth_user ne '',
                       $webauth_user,
                       'not set!',
                       1);
    push (@standard_tests, $record);

    $record = run_test('WEBAUTH_USER == REMOTE_USER',
                       $webauth_user eq $remote_user,
                       'they are equal',
                       'they are not equal!',
                       0);
    push (@standard_tests, $record);

    $record = run_test('WEBAUTH_TOKEN_CREATION',
                       $webauth_token_creation ne '',
                       scalar(localtime($webauth_token_creation)),
                       'not set!',
                       1);
    push (@standard_tests, $record);

    $record = run_test('WEBAUTH_TOKEN_EXPIRATION',
                       $webauth_token_expiration ne '',
                       scalar(localtime($webauth_token_expiration)),
                       'not set!',
                       1);
    push (@standard_tests, $record);

    return \@standard_tests;
}

# Creates an array of hash records for all of our cookies, suited to be
# passed into our template.
sub _cookies {
    my @cookies;
    my %cookies = CGI::Cookie->fetch;
    foreach my $var (sort(keys(%cookies))) {
        next unless $var =~ /^webauth_/ && $var !~ /^webauth_wpt_/;
        my ($name, $val) = split('=', $cookies{$var});

        my %record = (name  => $var,
                      value => _truncate_str($val, 40),
        );
        push (@cookies, \%record);
    }

    return \@cookies;
}

# Creates an array of hash records for directly relevant environment
# variables, suited to be  passed into our template.
sub _environment_important {
    my @environment;
    foreach my $var (sort(keys(%ENV))) {
        next unless $var eq 'REMOTE_USER' || $var eq 'AUTH_TYPE'
            || $var =~ m{^WEBAUTH_};
        my %record = (name  => $var,
                      value => _truncate_str($ENV{$var}, 80),
        );
        push (@environment, \%record);
    }

    return \@environment;
}

# Creates an array of hash records for less important environment variables,
# suited to be passed into our template.
sub _environment_misc {
    my @environment;
    foreach my $var (sort(keys(%ENV))) {
        next if $var eq 'REMOTE_USER';
        next if $var eq 'AUTH_TYPE';
        next if $var =~ m{^WEBAUTH_};
        my %record = (name  => $var,
                      value => _truncate_str($ENV{$var}, 80),
        );
        push (@environment, \%record);
    }

    return \@environment;
}

# Creates an array of hash records for the multifactor configuration and
# levels.
sub _multifactor_tests {
    my $webauth_factors_initial = $ENV{WEBAUTH_FACTORS_INITIAL};
    my $webauth_factors_session = $ENV{WEBAUTH_FACTORS_SESSION};
    my $webauth_loa             = $ENV{WEBAUTH_LOA};

    my @tests;
    my $record = run_test('WEBAUTH_FACTORS_INITIAL',
                          $webauth_factors_initial ne '',
                          $webauth_factors_initial,
                          'not set!',
                          1);
    push (@tests, $record);

    $record = run_test('WEBAUTH_FACTORS_SESSION',
                       $webauth_factors_session ne '',
                       $webauth_factors_session,
                       'not set!',
                       1);
    push (@tests, $record);

    $record = run_test('WEBAUTH_LOA',
                       $webauth_loa ne '',
                       $webauth_loa,
                       'not set!',
                       1);
    push (@tests, $record);

    return \@tests;
}

#############################################################################
# Internal misc functions
#############################################################################

# Given a string and a maximum length for it, truncate it and append a message
# after if the string exceeds the maximum length.  Return the string.
sub _truncate_str {
    my ($str, $max_length) = @_;
    if (length($str) > $max_length) {
        $str = substr($str, 0, $max_length) . '...(truncated)';
    }
    return $str;
}

#############################################################################
# External tests
#############################################################################

# Given a test name, a result test to perform, and a good and bad comments to
# use on pass/fail, return a hash for the test's status.
sub run_test {
    my ($test_name, $result, $good, $bad, $bold) = @_;

    my %record;
    $record{name}         = $test_name;
    $record{result}       = $result;
    $record{comment}      = $result ? $good : $bad;
    $record{comment_bold} = $bold;
    return \%record;
}

# Run all tests for App token lifetime and return as an array for reporting.
sub app_lifetime_test {
    my $webauth_token_expiration = $ENV{WEBAUTH_TOKEN_EXPIRATION};
    my @tests;
    my $record = run_test('WEBAUTH_TOKEN_EXPIRATION',
                          $webauth_token_expiration < time()+10,
                          'expires in less then 10 seconds',
                          'does not expire in less then 10 seconds',
                          0);
    push (@tests, $record);
    return \@tests;
}

# Test to make sure that the last used time is outside of a narrow window for
# 'now'.
sub last_used_test {
    my $webauth_token_lastused = $ENV{WEBAUTH_TOKEN_LASTUSED};
    my $time = time();
    my $low  = $time - 10;
    my $high = $time + 10;

    my @tests;
    my $record = run_test('WEBAUTH_TOKEN_LASTUSED',
                          ($webauth_token_lastused > $low &&
                           $webauth_token_lastused < $high),
                          scalar(localtime($webauth_token_lastused)),
                          'not within the acceptable time window!',
                          1);
    push (@tests, $record);
    return \@tests;
}

#############################################################################
# External misc functions
#############################################################################

# Takes a number of args for page title and any extra tests or unusual flags
# to use.  Then grabs several standard tests and tosses them in to create a
# test page result.
sub build_page {
    my ($args) = @_;

    # Set all values to be passed to the template.
    my %values = (test_num              => $args->{test_number},
                  test_desc             => $args->{test_desc},
                  extended_description  => $args->{extended_desc},
                  standard_tests        => _standard_tests(),
                  cookies               => _cookies(),
                  environment_important => _environment_important(),
                  environment_misc      => _environment_misc(),
                  extra_tests_title     => $args->{extra_title},
                  extra_tests           => $args->{extra_tests},
                  logout                => $args->{logout} || '/tests/logout',
                  remote_user           => $ENV{REMOTE_USER},
                  unauth_location       => $args->{unauth_loc} || 0,
    );

    # Multifactor tests have those as their test type.
    if ($args->{multifactor}) {
        $values{extra_tests_title} = 'Performing Multifactor tests';
        $values{extra_tests}       = _multifactor_tests();
    }

    # Build and return the page from a template.
    my $tt = Template->new (RELATIVE => 1) or carp ("$Template::ERROR\n");
    my $output = '';
    my $fname  = $args->{template} || '../test.tt2';
    $tt->process ($fname, \%values, \$output)
        or carp ($tt->error."\n");
    return $output;
}

1;

__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
WebAuth WebLogin multifactor

=head1 NAME

WebAuth::Tests - Assists with constructing WebAuth Apache module tests

=head1 SYNOPSIS

    use WebAuth::Tests qw(build_page);

    my %settings = (
        test_number   => 1,
        test_desc     => 'basic WebAuth test',
        extended_desc => \@extended,
    );

    print "Content-type: text/html\n\n";
    print build_page(\%settings);

=head1 DESCRIPTION

This module provides shared code for the test suite for the mod_webauth
Apache module.  It is used by the individual test programs and test Apache
configuration to construct a variety of scenarios to exercise most of the
functionality of mod_webauth and some of the WebLogin and mod_webkdc
features.  Most of the test setup is in the Apache configuration, but each
test corresponds to a Perl script, which uses this module, that checks
environment variables to see that the tests did what they should and
provides useful debugging information if they did not.

This module is primarily intended for use with the tests that are included
with WebAuth and currently includes some defaults that make it difficult
to use for other purposes.  The goal is to eventually make it more general
so that it can be used for building additional tests local to a particular
site.

=head1 FUNCTIONS

None of the following functions are exported by default.  They must be
explicitly requested when using the WebAuth::Tests module.

=over 4

=item build_page(SETTINGS)

Performs the work of building a test page that shows the test number,
title, information about the test run, and various tables showing current
status and tests run.  SETTINGS should be a reference to a hash, which may
contain one or more of the following settings:

=over 4

=item test_number

The number of this test, passed to the template.

=item test_desc

The short description of this test, passed to the template.

=item extended_description

The extended description of this test.  This should be a reference to an
array that contains one or more paragraphs of text as strings.  Each
element of the array will be wrapped in <p> tags.

=item extra_tests

An anonymous array of hash references, each of which represents a test
result.  The hash should have three keys: C<name>, C<result>, and
C<comment>.  C<name> should be the name of this test, C<result> should
be either C<PASS> or C<FAIL>, and C<comment> should provide additional
information about the test.

=item extra_tests_title

If there are extra tests, this will be used as the heading for that test
output.  If this setting is present, extra_tests should also be present.

=item multifactor

Set this to true to also perform multifactor tests.

=item template

The path (possibly relative) to the template used for generating HTML.
By default, this is set to F<../test.tt2>, which works for the default
mod_webauth test suite (and probably not for anything else).

=item unauth_loc

Set this to true if this test will be running without authentication.
This is used by the template to change some of the boilerplate text.

=back

=item run_test(NAME, RESULT, GOOD, BAD, BOLD)

Performs a test of WebAuth information, returning an anonymous hash
showing the results of the test in the format required by the
C<extra_tests> setting to build_page().  It takes the name of the test, a
boolean value that represents the result of the test, text to display on
true or false results, and a flag indicating whether to bold true results.

=item app_lifetime_test

Creates an anonymous array of hash references that contains the results of
a test for the lifetime of an application token.  The result is suitable
for inclusion in C<extra_tests>.

=item last_used_test()

Creates an anonymous array of hash references that contains the results of
a test for current last-used time for a token.  The result is suitable for
inclusion in C<extra_tests>.

=back

=head1 BUGS

The interactions between this module and its template aren't currently
completely documented.

No one has yet used this module for anything other than the mod_webauth
test suite included in the distribution.  It will probably need work to
be usable for writing site-specific tests.

=head1 AUTHOR

Roland Schemers and Jon Robertson <jonrober@stanford.edu>.

=head1 SEE ALSO

Template(3)

This module is part of WebAuth.  The current version is available from
L<http://webauth.stanford.edu/>.

=cut
