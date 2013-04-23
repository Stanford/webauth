# Utility functions for mod_webauth tests.
#
# Written by Roland Schemers
# Copyright 2003, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebAuth::Tests;

use strict;
use warnings;

use Carp;
use CGI qw/:standard/;
use CGI::Cookie;
use Data::Dumper;
use Template;

use Exporter qw(import);
our @EXPORT_OK = qw(build_page run_test app_lifetime_test last_used_test);

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
    my $fname  = '../test.tt2';
    $tt->process ($fname, \%values, \$output)
        or carp ($tt->error."\n");
    return $output;
}

1;

__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

WebAuth::Tests - Functions for the mod_webauth Perl tests

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

This module contains functions for tests run against a mod_webkdc server
to ensure that various pieces are all working properly.  Most of the actual
tests are done by configuration files, but these tests will run to check
environment variables to see that the tests did what they should, and to
provide useful debugging information if they did not.

=head1 COMMANDS

=over 4

=item build_page ($arguments)

Performs the work of building a test page that shows the test number,
title, information about the test run, and various tables showing current
status and tests run.

=item run_test ($name, $result, $good, $bad, $bold)

Performs a test of webauth information, returning a hashref record about
the results of the test.  It takes the name of the test, the results of a
simple test (such as equality) to perform, text to display on true or
false results, and a flag as to whether or not to bold true results.

=item last_used_test

Creates an arrayref of hashrefs that contains information used to create a
table showing the last used time for the token.

=item app_lifetime_test

Creates an arrayref of hashrefs that contains information used to create a
table showing token expiration information.
