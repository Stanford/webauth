#!/usr/bin/perl -w
#
# pwchange.fcgi -- WebLogin password change page for WebAuth.
#
# This is the page to change user password for weblogin.  It accepts
# information from the user, passes it to the WebKDC for authentication, and
# changes password if credentials match.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

require 5.006;

use strict;

use CGI ();
use CGI::Cookie ();
use CGI::Fast ();
use HTML::Template ();
use WebAuth qw(:base64 :const :krb5 :key);
use WebLogin;
use WebKDC ();
use WebKDC::Config ();
use WebKDC::WebKDCException;

# Set to true in our signal handler to indicate that the script should exit
# once it finishes processing the current request.
our $EXITING = 0;

# The names of the template pages that we use.  The beginning of the main
# routine changes the values here to be HTML::Template objects.
our %PAGES = (login    => 'login.tmpl',
              confirm  => 'confirm.tmpl',
              pwchange => 'pwchange.tmpl',
              error    => 'error.tmpl');

##############################################################################
# Debugging
##############################################################################

# Dump as much information as possible about the environment and input to
# standard output.  Not currently used anywhere, just left in here for use
# with debugging.
sub dump_stuff {
    my ($var, $val);
    foreach $var (sort keys %ENV) {
        $val = $ENV{$var};
        $val =~ s|\n|\\n|g;
        $val =~ s|\"|\\\"|g;
        print "${var}=\"${val}\"\n";
    }
    print "\n";
    print "\n";
    local $_;
    print "INPUT: $_" while <STDIN>;
}

##############################################################################
# Main routine
##############################################################################

# Pre-compile our templates.  When running under FastCGI, this results in a
# significant speedup, since loading and compiling the templates is a bit
# time-consuming.
%PAGES = map {
    $_ => HTML::Template->new (filename => $PAGES{$_},
                               cache    => 1,
                               path     => $WebKDC::Config::TEMPLATE_PATH)
} keys %PAGES;

# Exit safely if we get a SIGTERM.
$SIG{TERM} = sub { $EXITING = 1 };

# The main loop.  If we're not running under FastCGI, CGI::Fast will detect
# that and only run us through the loop once.  Otherwise, we live in this
# processing loop until the FastCGI socket closes.
while (my $q = CGI::Fast->new) {

    my $weblogin = new WebLogin ($q, \%PAGES);
    my ($status, $error);

    # Cases we might encounter:
    # * Expired password -- login.fcgi creates a changepw cred token and
    #   sends us here.
    # * Password going to expire soon -- login.fcgi creates a changpw cred
    #   token and gives a button to send us here.
    # * User choice -- User comes here on their own, needing to enter username
    #   and password

    # Check to see if this is our first visit and simply show the change page
    # if so.
    if (!$weblogin->{query}->param ('username')) {
        $weblogin->print_pwchange_page;
        next;
    }

    # Test to make sure that all required fields are filled out.
    next unless $weblogin->test_pwchange_fields;
    next unless $weblogin->test_cookies;
    next unless $weblogin->test_password_no_post;

    # Attempt password change via krb5_change_password API
    my ($status, $error) = $weblogin->change_user_password;

    # We've successfully changed the password...
    if ($status == WK_SUCCESS) {

        $weblogin->print_pwchange_confirm_page;

    # The password change failed for some reason.  Display the password
    # change page again, with the error template variable filled in.
    } else {
        $weblogin->{pages}->{pwchange}->param (error => 1);
        $weblogin->{pages}->{pwchange}->param (err_pwchange => 1);
        $weblogin->{pages}->{pwchange}->param (err_msg => $error);
        $weblogin->print_pwchange_page;
    }

# Done on each pass through the FastCGI loop.  Clear out template parameters
# for all of the pages for the next run and restart the script if its
# modification time has changed.
} continue {
    exit if $EXITING;
    for (keys %PAGES) {
        $PAGES{$_}->clear_params;
    }
    exit if -M $ENV{SCRIPT_FILENAME} < 0;
}
