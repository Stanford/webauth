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
our %PAGES = (pwchange => 'pwchange.tmpl',
              confirm  => 'confirm.tmpl',
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

    my $weblogin = WebLogin->new ($q, \%PAGES);
    my $req = $weblogin->{request};

    # Cases we might encounter:
    # * Expired password -- login.fcgi creates a changepw cred token and
    #   sends us here.
    # * Password going to expire soon -- login.fcgi creates a changpw cred
    #   token and gives a button to send us here.
    # * User choice -- User comes here on their own, needing to enter username
    #   and password

    # Check to see if this is our first visit and simply show the change page
    # if so (skipping checks for missing fields).
    if (!$weblogin->{query}->param ('changepw')) {
        $weblogin->print_pwchange_page ($req->request_token,
                                        $req->service_token);
        next;
    }

    # Test to make sure that all required fields are filled out.
    next unless $weblogin->test_pwchange_fields;
    next unless $weblogin->test_cookies;
    next unless $weblogin->test_password_no_post;

    # Attempt password change via krb5_change_password API
    my ($status, $error) = $weblogin->change_user_password;

    # We've successfully changed the password.  Depending on if we were sent
    # by an expired password, either pass along to the normal page or give a
    # confirm screen.
    if ($status == WK_SUCCESS) {

        # Expired password -- do the normal login process.
        if ($weblogin->{query}->param ('expired') == 1) {

            # Get the right script name and password.
            $weblogin->{script_name} = $WebKDC::Config::LOGIN_URL;
            my $newpass = $weblogin->{query}->param ('new_passwd1');
            $weblogin->{query}->param ('password', $newpass);

            # Set up all WebKDC parameters, including tokens, proxy tokens, and
            # REMOTE_USER parameters.
            my %cart = CGI::Cookie->fetch;
            $status = $weblogin->setup_kdc_request (%cart);

            # Pass the information along to the WebKDC and get the response.
            if (!$status) {
                ($status, $error)
                    = WebKDC::make_request_token_request ($weblogin->{request},
                                                          $weblogin->{response});
            }

            # Send the response we got off to the handler, where it can decide
            # which page to display based on the response.
            $weblogin->process_response ($status, $error);

        # We weren't sent by expired password -- just print a confirm.
        } else {
            $weblogin->print_pwchange_confirm_page;
        }

    # Heimdal returns this if the password failed strength checking.  Give
    # an error that's more understandable to users.
    # FIXME: Should be verified against MIT as well.
    } elsif ($status == WK_ERR_UNRECOVERABLE_ERROR
             && $error =~ /\(-1765328343\)/) {
        $weblogin->{pages}->{pwchange}->param (error => 1);
        $weblogin->{pages}->{pwchange}->param (err_pwweak => 1);
        $weblogin->print_pwchange_page ($weblogin->{query}->param ('RT'),
                                        $weblogin->{query}->param ('ST'));

    # The password change failed for some reason.  Display the password
    # change page again, with the error template variable filled in.
    } else {
        $weblogin->{pages}->{pwchange}->param (error => 1);
        $weblogin->{pages}->{pwchange}->param (err_pwchange => 1);
        $weblogin->{pages}->{pwchange}->param (err_msg => $error);
        $weblogin->print_pwchange_page ($weblogin->{query}->param ('RT'),
                                        $weblogin->{query}->param ('ST'));
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
