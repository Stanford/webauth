#!/usr/bin/perl -w
#
# login.fcgi -- WebLogin login page for WebAuth.
#
# This is the front page for user authentication for weblogin.  It accepts
# information from the user, passes it to the WebKDC for authentication, sets
# appropriate cookies, and displays the confirmation page and return links.
#
# It should use FastCGI if available, using the Perl CGI::Fast module's
# ability to fall back on regular operation if FastCGI isn't available.
#
# Written by Roland Schemers <schemers@stanford.edu>
# Extensive updates by Russ Allbery <rra@stanford.edu>
# Copyright 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
#     The Board of Trustees of the Leland Stanford Junior University
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
use WebLogin ();
use WebKDC ();
use WebKDC::Config ();

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

    my $weblogin = WebLogin->new ($q, \%PAGES);
    my ($status, $error);

    # If we already have return_url in the query, we're at the confirmation
    # page and the user has changed the REMOTE_USER configuration.  Set or
    # clear the cookie and then redisplay the confirmation page.
    if (defined $q->param ('return_url')) {
        $weblogin->redisplay_confirm_page ();
        next;
    }

    # Test for lack of a request token, cookies not being enabled, or sending
    # passwords over a non-POST method.  If found, these will internally
    # handle the error pages, so we stop processing this request.
    next unless $weblogin->test_request_token ();
    next unless $weblogin->test_cookies ();
    next unless $weblogin->test_password_no_post ();

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

    # Send the response we got off to the handler, where it can decide which
    # page to display based on the response.
    $weblogin->process_response ($status, $error);


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
