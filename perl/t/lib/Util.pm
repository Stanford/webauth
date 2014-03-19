# Utility class for webauth tests.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Parts from Russ Allbery <eagle@eyrie.org>
# Copyright 2010, 2012, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package Util;
require 5.006;

use strict;
use warnings;
use vars qw(@ISA @EXPORT $VERSION);

use WebAuth qw(3.00 WA_KEY_AES WA_AES_128);
use WebKDC::Config ();
use WebLogin;
use Template;
use Test::More;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '2.00';

use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(contents get_userinfo remctld_spawn remctld_stop create_keyring
    getcreds default_weblogin init_weblogin read_outputfile
    index_wrapper compare_fields create_test_keyring create_test_st
    create_test_rt page_configuration);

##############################################################################
# Data setup functions
##############################################################################

# Create and give default settings to a weblogin object.
# TODO: Remove and replace with init_weblogin in all places.
sub default_weblogin {

    # Load a version of the page templates that only prints out the vars.
    my %pages = (confirm  => 'confirm.tmpl',
                 pwchange => 'pwchange.tmpl',
                 error    => 'error.tmpl',
                );
    $WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
    $WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

    # Set up a query with some test data.
    $ENV{REQUEST_METHOD} = 'GET';
    my $query = CGI->new ({});

    # Set up the testing WebLogin object.
    my $weblogin = WebLogin->new;
    my $resp     = WebKDC::WebResponse->new;
    my $req      = WebKDC::WebRequest->new;
    $req->request_token('TestReqToken');
    $req->service_token('TestServiceToken');
    $weblogin->{response} = $resp;
    $weblogin->{request}  = $req;
    $weblogin->query($query);
    $weblogin->param('pages', \%pages);
    $weblogin->param('logging', 0);

    return $weblogin;
}

# Initialize the weblogin object, as we'll have to keep touching this over
# and again.
sub init_weblogin {
    my ($username, $password, $st_base64, $rt_base64) = @_;

    # Load a version of the page templates to only print out the vars sent.
    my %pages = (pwchange => 'pwchange.tmpl',
                 login    => 'login.tmpl',
                 confirm  => 'confirm.tmpl',
                 error    => 'error.tmpl');

    my $query = CGI->new ({});
    $query->request_method ('POST');
    $query->param ('username', $username);
    $query->param ('password', $password);
    $query->param ('ST', $st_base64);
    $query->param ('RT', $rt_base64);

    $WebKDC::Config::TEMPLATE_PATH         = 't/data/templates';
    $WebKDC::Config::TEMPLATE_COMPILE_PATH = 't/tmp/ttc';

    my $weblogin = WebLogin->new (QUERY  => $query,
                                  PARAMS => { pages => \%pages });
    $weblogin->cgiapp_prerun;
    $weblogin->param ('debug', 0);
    $weblogin->param ('logging', 0);
    $weblogin->param ('script_name', '/login');

    # Normally set during WebKDC::request_token_request.
    $weblogin->{response}->return_url ('https://test.example.org/');
    $weblogin->{response}->subject ($username);
    $weblogin->{response}->requester_subject ('webauth/test3.testrealm.org@testrealm.org');
    $weblogin->{response}->response_token ('TestResponse');
    $weblogin->{response}->response_token_type ('id');

    # Set the password expiration time depending on the user.
    if ($username eq 'testuser1') {
        # Expires in-range for a warning.
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    } elsif ($username eq 'testuser2') {
        # Expires out of range for a warning.
        $weblogin->{response}->password_expiration (time +
                                                    60 * 60 * 24 * 356);
    } elsif ($username eq 'testuser3') {
        # Do nothing here, we want non-existing pw expiration.
    } else {
        # Expires in-range for a warning..
        $weblogin->{response}->password_expiration (time + 60 * 60 * 24);
    }

    return $weblogin;
}

# Create and return a keyring for testing.
sub create_test_keyring {
    my ($wa) = @_;

    unlink ('t/data/test.keyring', 't/data/test.keyring.lock', 'krb5cc_test');
    $WebKDC::Config::KEYRING_PATH = 't/data/test.keyring';
    create_keyring ($WebKDC::Config::KEYRING_PATH);
    my $keyring = $wa->keyring_read ($WebKDC::Config::KEYRING_PATH);
}

# Create and return the ST for testing.
sub create_test_st {
    my ($wa, $keyring) = @_;
    my $principal = contents ('t/data/test.principal');
    my $random = 'b' x WebAuth::WA_AES_128;
    my $st = WebAuth::Token::WebKDCService->new ($wa);
    $st->subject ("krb5:$principal");
    $st->session_key ($random);
    $st->creation (time);
    $st->expiration (time + 3600);
    my $st_base64 = $st->encode ($keyring);
    return ($st, $st_base64);
}

# Create and return the RT for testing.
sub create_test_rt {
    my ($wa, $st) = @_;

    my $random = 'b' x WebAuth::WA_AES_128;
    my $key = $wa->key_create (WebAuth::WA_KEY_AES, WebAuth::WA_AES_128,
                               $random);
    my $client_keyring = $wa->keyring_new ($key);
    my $rt = WebAuth::Token::Request->new ($wa);
    $rt->type ('id');
    $rt->auth ('webkdc');
    $rt->return_url ('https://test.example.org/');
    $rt->creation (time);
    my $rt_base64 = $st->encode ($client_keyring);
    return $rt_base64;
}

# For all of the various page tests, do the initial setup of various config
# settings.
sub page_configuration {
    my ($user) = @_;

    # Set our method to not have password tests complain.
    $ENV{REQUEST_METHOD} = 'POST';

    # Miscellaneous config settings.
    $WebKDC::Config::EXPIRING_PW_URL = '/pwchange';
    $WebKDC::Config::EXPIRING_PW_WARNING = 60 * 60 * 24 * 7;
    $WebKDC::Config::EXPIRING_PW_RESEND_PASSWORD = 0;
    $WebKDC::Config::REMUSER_REDIRECT = 0;
    @WebKDC::Config::REMUSER_LOCAL_REALMS = ();
    @WebKDC::Config::REMUSER_PERMITTED_REALMS = ();
    $WebKDC::Config::BYPASS_CONFIRM = '';

    # Disable all the memcached stuff for now.
    @WebKDC::Config::MEMCACHED_SERVERS = ();
    # If the username is fully qualified, set a default realm.
    if ($user =~ /\@(\S+)/) {
        $WebKDC::Config::DEFAULT_REALM = $1;
        @WebKDC::Config::REMUSER_PERMITTED_REALMS = ($1);
        @WebKDC::Config::REMUSER_LOCAL_REALMS = ($1);
    }

    # Set up various ENV variables later used for logging.
    $ENV{SERVER_ADDR} = 'localhost';
    $ENV{SERVER_PORT} = '443';
    $ENV{REMOTE_ADDR} = '127.0.0.1';
    $ENV{REMOTE_PORT} = '443';
    $ENV{REMOTE_USER} = $user;
    $ENV{SCRIPT_NAME} = '/login';
}

##############################################################################
# Test wrappers
##############################################################################

# Given arrayrefs to the output variables and the variables we expect, run
# checks for each value.  Because the expected values may contain regular
# expressions, we don't use is_deeply, but check to see if the value starts
# with a \.
sub compare_fields {
    my ($output, $check, @fields) = @_;

    for my $field (@fields) {
        if ($check->{$field} =~ m{^\\}) {
            like ($output->{$field}, qr{$check->{$field}},
                "... and $field matches what it should be");
        } else {
            is ($output->{$field}, $check->{$field},
                "... and $field matches what it should be");
        }
    }
}

##############################################################################
# I/O functions
##############################################################################

# Returns the username and password from a file that contains them both,
# each on one line.
sub get_userinfo  {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $username = <FILE>;
    my $password = <FILE>;
    close FILE;
    chomp ($username, $password);
    return ($username, $password);
}

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}

# Given the name of an output file matching the state of a template we want
# to check against, read in that file and parse it into a hash of values that
# we can use to validate against for tests.  Return that hash.
sub read_outputfile {
    my ($fname) = @_;
    my %check;

    open (my $check_fh, '<', $fname) or die "could not open test file: $!\n";
    while (my $line = <$check_fh>) {
        chomp $line;
        my ($field, $value) = split (m{\s+}, $line);
        if (!defined $value) {
            $value = '' ;
        }
        $check{$field} = $value;
    }
    close $check_fh or die "could not close test file: $!\n";

    return %check;
}

# Wrapper around WebLogin::index to grab the page output into a string and
# return that output.  To make all the index runmode tests look cleaner.
sub index_wrapper {
    my ($weblogin) = @_;
    my %output;

    my $page = $weblogin->index;
    for my $line (split (/[\r\n]+/, $$page)) {
        my ($key, $value) = split (m{\s+}, $line);
        $output{$key} = $value;
    }
    return %output;
}

##############################################################################
# Kerberos utility functions
##############################################################################

# Given a keytab file and a principal, try authenticating with kinit.
sub getcreds {
    my ($file, $principal) = @_;
    my @commands = (
        "kinit -k -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -T /bin/true -k -K $file $principal >/dev/null 2>&1 </dev/null",
    );
    for my $command (@commands) {
        if (system ($command) == 0) {
            return 1;
        }
    }
    return 0;
}

# Given keytab data and the principal, write it to a file and try
# authenticating using kinit.
sub keytab_valid {
    my ($keytab, $principal) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;
    $principal .= '@' . $Wallet::Config::KEYTAB_REALM
        unless $principal =~ /\@/;
    my $result = getcreds ('keytab', $principal);
    if ($result) {
        unlink 'keytab';
    }
    return $result;
}

# Create a keyring file for use by the server.
sub create_keyring {
    my ($fname) = @_;
    return if -f $fname;

    my $wa = WebAuth->new;
    my $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
    my $ring = $wa->keyring_new ($key);
    $ring->write ($fname);
}

##############################################################################
# remctld handling
##############################################################################

# Start remctld with the appropriate options to run our fake keytab backend.
# Takes the principal it uses as its server principal, the keytab it uses for
# authentication, and the configuration file it should load.
sub remctld_spawn {
    my ($principal, $keytab, $config) = @_;

    # If REMCTLD is set in the environment, use that as the binary.
    my $remctld = $ENV{REMCTLD} || 'remctld';

    # In case REMCTLD was not set, add sbin directories to our PATH.
    local $ENV{PATH} = "/usr/local/sbin:/usr/sbin:$ENV{PATH}";

    # Determine the command to run.
    unlink 'test-pid';
    my @command = ($remctld, '-m', '-p', 14373, '-s', $principal, '-P',
                   'test-pid', '-f', $config, '-S', '-F', '-k', $keytab);
    print "Starting remctld: @command\n";

    # Fork off remctld.
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "cannot redirect stderr: $!\n";
        exec (@command) or die "cannot exec $remctld: $!\n";
    } else {
        my $tries = 0;
        while ($tries < 10 && ! -f 'test-pid') {
            select (undef, undef, undef, 0.25);
        }
    }
}

# Stop the running remctld process.
sub remctld_stop {
    open (PID, '<', 'test-pid') or return;
    my $pid = <PID>;
    close PID;
    chomp $pid;
    kill 15, $pid;
}
