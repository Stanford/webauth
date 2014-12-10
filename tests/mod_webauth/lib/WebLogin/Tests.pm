# WebLogin::Tests - Testing functions for weblogin
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University

#############################################################################
# Modules and declarations
#############################################################################

package WebLogin::Tests;

use 5.006;
use autodie;
use strict;
use warnings;

use Authen::OATH;
use Crypt::GeneratePassword qw(chars);
use Getopt::Long::Descriptive;
use IO::Handle;
use JSON;
use MIME::Base32;
use Net::Remctl;
use Test::More;
use WWW::Mechanize;

use Data::Dumper;

my $URL_ROOT   = 'https://weblogin-test.stanford.edu/tests/';
my $USERINFO   = 'lsdb-test.stanford.edu';
my %TEST_USERS = ();

use vars qw(@ISA @EXPORT);
use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(setup_users teardown_users logout login_success
    login_insufficient_loa login_insufficient_factor nologin);

#############################################################################
# Multifactor routines
#############################################################################

# Convert the normal hex version of a key to what Google requires, a base32
# version.  Most programs I've found expect the former, but Google is
# special.
sub _hex_to_google {
    my ($hex_key) = @_;
    my $base32 = MIME::Base32::encode(pack 'H*', $hex_key);
    return $base32;
}

# Given a hex key for OATH, a window, and the digits in the OTPs, generate a
# list of $window TOTP-based OTPs, with the current time in the middle.
# Return them as a list.
sub _totp_list {
    my ($hex_key, $time, $window, $digits, $duration) = @_;
    my $secret = MIME::Base32::decode(_hex_to_google($hex_key));

    # The starting time should be half the time window (since it goes
    # both into past and future from now) times thirty seconds (since
    # each time step is 30s) before now.
    my $start_time = $time - (($window - 1) / 2 * 30);

    # Go through the window to search for the given OTP.
    my (@otps);
    my $oath = Authen::OATH->new(digits   => $digits,
                                 timestep => $duration);
    for my $i (0 .. $window) {
        my $tmp_time = $start_time + 30 * $i;
        my $otp = $oath->totp($secret, $tmp_time);
        push(@otps, $otp);
    }

    use Data::Dumper; print Dumper (@otps);
    return @otps;
}

# Find the current OTP for a TOTP oath type.
sub _get_totp {
    my ($user_key) = @_;

    # Go through the window to search for the given OTP.
    my $hex_key = $TEST_USERS{$user_key}{key};
    my $secret = MIME::Base32::decode(_hex_to_google($hex_key));
    $TEST_USERS{$user_key}{base32} = $secret;
    my $oath   = Authen::OATH->new(digits   => 6,
                                   timestep => 30,
                                  );

    my $otp = $oath->totp($secret, time);
    return $otp;
}

# Find the current OTP for an HOTP oath type.  We don't have the key so we
# just grab the next one of the list we were given.
sub _get_hotp {
    my ($user_key) = @_;

    my $otps = $TEST_USERS{$user_key}{otps};
    my $otp = shift(@{ $otps });
    return $otp;
}

# Get an OTP, deciding whether we use the TOTP or HOTP method.
sub _get_otp {
    my ($user_key) = @_;

    if ($TEST_USERS{$user_key}{type} eq 'HOTP') {
        return _get_hotp($user_key);
    } else {
        return _get_totp($user_key);
    }
}

#############################################################################
# Setup and teardown
#############################################################################

# Attempt to create a user with a known password, randomly generated.
sub _user_create {
    my ($userid) = @_;
    my $count = 0;
    my $set   = 0;

    # Generate a random password and attempt to set it, trying again if it
    # fails.
    my $pass;
    do {
        warn "Attempting to create $userid\n";
        $pass = chars(20, 25);
        my $result = remctl($USERINFO, 0, '', 'kadmin', 'create', $userid,
                            $pass, 'enabled');

        $set = 1 if $result->status == 0;
        $count++;
    } until ($set || $count > 99);

    # Die if we exceeded password change attempt number.
    unless ($set) {
        die "could not create $userid in 100 attempts\n";
    }

    return $pass;
}

# Attempt to set an existing user with a known password, randomly generated.
sub _user_passwd {
    my ($userid) = @_;
    my $count = 0;
    my $set   = 0;

    # Generate a random password and attempt to set it, trying again if it
    # fails.
    my $pass;
    do {
        warn "Attempting to set password for $userid\n";
        $pass = chars(20, 25);
        my $result = remctl($USERINFO, 0, '', 'kadmin', 'reset_passwd',
                            $userid, $pass);

        $set = 1 if $result->status == 0;
        $count++;
    } until ($set || $count > 99);

    # Die if we exceeded password change attempt number.
    unless ($set) {
        die "could not set password for $userid in 100 attempts\n";
    }

    return $pass;
}

# Go through all of our users and set them up with known passwords and
# multifactor configuration.
sub setup_users {
    my (%users) = @_;
    %TEST_USERS = %users;

    # Create or change password for each test user.
    for my $type (keys %TEST_USERS) {
        my $userid = $TEST_USERS{$type}{username};
        my $pass;
        my $result = remctl($USERINFO, 0, '', 'kadmin', 'examine', $userid);
        if ($result->stdout =~ m{error: No such entry in the database}) {
            $pass = _user_create($userid);
        } else {
            $pass = _user_passwd($userid);
        }
        $TEST_USERS{$type}{password} = $pass;
    }

    # Set up a list for the weak user.
    my $userid = $TEST_USERS{low_multifactor}{username};
    my %args = (username  => $userid,
                requestor => 'a',
                name      => 'WebKDC test list');
    my $json_obj = JSON->new;
    my $json_request = $json_obj->encode(\%args);
    my $result = remctl($USERINFO, 0, '', 'two-step', 'token', 'create',
                        'list', $json_request);
    if ($result->status != 0) {
        die "could not set multifactor for $userid: ", $result->stderr,
            "\n";
    }
    my $output = $json_obj->decode($result->stdout);
    if ($output->{response}{list}) {
        $TEST_USERS{low_multifactor}{otps} = $output->{response}{list};
    } else {
        die "did not get a multifactor list for $userid\n";
    }

    # Set up an authenticator for the high-profile user.
    $userid = $TEST_USERS{high_multifactor}{username};
    %args = (username  => $userid,
             requestor => 'a',
             name      => 'WebKDC test authenticator');
    $json_request = $json_obj->encode(\%args);
    $result = remctl($USERINFO, 0, '', 'two-step', 'token', 'create',
                     'authenticator', $json_request);
    if ($result->status != 0) {
        die "could not set multifactor for $userid: ", $result->stderr,
            "\n";
    }
    $output = $json_obj->decode($result->stdout);
    if ($output->{response}{hex_key}) {
        $TEST_USERS{high_multifactor}{key} = $output->{response}{hex_key};
    } else {
        die "did not get a multifactor token for $userid\n";
    }
}

# Remove Kerberos and multifactor information for each user.
sub teardown_users {

    for my $type (keys %TEST_USERS) {
        my $userid = $TEST_USERS{$type}{username};

        # Delete the multifactor configuration.
        my %args = (username  => $userid,
                    requestor => 'a',
                   );

        my $json_obj = JSON->new;
        my $json_request = $json_obj->encode(\%args);
        my $result = remctl($USERINFO, 0, '', 'two-step', 'purge',
                            $json_request);
        if ($result->status != 0) {
            die "could not delete multifactor for $userid: ",
                $result->stderr, "\n";
        }

        # Delete the Kerberos principal.
        $result = remctl($USERINFO, 0, '', 'kadmin', 'delete', $userid);
        if ($result->status != 0) {
            warn "could not remove kerberos for $userid\n";
        }
    }
}

#############################################################################
# Login/logout
#############################################################################

# Function to log out of the site by hitting the logout URL and deleting all
# cookies, to reset things between tests.
sub logout {
    my ($mech) = @_;
    return WWW::Mechanize->new;
}

# Function to log in via WebAuth, to pull the repetitive code into one place.
#
# Returns: 1 if we had to go through multifactor
#          0 if we did not
sub login {
    my ($mech, $url, $type) = @_;

    my $username = $TEST_USERS{$type}{username};
    my $password = $TEST_USERS{$type}{password};

    # Get the response from hitting the requested page.  This should be a
    # login form, but if we don't manage to bury cookies it might be the
    # end form.  If that's true, warn so that this can be looked at, but
    # return the mechanism to continue testing.
    $mech->get($url);
    my $login_form = $mech->form_name('login');
    ok(defined $login_form, "Login form for $url is found");

    # Log into the WebAuth site.  Skip this if we were apparently already
    # logged in.
    my %args;
    if (defined $login_form) {
        my %args = (form_name => 'login',
                    fields    => {
                        username => $username,
                        password => $password,
                    },
                    button    => 'Submit',
                   );
        $mech->submit_form(%args);
    }

    #print $mech->content;

    # Go through the multifactor login page if it exists.
    $login_form = $mech->form_name('login');
    if (defined $login_form) {
        my $otp = _get_otp($type);
        %args = (form_number => 1,
                 fields    => { otp => $otp },
                 button    => 'Submit',
                );
        $mech->submit_form(%args);
        return 1;
    } else {
        return 0;
    }
}

# Function to log in via WebAuth, to pull the repetitive code into one place.
#
# Returns: 1 if we had to go through multifactor
#          0 if we did not
sub login_success {
    my ($mech, $url, $type) = @_;

    my $username = $TEST_USERS{$type}{username};
    my $mf = login($mech, $url, $type);

    # Check to see if we have the standard content that should be on every
    # post-login page.
    like($mech->content,
         qr{You \s+ are \s+ accessing \s+ a \s+ webauth-protected
         \s+ page \s+ as \s+ the \s+ user: \s+ $username\b}xms,
         '... and login succeeded');

    return $mf;
}

# Function to log in via WebAuth, but end up on an insufficient privileges
# page.  This is called by other functions that do the actual checking
# against the type of insufficient privileges.
sub login_insufficient {
    my ($mech, $url, $type) = @_;

    my $username = $TEST_USERS{$type}{username};
    my $password = $TEST_USERS{$type}{password};
    my $mf = login($mech, $url, $type);

    is($mf, 0,
       '... and no multifactor login for having no sufficient factors');
}

# Tests logging in with insufficient level of assurance.
sub login_insufficient_loa {
    my ($mech, $url, $type) = @_;

    login_insufficient($mech, $url, $type);

    # Check to see if we have the standard content that should be on every
    # post-login page.
    like($mech->content,
         qr{The \s+ destination \s+ site \s+ requires \s+ a \s+ higher \s+ level \s+ of \s+ assurance \s+ than \s+ you \s+ have \s+ set \s+ up..}xms,
         '... and login succeeded');
}

# Tests logging in with insufficient factor.
sub login_insufficient_factor {
    my ($mech, $url, $type) = @_;

    login_insufficient($mech, $url, $type);

    # Check to see if we have the standard content that should be on every
    # post-login page.
    like($mech->content,
         qr{Two-step authentication method not strong enough.},
         '... and login succeeded');
}

# Function to hit a page and just get the response, without trying to log in
sub nologin {
    my ($mech, $url, $type) = @_;

    my $username = $TEST_USERS{$type}{username};

    # Get the response from hitting the requested page.  This should be a
    # login form, but if we don't manage to bury cookies it might be the
    # end form.  If that's true, warn so that this can be looked at, but
    # return the mechanism to continue testing.
    $mech->get($url);
    my $login_form = $mech->form_name('login');
    ok(!defined $login_form, "Login form for $url is not required");

    # Check to see if we have the standard content that should be on every
    # post-login page.
    like($mech->content,
         qr{You \s+ are \s+ accessing \s+ a \s+ webauth-protected
         \s+ page \s+ as \s+ the \s+ user: \s+ $username\b}xms,
         '... and login succeeded');

}

1;

__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

name - description

=head1 SYNOPSIS

B<name> [B<-h>] [B<--manual>]

=head1 DESCRIPTION

Description here.

=head1 OPTIONS

=over 4

=item B<-h>, B<--help>

Prints a short command summary for the script.

=item B<--manual>, B<--man>

Prints the perldoc information (this document) for the script.

=back

=head1 AUTHORS

Jon Robertson <jonrober@stanford.edu>

=cut
