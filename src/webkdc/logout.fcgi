#!/usr/local/bin/perl

#--------------------------------------------------------------------------
# File   : Weblogin logout
# Author : Jeanmarie Lucker
# Date   : Feb 10, 2003
#
# Destroy all webauth_wpt cookies
#
#--------------------------------------------------------------------------
$ENV{HTML_TEMPLATE_ROOT} = '/chroot/web/webkdc/templates';
%PAGES = ('logout' => 'logout.tmpl');

use strict;
use CGI::Fast qw(-compile);
use CGI::Cookie;
use HTML::Template;
use vars qw(%PAGES);

sub get_cookie_values {  
    my($cookies) = @_;
    my $n;

    while ( my ($name,$value) = each(%$cookies))
    {
         my @fields = split(/;/,$value);
         ($n,$$cookies{$name}) = split(/=/,$fields[0]);
	 #print STDERR "cookie is $name\n";
    }
}
###############################################
# Main
###############################################

%PAGES = map { $_ => HTML::Template->new (filename => $PAGES{$_},cache => 1) } (keys %PAGES);

while (my $q = new CGI::Fast) {

    my %cookies = fetch CGI::Cookie;
    my $num_cookies = (keys(%cookies));
#     print STDERR "***********the number of cookies is $num_cookies\n";
#     print STDERR "the env http cookies are$ENV{HTTP_COOKIE}\n";
#     print STDERR "the env cookies are$ENV{COOKIE}\n";
  
    my $ca;

    foreach my $key (sort(keys(%cookies))) {
	#print STDERR "$key = $cookies{$key}\n";
 	if ($key=~/^webauth_wpt/) {
 	    my ($name, $val) = split('=', $cookies{$key});
 	    push(@$ca, $q->cookie(-name => $name, -value => '', 
				  -expires=> '-1d', -secure => 'yes'));


 	    print STDERR "*****found a cookie to delete ($name)\n";
 	 }
    }	


#    get_cookie_values(\%cookies);

    if ($ca) {
	print STDERR"In ca\n";
	$PAGES{logout}->param ('cookies_flag'   => 1);
	print $q->header(-type => 'text/html', -cookie => $ca);
    }else {
	print $q->header(-type => 'text/html');
    }
	 print $PAGES{'logout'}->output
}continue  { 
    # Clear out the template parameters for the next run.
    foreach (keys %PAGES) {
        $PAGES{$_}->clear_params ();
    }
#exit if -M $ENV{SCRIPT_FILENAME} < 0;

}

