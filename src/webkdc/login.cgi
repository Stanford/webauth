#!/usr/pubsw/bin/perl

use strict;
use warnings;

#use lib '../bindings/perl/WebAuth/blib/lib';
#use lib '../bindings/perl/WebAuth/blib/arch/auto/WebAuth';

use WebAuth qw(:base64 :const :krb5 :key);
use WebKDC;
use WebKDC::WebKDCException;

use CGI qw/:standard/;
use Dumpvalue;

sub dump_stuff {
    my ($var, $val);
    foreach $var (sort(keys(%ENV))) {
	$val = $ENV{$var};
	$val =~ s|\n|\\n|g;
	$val =~ s|"|\\"|g;
	print "${var}=\"${val}\"\n";
    }
    
    print "\n";
    print "\n";
    while(<STDIN>) {
	print "INPUT: $_";
    }
}

sub print_headers {
    my ($q, $cookies) = @_;
    my $ca;

    if ($cookies) {
	while (my($name, $value) = each(%{$cookies})) {
	    push(@$ca, $q->cookie(-name => $name, -value => $value));
	}
    }

    if ($ca) {
	print $q->header(-type => 'text/html', -cookie => $ca);
    } else {
	print $q->header(-type => 'text/html');
    }
}

sub cancel_page {
    my $q = shift;

    print $q->header(-type => 'text/html');

    print << 'EOF';

<HTML>
  <HEAD>
    <HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
    <TITLE>Weblogin Canceled</TITLE>
  </HEAD>

  <BODY bgcolor="#FFFFFF">
    <HR>
    <TABLE border="0">
      <TR>
        <TD rowspan="5">
          <IMG src="/webkdc/quad.gif" alt="[Stanford Quad]">
        </TD>
        <TH colspan="3" align="center">
          <H2>Weblogin Canceled</h2>
        </TH>
      </TR>
    </TABLE>
    
    <HR size="2">
    
    <H4 align="center">
      Help for this page
    </H4>
    <P>
      On the previous Web page, you were asked to identify yourself with
      your SUNet ID and password. You chose to Cancel.
    </P>
  </BODY>

  <HEAD>
    <HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
  </HEAD>
</HTML>

EOF

}

sub login_form {
    my ($q, $resp, $RT, $ST,) = @_;

    print_headers($q, $resp->proxy_cookies);

    print $q->Dump;

    print << "EOF";

    <hr>
    <FORM method="POST" autocomplete="OFF" action="/login"
          enctype="application/x-www-form-urlencoded">

      <TABLE border="0">
        <TR>
          <TD rowspan="5"><IMG src="/webkdc/quad.gif" alt="[Stanford Quad]"></TD>
          <TH colspan="3" align="center">
            <font size="+3">SUNet ID Login</font>
          </TH>
        </TR>
        <TR>
          <TH align="right">
            Enter your SUNet ID:
          </TH>
          <TD colspan="2">
            <INPUT type="text" name="username" value=""
                   maxlength="30" size="16">
          </TD>
        </TR>
        <TR>
          <TH align="right">Enter your password:</TH>
          <TD>
            <INPUT type="password" name="password" size="16">
          </TD>
        </TR>
        <TR>
          <TD>
          </TD>
          <TD>
            <INPUT type="submit" name="submit" value="Continue">
          </TD>
          <TD align="right">
            <INPUT type="submit" name="submit" value="Cancel">
          </TD>
        </TR>
      </TABLE>

      <INPUT type="hidden" name="RT" value="$RT">
      <INPUT type="hidden" name="ST" value="$ST">
    </FORM> 
    <hr>
EOF
exit(1);
}

my $q = new CGI;

my $request_token_str = $q->param('RT');
my $service_token_str = $q->param('ST');
my $submit = $q->param('submit');


if ($submit eq 'Cancel') {
    cancel_page($q);
    exit(1);
}

# need to convert spaces back to +'s if they hosed by url-encode/decode

$request_token_str =~ tr/ /+/;
$service_token_str =~ tr/ /+/;

my $username = $q->param('username');
my $password = $q->param('password');

my $req = new WebKDC::WebRequest;
my $resp = new WebKDC::WebResponse;

# if the user just submitted their username/password, include them
if ($username && $password && $submit eq 'Continue') {
    $req->user($username);
    $req->pass($password);
}

# pass in any proxy-tokens we have from a cookies
# i.e., enumerate through all cookies that start with webauth_pt
# and put them into a hash:
# $cookies = { "webauth_pt_krb5" => $cookie_value }

my $pt_krb5 = $q->cookie('webauth_pt_krb5');
$req->proxy_cookie('krb5', $pt_krb5) unless !$pt_krb5;

######$req->proxy_cookies($cookies);

# $req_token_str and $service_token_str would normally get
# passed in via query/post parameters

$req->request_token($request_token_str);
$req->service_token($service_token_str);

eval {
    WebKDC::handle_request_token($req, $resp);
};

if (WebKDC::WebKDCException::match($@, WK_ERR_LOGIN_FAILED)) {
    # need to prompt again, also need to limit number of times
    # we'll prompt
    # make sure to pass the request/service tokens in hidden fields
 print $q->header(-type => 'text/html');
print "$@\n";
    print "oops -- reprompt\n";

} elsif (WebKDC::WebKDCException::match($@, WK_ERR_USER_AND_PASS_REQUIRED)) {

    # this exception indicates someone requested an id-token
    # and either didn't have a proxy-token, or it was expired.
    # prompt the user for their username/password, making sure
    # to pass the request/service tokens in hidden fields
    
    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies
    login_form($q, $resp, $request_token_str, $service_token_str);;

} elsif ($@) {
    # something nasty happened
    # log $@, and display an error to the user that a system problem
    # has occurred and tell them to try again later

    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies
 print $q->header(-type => 'text/html');
print "$@\n";

    print "oops -- nasty\n";

} else {

    # everything went ok
    # $resp->return_url  will have the return_url for a redirect
    # FIXME: check post_url first?

    # also need to check $resp->proxy_cookies() to see if we have
    # to update any proxy cookies
    print_headers($q, $resp->proxy_cookies);
    print "ok!\n";
    my $return_url = $resp->return_url();
    $return_url .= "WEBAUTHR=".$resp->response_token();
    $return_url .= ";WEBAUTHS=".$resp->app_state() unless !$resp->app_state();
    print "click <a href=\"$return_url\">here</a> to return!\n";
}

exit(1);

print "---------------\n";
dump_stuff;
print "---------------\n";


my $params = $q->Vars;

my $dumper = new Dumpvalue;
$dumper->dumpValue($params);

print "---------------\n";

print $q->Dump;

print "---------------\n";

print $q->cookie('webauth_at'), "\n";

print "---------------\n";
