package WebKDC::Token;

use strict;
use warnings;

use WebAuth3 qw(:const :hex :token);
use WebKDC::WebKDCException;

use UNIVERSAL qw(isa);
use Carp;

use overload '""' => \&to_string;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;


our %ta_desc = 
    (
     &WA_TK_APP_STATE => 'app-state',
     &WA_TK_COMMAND => 'command',
     &WA_TK_CRED_DATA => 'cred-data',
     &WA_TK_CRED_TYPE => 'cred-type',
     &WA_TK_CREATION_TIME => 'creation-time',
     &WA_TK_ERROR_CODE => 'error-code',
     &WA_TK_ERROR_MESSAGE => 'error-message',
     &WA_TK_EXPIRATION_TIME => 'expiration-time',
     &WA_TK_SESSION_KEY => 'session-key',
     &WA_TK_LASTUSED_TIME => 'lastused-time',
     &WA_TK_PASSWORD => 'password',
     &WA_TK_PROXY_TYPE => 'proxy-type',
     &WA_TK_PROXY_DATA => 'proxy-data',
     &WA_TK_PROXY_SUBJECT => 'proxy-subject',
     &WA_TK_REQUEST_OPTIONS => 'request-options',
     &WA_TK_REQUESTED_TOKEN_TYPE => 'req-token-type',
     &WA_TK_RETURN_URL => 'return-url',
     &WA_TK_SUBJECT => 'subject',
     &WA_TK_SUBJECT_AUTH => 'subject-auth',
     &WA_TK_SUBJECT_AUTH_DATA => 'subject-auth-data',
     &WA_TK_TOKEN_TYPE => 'token-type',
     &WA_TK_USERNAME => 'username',
     &WA_TK_WEBKDC_TOKEN => 'webkdc-token',
     );	       

sub get_ta_desc($) {
    my $ta = shift;
    return $ta_desc{$ta} || $ta;
}

sub to_string {
    my ($self) = @_;
    my $attrs = $self->{'attrs'};
    my ($key, $tt, $val, $out);

    $tt = $$attrs{&WA_TK_TOKEN_TYPE};
    my $hf="-------------------- $tt token --------------------\n";
    $out = $hf;
    my $fmt = "%20s: %s\n";
    while (($key,$val) = each %$attrs) {
	if ($key eq WA_TK_CREATION_TIME ||
	    $key eq WA_TK_LASTUSED_TIME ||
	    $key eq WA_TK_EXPIRATION_TIME) {
	    $val = localtime(unpack("N", $val));
	} elsif ($key eq WA_TK_SESSION_KEY ||
		 $key eq WA_TK_CRED_DATA ||
		 $key eq WA_TK_APP_STATE ||
		 $key eq WA_TK_PROXY_DATA ||
		 $key eq WA_TK_SUBJECT_AUTH_DATA ||
		 $key eq WA_TK_WEBKDC_TOKEN) {
	    $val = hex_encode($val);
	}  elsif ($key eq WA_TK_PASSWORD) {
	    $val = "XXXXXXX";
	}
	$out .= sprintf($fmt, get_ta_desc($key), $val);
    }
    $out .= $hf;
    return $out;
}

sub to_token {
    my ($self, $key) = @_;
    $self->validate_token();
    return token_create($self->{'attrs'}, 0, $key);
}

sub new {
    my $type = shift;
    my $self = { "attrs" => {}};
    bless $self, $type;
    if (@_) {
	$self->init_from_token(@_);
    } else {
	$self->init();
    }
    return $self;
}

sub parse {
    my ($token, $key, $ttl) = @_;
    my $attrs = token_parse($token, $ttl, $key);
    my $tt = $$attrs{&WA_TK_TOKEN_TYPE};
    my $c;

    if    ($tt eq 'app')   { $c = 'WebKDC::AppToken'; }
    elsif ($tt eq 'id')    { $c = 'WebKDC::IdToken'; }
    elsif ($tt eq 'cred')    { $c = 'WebKDC::CredToken'; }
    elsif ($tt eq 'proxy') { $c = 'WebKDC::ProxyToken'; }
    elsif ($tt eq 'webkdc-proxy') { $c = 'WebKDC::WebKDCProxyToken'; }
    elsif ($tt eq 'req') { $c = 'WebKDC::RequestToken'; }
    elsif ($tt eq 'error') { $c = 'WebKDC::ErrorToken'; }
    elsif ($tt eq 'webkdc-service') { $c = 'WebKDC::WebKDCServiceToken'; }
    else { croak "unknown token type in WebKDC::Token::parse: $tt" }
    my $t = new $c;
    $t->{'attrs'} = $attrs;
    $t->validate_token();
    return $t;
}

sub init_from_token {
    my ($self, $token, $key, $ttl) = @_;
    $self->{'attrs'} = token_parse($token, $ttl, $key);
    $self->validate_token();
}

sub validate_token() {
    croak "someone didn't implement validate_token!";
}

sub init {
    croak "someone didn't implement init";
}

sub token_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_TOKEN_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_TOKEN_TYPE};
}

############################################################

package WebKDC::AppToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;


sub init {
    my $self = shift;
    $self->token_type('app');
}

sub session_key {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SESSION_KEY} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SESSION_KEY};    
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub lastused_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_LASTUSED_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_LASTUSED_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub app_data {
    my $self = shift;
    my $name = shift;
    $self->{'attrs'}{$name} = shift if @_;
    return $self->{'attrs'}{$name};
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'app') && 
	defined($self->expiration_time());
}

############################################################

package WebKDC::IdToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('id');
}

sub subject_auth {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT_AUTH} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT_AUTH};
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub subject_auth_data {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT_AUTH_DATA} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT_AUTH_DATA};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = 
	pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    # FIXME: add support for sa=webkdc as well
    croak "validate_token failed" unless
	($self->token_type() eq 'id') && 
	(($self->subject_auth() eq 'krb5' && 
	  defined($self->subject_auth_data())) ||
	 ($self->subject_auth() eq 'webkdc' &&
	  defined($self->subject()))) && 
	defined($self->creation_time()) &&
	defined($self->expiration_time());
}

############################################################

package WebKDC::LoginToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;


sub init {
    my $self = shift;
    $self->token_type('login');
}

sub username {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_USERNAME} = shift if @_;
    return $self->{'attrs'}{&WA_TK_USERNAME};
}

sub password {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PASSWORD} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PASSWORD};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}
sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'login') && 
	defined($self->username) && 
	defined($self->password);
}

############################################################

package WebKDC::ProxyToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('proxy');
}

sub proxy_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PROXY_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PROXY_TYPE};
}

sub webkdc_token {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_WEBKDC_TOKEN} = shift if @_;
    return $self->{'attrs'}{&WA_TK_WEBKDC_TOKEN};
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'proxy') && 
	($self->proxy_type() eq 'krb5') && 
	defined($self->webkdc_token()) &&
	defined($self->creation_time());
	defined($self->expiration_time());
}


############################################################

package WebKDC::CredToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('cred');
}

sub cred_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CRED_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_CRED_TYPE};
}

sub cred_data {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CRED_DATA} = shift if @_;
    return $self->{'attrs'}{&WA_TK_CRED_DATA};
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'cred') && 
	($self->cred_type() eq 'krb5') && 
	defined($self->cred_data()) &&
	defined($self->creation_time());
	defined($self->expiration_time());
}

############################################################


package WebKDC::WebKDCProxyToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('webkdc-proxy');
}

sub proxy_subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PROXY_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PROXY_SUBJECT};
}

sub proxy_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PROXY_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PROXY_TYPE};
}

sub proxy_data {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PROXY_DATA} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PROXY_DATA};
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'webkdc-proxy') && 
	($self->proxy_type() eq 'krb5') && 
	defined($self->proxy_subject()) &&
	defined($self->proxy_data()) &&
	defined($self->creation_time());
	defined($self->expiration_time());
}

############################################################

package WebKDC::RequestToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('req');
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub app_state {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_APP_STATE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_APP_STATE};
}


sub subject_auth {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT_AUTH} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT_AUTH};
}

sub request_options {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_REQUEST_OPTIONS} = shift if @_;
    return $self->{'attrs'}{&WA_TK_REQUEST_OPTIONS};
}

sub requested_token_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_REQUESTED_TOKEN_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_REQUESTED_TOKEN_TYPE};
}

sub proxy_type {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_PROXY_TYPE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_PROXY_TYPE};
}

sub return_url {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_RETURN_URL} = shift if @_;
    return $self->{'attrs'}{&WA_TK_RETURN_URL};
}

sub command {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_COMMAND} = shift if @_;
    return $self->{'attrs'}{&WA_TK_COMMAND};
}

sub validate_token {
    my $self = shift;

    # FIXME: more checks for request_options, req_token_type (sa/prt)
    croak "validate_token failed" unless
	($self->token_type() eq 'req') && 
	defined($self->creation_time());

    if ($self->command()) {
	croak "validate_token failed" unless
	    $self->command() eq 'getTokensRequest';
    } else {
	croak "validate_token failed" unless
	    defined($self->return_url()) &&
	    ($self->requested_token_type() eq 'id') && 
	    ($self->subject_auth() eq 'krb5' ||
	     ($self->subject_auth() eq 'webkdc'));
    }
}

############################################################

package WebKDC::ErrorToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;
use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('error');
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub error_code {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_ERROR_CODE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_ERROR_CODE};
}

sub error_message {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_ERROR_MESSAGE} = shift if @_;
    return $self->{'attrs'}{&WA_TK_ERROR_MESSAGE};
}

sub validate_token {
    my $self = shift;

    croak "validate_token failed" unless
	($self->token_type() eq 'error') && 
	defined($self->creation_time()) &&
	defined($self->error_code()) &&
	defined($self->error_message());

}

############################################################

package WebKDC::WebKDCServiceToken;

use strict;
use warnings;

use WebAuth3 qw(:const);
use WebKDC::Token;

use Carp;

BEGIN {
    use Exporter   ();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 1.00;
    @ISA         = qw(Exporter WebKDC::Token);
    @EXPORT      = qw();
    %EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

    # your exported package globals go here,
    # as well as any optionally exported functions
    @EXPORT_OK   = qw();
}

our @EXPORT_OK;

sub init {
    my $self = shift;
    $self->token_type('webkdc-service');
}

sub session_key {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SESSION_KEY} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SESSION_KEY};    
}

sub subject {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_SUBJECT} = shift if @_;
    return $self->{'attrs'}{&WA_TK_SUBJECT};
}

sub creation_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_CREATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_CREATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub expiration_time {
    my $self = shift;
    $self->{'attrs'}{&WA_TK_EXPIRATION_TIME} = pack("N", shift) if @_;
    my $time = $self->{'attrs'}{&WA_TK_EXPIRATION_TIME};
    if (defined($time)) {
	return unpack('N', $time);
    } else {
	return $time;
    }
}

sub validate_token {
    my $self = shift;

    croak "validate_webkdc-service token failed" unless
	($self->token_type() eq 'webkdc-service') && 
	defined($self->session_key()) &&
	defined($self->subject()) &&
	defined($self->creation_time()) &&
	defined($self->expiration_time());
}

1;

__END__

=head1 NAME

WebKDC::Token - token objects for use with WebAuth

=head1 SYNOPSIS

  use WebKDC::Token;
  # includes WebKDC::{App,Id,Proxy,Request,Response,Service}Token

  # manually create a new token, and then encode/encrypt it
  my $id_token = new WebKDC::Token;

  $id_token->subject_auth('krb5');
  $id_token->subject_auth_data($sad);
  $id_token->creation_time(time());
  $id_token->subject_expiration_time($et);

  my $id_token_str = bas64_encode($id_token->to_token($key));

  # parse an encrypted/encoded token
  my $req_token = new WebKDC::RequestToken($req_token_str, $key, $ttl, 1);

=head1 DESCRIPTION

WebKDC::Token is the base class for all the Token objects, which are
available upon using WebKDC::Token:

 WebKDC::AppToken
 WebKDC::IdToken
 WebKDC::ProxyToken
 WebKDC::RequestToken
 WebKDC::ErrorToken
 WebKDC::CredToken
 WebKDC::WebKDCProxyToken
 WebKDC::WebKDCServiceToken

It contains the functions that are common across all the token objects,
as well as some functions that must be overridden in the subclasses.

=head1 EXPORT

None

=head1 METHODS

=over 4

=item to_token(key_or_keyring)

$binary_token = $token->to_token($key_or_keyring);

Takes a token object and encrypts/encodes it into a binary string.
WebAuth3::base64_encode should be used if the token needs to base64 encoded.

=item to_string()

$str = $token->to_string();

used mainly for debugging to get a dump of all the attributes in a
token. The Token object all overloads '""', so calling this function
is optional, you can just use a token object as a string to get
the same result.

=item new

 $token = new WebKDC::SubclassToken;
 $token = new WebKDC::SubclassToken($binary_token, $key_or_ring, $ttl);

The new constructor for tokcns is used to create a token object. The
first form is used to construct new tokens, while the second form
is used to parse a binary token into a token object. Note, only
subclasses of Token should be constructed using new. To parse an
unknown token, use the parse class method.

=item parse

 $token = WebKDC::Token::parse($binary_token, $key_or_ring, $ttl);

Used to create a from a binary token when you don't know ahead
of time what the resulting token type will be. The type of
the returened token can be checked with token_type() or the
UNIVERSAL isa method.

=item validate_token

This method should be overridden by subclasses. It is used
to validate that a particular token contains the correct
attributes. It gets called by the to_token method before the token
is encoded, and by the constructor with args after a token has been parsed.

=item init

This method should be ovveridden by subclasses and is used to
initialize a token when the constructor with no args is called.

=item token_type([$new_value])

 $token->token_type($new_value);
 $type = $token->token_type();

The first form is used to set the token type, the second form
is used to get the token type.

=back

=head1 WebKDC::AppToken

The WebKDC::AppToken object is used to represent WebAuth app-tokens.

  $token = new WebKDC::AppToken;
  $token = new WebKDC::AppToken($binary_token, $key_or_ring, $ttl);

  $token->app_data($name[, $new_value])
  $token->creation_time([$new_value])
  $token->expiration_time([$new_value])
  $token->lastused_time([$lastused_time])
  $token->subject([$new_value])

=head1 WebKDC::CredToken

The WebKDC::CredToken object is used to represent WebAuth cred-tokens.

  $token = new WebKDC::CredToken;
  $token = new WebKDC::CredToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->expiration_time([$new_value])
  $token->cred_type([$new_value])
  $token->cred_data([$new_value])
  $token->subject([$new_value])

=head1 WebKDC::IdToken

The WebKDC::IdToken object is used to represent WebAuth id-tokens.

  $token = new WebKDC::IDToken;
  $token = new WebKDC::IdToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->subject([$new_value])
  $token->subject_auth([$new_value])
  $token->subject_auth_data([$new_value])
  $token->subject_expiration_time([$new_value])

=head1 WebKDC::LoginToken

The WebKDC::LoginToken object is used to represent WebAuth login-tokens.

  $token = new WebKDC::LoginToken;
  $token = new WebKDC::LoginToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->password([$new_value])
  $token->username([$new_value])

=head1 WebKDC::ProxyToken

The WebKDC::ProxyToken object is used to represent WebAuth proxy-tokens.

  $token = new WebKDC::ProxyToken;
  $token = new WebKDC::ProxyToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->expiration_time([$new_value])
  $token->proxy_type([$new_value])
  $token->subject([$new_value])
  $token->webkdc_token([$new_value])

=head1 WebKDC::RequestToken

The WebKDC::RequestToken object is used to represent WebAuth request-tokens.

  $token = new WebKDC::RequestToken;
  $token = new WebKDC::RequestToken($binary_token, $key_or_ring, $ttl);

  $token->app_state([$new_value])
  $token->creation_time([$new_value])
  $token->proxy_type([$new_value])
  $token->request_options([$new_value])
  $token->requested_token_type([$new_value])
  $token->return_url([$new_value])
  $token->subject_auth([$new_value])

=head1 WebKDC::ErrorToken

The WebKDC::ErrorToken object is used to represent WebAuth error-tokens.

  $token = new WebKDC::ErrorToken;
  $token = new WebKDC::ErrorToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->error_code([$new_value])
  $token->error_message([$new_value])

=head1 WebKDC::WebKDCProxyToken

The WebKDC::WebKDCProxyToken object is used to represent WebAuth 
webkdc-proxy-tokens.

  $token = new WebKDC::WebKDCProxyToken;
  $token = new WebKDC::WebKDCProxyToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->expiration_time([$new_value])
  $token->proxy_data([$new_value])
  $token->proxy_subject([$new_value])
  $token->proxy_type([$new_value])
  $token->subject([$new_value])

=head1 WebKDC::WebKDCServiceToken

The WebKDC::WebKDCServiceToken object is used to represent WebAuth 
webkdc-service-tokens.

  $token = new WebKDC::WebKDCServiceToken;
  $token = new WebKDC::WebKDCServiceToken($binary_token, $key_or_ring, $ttl);

  $token->creation_time([$new_value])
  $token->expiration_time([$new_value])
  $token->subject([$new_value])
  $token->session_key([$new_value])

=head1 AUTHOR

Roland Schemers (schemers@stanford.edu)

=head1 SEE ALSO

L<WebAuth3>.

=cut
