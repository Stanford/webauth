package WebKDC::XmlElement;

use strict;
use warnings;

use XML::Parser;

#use overload '""' => \&to_string;

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

sub convert_tree {
    my ($doc, $tree) = @_;
    $doc->attrs(shift @$tree);
    my ($element, $content);

    while (defined($element = shift @$tree)) {
	$content = shift @$tree;
	if ($element eq '0') {
	    $doc->append_content($content) if $content ne '';
	} elsif (ref $content eq 'ARRAY') {
	    my $child = new WebKDC::XmlElement;
	    $child->name($element);
	    convert_tree($child, $content);
	    $doc->add_child($child);
	} else {
	    die "convert tree error";
	}
    }
};

sub new {
    my $type = shift;
    my $self = { 'attrs' => {}, 'children' => []};
    bless $self, $type;
    if (@_) {
	my $xml = shift;
	my $parser = new XML::Parser(Style => 'Tree');
	my $tree = $parser->parse($xml);
	$self->name(shift @$tree);
	convert_tree($self, shift @$tree);
    }
    return $self;
}

sub name {
    my $self = shift;
    $self->{'name'} = shift if @_;
    return $self->{'name'};
}

sub attrs {
    my $self = shift;
    $self->{'attrs'} = shift if @_;
    return $self->{'attrs'};
}

sub content {
    my $self = shift;
    $self->{'content'} = shift if @_;
    return $self->{'content'};
}

sub append_content {
    my $self = shift;
    $self->{'content'} .= shift if @_;
}

sub has_attrs {
    my $self = shift;
    return %{$self->{'attrs'}};
}

sub attr {
    my $self = shift;
    my $name = shift;
    $self->{'attrs'}{$name} = shift if @_;
    return $self->{'attrs'}{$name};
}

sub children {
    my $self = shift;
    $self->{'children'} = shift if @_;
    return $self->{'children'};
}

sub has_children {
    my $self = shift;
    return $#{$self->{'children'}} != -1;
}

sub add_child {
    my $self = shift;
    push @{$self->{'children'}}, shift;
}


sub escape {
    my $v = shift;
    $$v =~ s/&/&amp;/sg;
    $$v =~ s/</&lt;/sg;
    $$v =~ s/>/&gt;/sg;
    $$v =~ s/\"/&quot;/sg;
    $$v =~ s/\'/&apos;/sg;
}

sub recursive_to_string {
    my ($e, $out, $pretty, $level) = @_;
    my $name = $e->name;
    my $closed = 0;
    $$out .= ' ' x $level if $pretty;
    $$out .= "<$name";
    while (my($attr,$val) = each(%{$e->attrs})) {
	escape(\$val);
	$$out .= " $attr=\"$val\"";
    }
    my $child;
    foreach $child (@{$e->children}) {
	    if (!$closed) {
		$$out .= ">";
		$$out .= "\n" if $pretty;
		$closed=1;
	    }
	    recursive_to_string($child, $out, $pretty, $level+2);
	}
    
    if (defined($e->content)) {
	if (!$closed) {
	    $$out .= ">";
	    $$out .= "\n" if $pretty;
	    $closed=1;
	}
	my $c = $e->content;
	escape(\$c);
	$$out .= ' ' x ($level+2) if $pretty;
	$$out .= $c;
	$$out .= "\n" if $pretty;
    }
    if ($closed) {
	$$out .= ' ' x $level if $pretty;
	$$out .= "</$name>";
	$$out .= "\n" if $pretty;
    } else {
	$$out .= "/>";
	$$out .= "\n" if $pretty;
    }
}

sub to_string {
    my $self = shift;
    my $pretty = shift;
    my $output;
    recursive_to_string($self, \$output, $pretty, 0);
    return $output;
}

1;
