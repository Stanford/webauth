# Manipulate a document composed of WebKDC::XmlElement objects.
#
# Written by Roland Schemers
# Copyright 2002, 2009
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package WebKDC::XmlDoc;

use strict;
use warnings;

use WebKDC::XmlElement;

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

sub new {
    my $type = shift;
    my $self = {};
    bless $self, $type;
    return $self;
}

sub start {
    my $self = shift;
    my $name = shift;
    my $element = new WebKDC::XmlElement;
    $element->name($name);
    if (@_) {
	my $attrs = shift;
	$element->attrs($attrs) if defined($attrs);
    }
    if (@_) {
	$element->content(shift);
    }
    if (!defined($self->{'root'})) {
	$self->{'root'} = $element;
    } else {
	my $s = $self->{'stack'};
	my $parent = @{$s}[$#{$s}];
	$parent->add_child($element);
    }
    push(@{$self->{'stack'}}, $element);
    return $self;
}

sub current {
    my $self = shift;
    my $s = $self->{'stack'};
    my $e = @{$s}[$#{$s}] || die "not in an element";
    return $e;
}

sub end {
    my $self = shift;
    my $s = $self->{'stack'};
    my $e = @{$s}[$#{$s}] || die "not in an element";
    if (@_) {
	my $name = shift;
	my $aname = $e->name;
	if ($name ne $aname) {
	    die "name mismatch in end. expecting($name), actual($aname)";
	}
    }
    pop(@{$self->{'stack'}});
 }

sub add {
    my ($self, $name, $attrs, $text) = @_;
    $self->start($name, $attrs);
    $self->current->append_content($text) if defined($text);
    $self->end;
}

sub root {
    my $self = shift;
    return $self->{'root'};
}

1;

__END__
