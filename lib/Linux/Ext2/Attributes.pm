=head1 NAME

Linux::Ext2::Attributes - Manipulate Linux extended filesystem attributes.

=head1 SYNOPSIS

  use Linux::Ext2::Attributes qw(set_attrs :flags);
  
  set_attrs("somefile", "i");
  
  my $attribs = Linux::Ext2::Attributes->load("somefile");
  
  my $attribs_i = $attribs->flags;   # 16
  my $attribs_s = $attribs->string;  # "i"
  
  $attribs->set("-i");
  
  $attribs->save("somefile");

=head1 DESCRIPTION

Linux::Ext2::Attributes provides an object-oriented interface for manipulating
Linux extended filesystem attributes and a chattr-like function.

Only regular files/directories can have attributes.

=cut

package Linux::Ext2::Attributes;

use strict;
use warnings;

our $VERSION = "0.10";

use Scalar::Util qw(looks_like_number);
use Carp;
use Errno qw(ENOTTY);

use Exporter "import";

our @EXPORT_OK = qw(
	set_attrs
	
	EXT2_NOATIME_FL
	EXT2_APPEND_FL
	EXT2_COMPRBLK_FL
	EXT2_COMPR_FL
	EXT2_DIRSYNC_FL
	EXT2_NODUMP_FL
	EXT2_ECOMPR_FL
	EXT4_EXTENTS_FL
	EXT4_HUGE_FILE_FL
	EXT2_INDEX_FL
	EXT2_IMMUTABLE_FL
	EXT3_JOURNAL_DATA_FL
	EXT2_SECRM_FL
	EXT2_SYNC_FL
	EXT2_TOPDIR_FL
	EXT2_NOTAIL_FL
	EXT2_UNRM_FL
	EXT2_NOCOMP_FL
	EXT2_DIRTY_FL
	
	EXT2_READONLY_FLAGS
);

our %EXPORT_TAGS = (
	"flags" => [ qw(
		EXT2_NOATIME_FL
		EXT2_APPEND_FL
		EXT2_COMPRBLK_FL
		EXT2_COMPR_FL
		EXT2_DIRSYNC_FL
		EXT2_NODUMP_FL
		EXT2_ECOMPR_FL
		EXT4_EXTENTS_FL
		EXT4_HUGE_FILE_FL
		EXT2_INDEX_FL
		EXT2_IMMUTABLE_FL
		EXT3_JOURNAL_DATA_FL
		EXT2_SECRM_FL
		EXT2_SYNC_FL
		EXT2_TOPDIR_FL
		EXT2_NOTAIL_FL
		EXT2_UNRM_FL
		EXT2_NOCOMP_FL
		EXT2_DIRTY_FL
	) ]
);

# Flags collected from e2fsprogs and Linux headers
# See the e2fsprogs source/docs for more info.

use constant EXT2_NOATIME_FL      => 0x00000080; # A
use constant EXT2_APPEND_FL       => 0x00000020; # a
use constant EXT2_COMPRBLK_FL     => 0x00000200; # B
use constant EXT2_COMPR_FL        => 0x00000004; # c
use constant EXT2_DIRSYNC_FL      => 0x00010000; # D
use constant EXT2_NODUMP_FL       => 0x00000040; # d
use constant EXT2_ECOMPR_FL       => 0x00000800; # E
use constant EXT4_EXTENTS_FL      => 0x00080000; # e
use constant EXT4_HUGE_FILE_FL    => 0x00040000; # h
use constant EXT2_INDEX_FL        => 0x00001000; # I
use constant EXT2_IMMUTABLE_FL    => 0x00000010; # i
use constant EXT3_JOURNAL_DATA_FL => 0x00004000; # j
use constant EXT2_SECRM_FL        => 0x00000001; # s
use constant EXT2_SYNC_FL         => 0x00000008; # S
use constant EXT2_TOPDIR_FL       => 0x00020000; # T
use constant EXT2_NOTAIL_FL       => 0x00008000; # t
use constant EXT2_UNRM_FL         => 0x00000002; # u
use constant EXT2_NOCOMP_FL       => 0x00000400; # X
use constant EXT2_DIRTY_FL        => 0x00000100; # Z

# These flags may not be set or cleared by the user.

use constant EXT2_READONLY_FLAGS  => (EXT2_ECOMPR_FL | EXT4_EXTENTS_FL | EXT4_HUGE_FILE_FL | EXT2_INDEX_FL | EXT2_NOCOMP_FL | EXT2_DIRTY_FL);

my %flag_chars = (
	'A' => EXT2_NOATIME_FL,
	'a' => EXT2_APPEND_FL,
	'B' => EXT2_COMPRBLK_FL,
	'c' => EXT2_COMPR_FL,
	'D' => EXT2_DIRSYNC_FL,
	'd' => EXT2_NODUMP_FL,
	'E' => EXT2_ECOMPR_FL,
	'e' => EXT4_EXTENTS_FL,
	'h' => EXT4_HUGE_FILE_FL,
	'I' => EXT2_INDEX_FL,
	'i' => EXT2_IMMUTABLE_FL,
	'j' => EXT3_JOURNAL_DATA_FL,
	's' => EXT2_SECRM_FL,
	'S' => EXT2_SYNC_FL,
	'T' => EXT2_TOPDIR_FL,
	't' => EXT2_NOTAIL_FL,
	'u' => EXT2_UNRM_FL,
	'X' => EXT2_NOCOMP_FL,
	'Z' => EXT2_DIRTY_FL,
);

# ioctl numbers are different on 32/64-bit kernels.

use constant EXT2_IOC_GETFLAGS_32 => 0x80046601;
use constant EXT2_IOC_SETFLAGS_32 => 0x40046602;

use constant EXT2_IOC_GETFLAGS_64 => 0x80086601;
use constant EXT2_IOC_SETFLAGS_64 => 0x40086602;

sub _get_fh {
	my ($file) = @_;
	
	if(ref($file))
	{
		return $file;
	}
	
	open(my $fh, "<", $file) or return undef;
	
	return $fh;
}

sub _get_flags {
	my ($file) = @_;
	
	my $fh = _get_fh($file) or return undef;
	
	my $flags = pack("i", 0);
	
	if(!ioctl($fh, EXT2_IOC_GETFLAGS_32, $flags) && $!{ENOTTY} && !ioctl($fh, EXT2_IOC_GETFLAGS_64, $flags))
	{
		return undef;
	}
	
	return scalar unpack("i", $flags);
}

sub _set_flags {
	my ($file, $flags) = @_;
	
	$file = _get_fh($file) or return undef;
	
	$flags = pack("i", $flags);
	
	return ioctl($file, EXT2_IOC_SETFLAGS_32, $flags)
		|| ($!{ENOTTY} && ioctl($file, EXT2_IOC_SETFLAGS_64, $flags));
}

=head1 SUBROUTINES

=head2 set_attrs

  set_attrs($file, $attribs)
  set_attrs($file, EXT2_IMMUTABLE_FL | EXT2_NOATIME_FL)
  set_attrs($file, "iA")
  set_attrs($file, "-a+iA")

Set the attributes on a filename or open file. The attributes may be an instance
of Linux::Ext2::Attributes, an integer of bitwise OR'd flags or a string based
on the format used by the chattr program.

Not all attributes of a file may be changed. Any read-only attributes on a file
will remain unchanged.

Returns true on success, false on error.

=cut

sub set_attrs {
	my ($file, $attribs, $force) = @_;
	
	$file = _get_fh($file) or return undef;
	
	my $old_flags = _get_flags($file);
	
	if(!defined($old_flags))
	{
		return undef;
	}
	
	my $new_flags = __PACKAGE__->new($old_flags);
	$new_flags->set($attribs);
	
	if(!$force)
	{
		$new_flags->set(($old_flags & EXT2_READONLY_FLAGS) | $new_flags->strip->flags);
	}
	
	return _set_flags($file, $new_flags->flags);
}

=head1 METHODS

=head2 new

  my $attribs = Linux::Ext2::Attributes->new()
  my $attribs = Linux::Ext2::Attributes->new($value)

Return a new instance of Linux::Ext2::Attributes containing no flags or an
arbitrary set.

=cut

sub new {
	my ($class, $value) = @_;
	
	my $self = bless(\do { my $self = 0; }, $class);
	
	if(defined($value))
	{
		$self->set($value);
	}
	
	return $self;
}

=head2 load

  my $attribs = Linux::Ext2::Attributes->load("filename")
  my $attribs = Linux::Ext2::Attributes->load($filehandle)
  my $attribs = Linux::Ext2::Attributes->load(\*FILE)

Get the attributes of a filename or open file. Returns an instance of
Linux::Ext2::Attributes on success, undef on error.

=cut

sub load {
	my ($class, $file) = @_;
	
	my $flags = _get_flags($file);
	
	return defined($flags) ? bless(\$flags, $class) : undef;
}

=head2 save

  $attribs->save("filename")
  $attribs->save($filehandle)
  $attribs->save(\*FILE)

Set the attributes of a filename or open file. Returns true on success, false
on failure.

=cut

sub save {
	my ($self, $file) = @_;
	
	return set_attrs($file, $self);
}

=head2 set

  $attribs->set($attribs)
  $attribs->set(EXT2_IMMUTABLE_FL | EXT2_NOATIME_FL)
  $attribs->set("iA")
  $attribs->set("-a+iA")

Replace or modify the stored flags value. Takes the same attributes as set_attrs.

=cut

sub set {
	my ($self, $attribs) = @_;
	
	if(ref($attribs))
	{
		$$self = $$attribs;
	}
	elsif(looks_like_number($attribs))
	{
		$$self = $attribs;
	}
	elsif($attribs =~ m/\A=?([AaBcDdEehIijsSTtuXZ]*)\z/)
	{
		$$self = 0;
		
		$attribs =~ s/=//;
		
		foreach my $flag(split(//, $attribs))
		{
			$$self |= $flag_chars{$flag};
		}
	}
	elsif($attribs =~ m/\A([-+][AaBcDdEehIijsSTtuXZ]*)*\z/)
	{
		my $add = 0;
		
		foreach my $flag(split(//, $attribs))
		{
			if($flag eq "-")
			{
				$add = 0;
			}
			elsif($flag eq "+")
			{
				$add = 1;
			}
			else{
				if($add)
				{
					$$self |= $flag_chars{$flag};
				}
				else{
					$$self &= ~$flag_chars{$flag};
				}
			}
		}
	}
	else{
		carp("Unknown flags passed to set: '$attribs'");
	}
}

=head2 flags

  my $attribs_i = $attribs->flags()

Return the attributes as a bitwise OR'd integer (e.g. 148).

=cut

sub flags {
	my ($self) = @_;
	
	return $$self;
}

=head2 string

  my $attribs_s = $attribs->string()

Return the attributes as a string of characters (e.g. "icA").

=cut

sub string {
	my ($self) = @_;
	
	my $string = "";
	
	foreach my $flag(keys(%flag_chars))
	{
		if($$self & $flag_chars{$flag})
		{
			$string .= $flag;
		}
	}
	
	return $string;
}

=head2 strip

  $attribs->strip()

Unset any read-only/system flags and return self.

=cut

sub strip {
	my ($self) = @_;
	
	$$self &= ~EXT2_READONLY_FLAGS;
	
	return $self;
}

sub _do_flag {
	my ($self, $flag, $value) = @_;
	
	if(defined($value))
	{
		if($value)
		{
			$$self |= $flag;
		}
		else{
			$$self &= ~$flag;
		}
	}
	
	return ($$self & $flag) ? 1 : 0;
}

=head2 immutable

  $attribs->immutable()
  $attribs->immutable(true/false value)

Get and/or set the state of the immutable flag. Returns the current/new value.

=cut

sub immutable {
	my ($self, $value) = @_;
	
	return $self->_do_flag(EXT2_IMMUTABLE_FL, $value);
}

=head2 append_only

  $attribs->append_only()
  $attribs->append_only(true/false value)

Get and/or set the state of the append only flag. Returns the current/new value.

=cut

sub append_only {
	my ($self, $value) = @_;
	
	return $self->_do_flag(EXT2_APPEND_FL, $value);
}

=head2 flag

  $attribs->flag(EXT3_JOURNAL_DATA_FL)
  $attribs->flag("j", true/false value)

Get and/or set the state of an arbitrary flag. Returns the current/new value.

=cut

sub flag {
	my ($self, $flag, $value) = @_;
	
	if(!looks_like_number($flag))
	{
		if(!defined($flag_chars{$flag}))
		{
			carp("Unknown flag passed to flag: '$flag'");
			return undef;
		}
		
		$flag = $flag_chars{$flag};
	}
	
	return $self->_do_flag($flag, $value);
}

=head1 FLAGS

The following flag constants are defined and may be imported using the :flags
tag. Not all of them may be modified by the user or are currently implemented
in the Linux kernel. For more information see the chattr man page.

  EXT2_NOATIME_FL      (A) - Do not update atime on access.
  EXT2_APPEND_FL       (a) - File may only be appended to.
  EXT2_COMPRBLK_FL     (B) - One or more compressed clusters.
  EXT2_COMPR_FL        (c) - Compress file on disk.
  EXT2_DIRSYNC_FL      (D) - Directory changes are synchronous.
  EXT2_NODUMP_FL       (d) - Not backed up by dump.
  EXT2_ECOMPR_FL       (E) - Compression error.
  EXT4_EXTENTS_FL      (e) - File is using extents for block mapping.
  EXT4_HUGE_FILE_FL    (h) - File is (or was) larger than 2TB.
  EXT2_INDEX_FL        (I) - Directory is indexed using hashed trees.
  EXT2_IMMUTABLE_FL    (i) - File may not be modified.
  EXT3_JOURNAL_DATA_FL (j) - Journal file data as well as metadata.
  EXT2_SECRM_FL        (s) - File will be securely deleted when unlinked.
  EXT2_SYNC_FL         (S) - Changes to this file are written synchronously.
  EXT2_TOPDIR_FL       (T) - Directory is at the top of a hierarchy.
  EXT2_NOTAIL_FL       (t) - Disable tail merging.
  EXT2_UNRM_FL         (u) - Keep file for undeletion.
  EXT2_NOCOMP_FL       (X) - Don't compress file.
  EXT2_DIRTY_FL        (Z) - Compressed file is dirty.

=head1 BUGS

The ioctl numbers are hardcoded into the module as they're different under
32/64-bit kernels and both are tried.

=head1 AUTHOR

Daniel Collins, solemnwarning@solemnwarning.net

=cut

1;
