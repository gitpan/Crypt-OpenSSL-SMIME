# U N I V E R M A G  2 
# Web Application Engine
# Property representation for Univermag 2
# Copyright 1999-2001 by YASP Software Ltd.
# $Id: SMIME.pm,v 1.1.2.1 2003/02/12 11:02:14 dima Exp $
# 
# [% TAGS #% %# %]


package Crypt::OpenSSL::SMIME;

=head1 NAME

Crypt::OpenSSL::SMIME - signing and encrypting messages with S/MIME standard using OpenSSL libraries.

=head1 SYNOPSIS

use Crypt::OpenSSL::SMIME;

 $smime = new Crypt::OpenSSL::SMIME({
   signer_mail     => 'sender@test.com',
   signer_cert     => 'sender.crt',
   signer_key     => 'sender.key',
   signer_key_pass => 'mysecurepassword',
   outfile             => 'MailEncrypted.txt'
 });
			
$smime->loadDataFile('MailForSend.txt');

$smime->encryptData('recipient.crt', 'recipient@test.com', 'Subject text');

=head1 DESCRIPTION

Crypt::OpenSSL::SMIME is a brain dead minimalistic not yet secure for use by 
paranoid people wrapper around OpenSSL library which was extremely useful 
for us at YASP Software Ltd to send sensitive information to Outlook and Mozilla
mailboxes and requires NO additional support from the mail reader software
to decrypt messages unlike PGP.

Ok, here is clear and long description.

It is minimalistic becouse it does sign and encrypt operations in one go. No flexibility (yet).

It is not yet secure for paranoid people becouse it creates outputfile. On first go this file will
contain signed message. I.e. original message in clear text and signature appended. On second go
this file will be overwritten with encrypted one. So bad boy has a couple of milliseconds to read
unencrypted data from disk. I know i am paranoid but the question is: am I paranoid enough ?
We are working on the next version which will be secure even for paranoid users. 

It is extremely useful becouse allow to encrypt mail messages with S/MIME standard with 4
lines of Perl code. Mail reading software like Mozilla and Outlook have builtin support for this
standard unlike PGP. Recipient will need to install his certificate though. Which is proven to be
simple step even for dumb people. If you managed to run your own CA recipient will probably 
want your root CA certificate as weel. I hope i used well known words here.

=head1 Class Methods

=over

=item I<new> hashref
 
Takes reference to hash as parameter. Probably not good idea though.
Hash keys:

 signer_mail - email address of the sender (From: )
 signer_cert - filename with sender certificate file
 signer_key - filename with sender key file 
 signer_key_pass - password for sender key
 outfile - filename to store signed and encrypted message
	
=item I<loadDataFile> filename

 filename - filename with original message

Note: we are not yet support attachements. At least we did not tested it.

=item I<encryptData> recipient_cert, recipient_email, subject

 recipient_cert - filename with recipient certificte
 recipient_email - recipient email
 subject - Subject: for email

=back

=head1 COPYRIGHT

Copyright (c) 2003 YASP Software Ltd.
http://www.yasp.com/
All Rights Reserved.

Distribution and use of this module is under the same terms as the
OpenSSL package itself (i.e. free, but mandatory attribution; NO
WARRANTY). Please consult LICENSE file in the root of the OpenSSL
distribution.

And remember, you, and nobody else but you, are responsible for
auditing this module and OpenSSL library for security problems,
backdoors, and general suitability for your application.

=cut

use strict;

use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);

$VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Crypt::OpenSSL::SMIME macro $constname";
	}
    }
    no strict 'refs';
    *$AUTOLOAD = sub () { $val };
    goto &$AUTOLOAD;
}

bootstrap Crypt::OpenSSL::SMIME $VERSION;

sub init {
    my $self = shift;
    #print "$self " , $self->{prop_altid}, "\n";
}

1;

=head1 SEE ALSO

  <http://www.openssl.org/>                - OpenSSL source, documentation, etc
  openssl-users-request@openssl.org        - General OpenSSL mailing list

=cut


=head1 AUTHORS

Dmitry Dorofeev I<dima somewhere inside yasp point com> original C code to show that S/MIME is really simple with OpenSSL
and author of this POD text

Max Rozanov I<max somewhere inside yasp point com> XS hacker who made all hard work to convert C code into Perl Modiule

Artem Marchenko I<tema somewhere inside yasp point com> Who made test suite.

Please send bug reports to dima-smime somewhere inside yasp point or dot com

=cut

__END__
