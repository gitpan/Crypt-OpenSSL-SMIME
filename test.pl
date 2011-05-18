# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)
use strict;
use vars qw/$loaded/;

BEGIN { $| = 1; print "1..5\n";}
END {print "not ok 1\n" unless $loaded;}

use Crypt::OpenSSL::SMIME;
use UNIVERMAG::Keys;

$loaded = 1;
print "ok 1\n";

{
      my $aaa = new Crypt::OpenSSL::SMIME({
                  From                => 'univermag-encryption-service@yasp.com',
                  rootCA              => 'Cert/ca.crt',
                  signerfile          => 'Cert/univermag.crt',
                  signer_key_file     => 'Cert/univermag.key',
                  pass_for_root_CA    => $KEYS_P{root_CA},
                  pass_for_signer_key => $KEYS_P{univermag},
                  outfile             => 'result.txt',
            });

        if ($aaa->failed()) {
            print 'Failed to create object Crypt::OpenSSL::SMIME';
            exit 0;
        }
        print "ok 2\n";

        if ($aaa->loadDataFile('Data/2.txt')) {
           print "ok 3\n";
        } else {
           print "Failed to load file Data/2.txt\n";
           exit 0;
        }

        
        if ($aaa->encryptData('Cert/max.crt', 'max@yasp.com', 'Here is Your Invoice')) {
           print "ok 4\n";
        } else {
           print "Failed to create encrypted file result.txt\n";
           exit 0;
        }

        #if ($aaa->encryptData('Cert/dima.crt', 'dima@yasp.com', 'Here is Your Invoice')) {
        #  print "ok 5\n";
        #} else {
        #   print "Failed to create encrypted file result.txt\n";
        #   exit 0;
        #}

}

print "done\n";
