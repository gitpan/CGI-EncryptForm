

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..11\n"; }
END {print "not ok 1\n" unless $loaded;}

use CGI::EncryptForm;
$loaded = 1;
print "ok 1\n";

{
    my $stuff = {x => 'fjfi3jfo34f2F$RG$%Gerfghjwifu3d34dij43djd4d4d'};
		my $secret_key = 'ewdi34jfwqE';
    my $cfo;
		my $enc;
		my $hash = {};

		if (($cfo = new CGI::EncryptForm()) != -1) {
        print "ok 2\n";
		}
		else {
				print "not ok 2";
    }
    if ($cfo->secret_key($secret_key) != -1) {
        print "ok 3\n";
		}
    else {
				print "not ok 3\n";
    }    
    if ($cfo->autoescape(1) != -1) {
        print "ok 4\n";
		}
    else {
				print "not ok 4\n";
    }    
    if (($enc = $cfo->encrypt($stuff)) != -1) {
        print "ok 5\n";
		}
    else {
				print "not ok 5\n";
    }    
    if ((($hash = $cfo->decrypt($enc)) != -1) && $hash->{x} eq $stuff->{x}) {
        print "ok 6\n";
		}
    else {
				print "not ok 6\n";
    }    
		$cfo->secret_key('wrong key');
    if ($cfo->decrypt($enc) ne $stuff) {
        print "ok 7\n";
		}
    else {
				print "not ok 7\n";
		}
		if (($xx = $cfo->encrypt({ a => b, c => d })) != -1) {
			print "ok 8\n";
		}
		else {
			print "not ok 8\n";
		}
		if ($cfo->decrypt('') == -1) {
			print "ok 9\n";
		}
		else {
			print "not ok 9\n";
		}
		if ($cfo->decrypt(' ') == -1) {
			print "ok 10\n";
		}
		else {
			print "not ok 10\n";
		}
		if ($cfo->decrypt('354543564,edewD$#D$Dewd') == -1) {
			print "ok 11\n";
		}
		else {
			print "not ok 11\n";
		}

}


