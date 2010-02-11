use 5.006;
use strict;
use warnings;

use inc::Module::Install;

name          ('HTTP-Sessioniser');
author        ('David Cannings <david@edeca.net>');
license       ('perl');
all_from      ('lib/HTTP/Sessioniser.pm');

#requires(URI => 1);
#requires(LWP => 5);
requires('IO::Compress::Gzip');

#requires('Compress::Zlib' => '1.20');
#requires('File::Path'     => '2.04'); # new interface, bugfixes
#requires('File::HomeDir'  => '0.57'); # Win32 Support
#requires('Pod::Usage'     => '1.00');

#extra_tests;

#install_script('bin/minicpan');

repository('http://github.com/edeca/HTTP-Sessioniser');
#auto_manifest;

WriteAll();
