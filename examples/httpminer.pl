#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;
use MIME::Base64;
use Time::Format;
use Text::CSV;
use HTTP::Sessioniser;
use URI;
use Digest::MD5 qw(md5_hex);

########
#   File: httpminer.pl
# Author: David <david@edeca.net>
#   Date: 27/Oct/2010
#
# This script is a simple example of using HTTP::Sessioniser to dump a list of 
# HTTP requests.  It is slightly cleverer than tshark/Wireshark or other tools as
# it can pair request data to response data, e.g. the response code.
#
# It reads a list of filenames from STDIN and outputs CSV, one row per request/response.
#
# As HTTP::Sessioniser requires Net::LibNIDS and the libnids C library, this
# might be limited to certain platforms.
########

# If the input is defined, return it.  If not, return empty string.
# Why call it es?  Why not!  ("empty string")
sub es($) {
	my $s = shift;
	defined($s) ? $s : "";
}

my $sessioniser = new HTTP::Sessioniser;
my $csv = Text::CSV->new({ 'quote_char' => "\"", 'escape_char' => "\\", 'always_quote' => 1 });

foreach (<STDIN>) {
	chomp $_;
 	my $filename = $_;
	my $data;

	print STDERR "[+] Processing [$filename]\n";
	
	# Process this file using HTTP::Sessioniser, passing results to
	# our callback
	$sessioniser->parse_file($filename, \&process_data);
}

# The callback function from HTTP::Sessioniser.
sub process_data($$) {
	my ($request, $response, $info) = @_;
	
	# $request is a HTTP::Request, $response is a HTTP::Response,
	# therefore we have access to all the methods that LWP exposes.

	# CSV output of request data, fields are:
	# request_time, client_ip, server_ip, method, url, url_hash, host, cookie, request_data, 
	# user_agent, referer, auth_basic, proxy_auth, capturefile	
	my @row;

	push @row, time_format('yyyy-mm-dd hh:mm:ss', $info->{request_time});
	push @row, $info->{client_ip};
	push @row, $info->{server_ip};
	push @row, es($request->method);
	push @row, es($request->uri);

	# This is the MD5 hash of the path and query string, which can 
	# uniquely identify a request to a specific page & parameters.
	# I use this as one index when putting results into a database.
	my $uri = URI->new($request->uri);
	push @row, md5_hex($uri->path_query);

	push @row, es($request->header('Host'));
	push @row, encode_base64(es($request->header('Cookie')), '');
	push @row, encode_base64(es($request->content), '');
	push @row, es($request->headers->user_agent);
	push @row, es($request->headers->referer);
	push @row, es($request->headers->authorization_basic);
	push @row, es($request->headers->proxy_authorization_basic); 

	# CSV output of response data, fields are:
	# response_time, status, message, content-type, server, expires, server_date

	# There was no response.  This can happen if the server was not reachable, the
	# response was not in the pcap etc.
	if (!defined $response) { 
		push @row, "", "", "", "", "", "", "";
	} else {
		push @row, time_format('yyyy-mm-dd hh:mm:ss', $info->{response_time});
		push @row, es($response->code);
		push @row, es($response->message);
		
		# Get the content type and trim off any extra (e.g. charset info)
		my $content_type = es($response->header('Content-Type'));
		if ($content_type =~ /(.+?);/) {
			$content_type = $1;
		}

		push @row, $content_type;
		push @row, es($response->headers->server);
		push @row, es(time_format('yyyy-mm-dd hh:mm:ss', $response->headers->expires));
		push @row, es(time_format('yyyy-mm-dd hh:mm:ss', $response->headers->date));
	}
	push @row, $info->{filename};

	$csv->combine(@row);
	print $csv->string();
	print "\n";
}
