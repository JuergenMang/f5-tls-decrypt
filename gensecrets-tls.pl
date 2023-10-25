#!/usr/bin/env perl

# Date:   2022-05-24
# Author: Juergen Mang <juergen.mang@sec.axians.de>
#
# This script depends on the special tcpdump found on a F5 system
# and the ssl provider in F5 versions 15.0 or greater.

use strict;
use warnings;

#Debugging
my $debug = 0;
my $dump_struct = 0;
if ($dump_struct eq 1) {
	use Data::Dumper;
}

#Global variables
my $skipped = 0;
my $flows_tls1;
my $flows_tls1_3;

if (not defined($ARGV[0])) {
	print_usage();
}

#Detect filetype
my $is_tcpdump_file = 1;
open my $cmd, "-|", "file $ARGV[0]" or die "Can not open file command: ".$@;
while (<$cmd>) {
	$is_tcpdump_file = 0 if /ASCII/;
}
close $cmd;

if ($is_tcpdump_file eq 1) {
	print STDERR "Inputfile is a pcap file.\n";
}
else {
	print STDERR "Inputfile is an ascii file.\n";
}

if ($is_tcpdump_file eq 1) {
	#Script must be run on a F5
	my $on_f5 = 0;
	open my $cmd, "-|", "tcpdump -h 2>&1" or die "Can not open tcpdump command: ".$@;
	while (<$cmd>) {
		$on_f5 = 1 if /--f5/;
	}
	close $cmd;
	if ($on_f5 eq 0) {
		print STDERR "This script must run on a F5.\n";
		exit 1;
	}
}

#functions
sub print_usage {
	print STDERR "Usage: $0 (dump.pcap|dump.out) > dump.pms\n\n".
		"Reading the tcpdump file depend on the special f5 tcpdump utility.\n".
		"You can execute this script on a F5 or execute \"tcpdump -r dump.pcap > dump.out\" on the F5,\n".
		"transfer the file and run the script against the dump.out file.\n".
		"This utility detects the file format for you.\n\n".
		"Run:\n".
		"#tmsh modify sys db tcpdump.sslprovider value enable\n".
		"#tcpdump -nni 0.0:nnnp -s0 --f5 ssl:v -w /tmp/dump.pcap -vvv <filter>\n\n";
		"#tmsh modify sys db tcpdump.sslprovider value disable\n".
	exit 1;
}

sub print_ifdef {
	#print out the secret if it has a none zero value
	my ($key, $cr, $secret, $flow) = @_;
	if ($cr ne "0" and $secret ne "0") {
		print $key." ".$cr." ".$secret."\n";
	}
	else {
		print STDERR "No secrets found, skipping flow $flow\n" if $debug eq 1;
		$skipped++;
	}
}

sub addflow_tls1 {
		#adds a flow with corresponding secrets
		#- each flow can have multiple client_randoms
		#- each client_random has one master_secret
		my ($key, $value, $flowid) = @_;
		#skip values starting with zeros
		if (not $value =~ /^0000000/) {
			if ($key eq "CR" and not defined($flows_tls1->{$flowid}->{"CR"}->{$value})) {
				#add new client_random for defined flow, master_secret is not known in this step
				print STDERR "Flow $flowid: Adding $key $value\n" if $debug eq 1;
				$flows_tls1->{$flowid}->{"CR"}->{$value} = 0;
				$flows_tls1->{$flowid}->{"lastcr"} = $value;
			}
			elsif ($key eq "MS") {
				#update master secret for last client_random for defined flow
				my $lastcr = $flows_tls1->{$flowid}->{"lastcr"};
				print STDERR "Flow $flowid: Updating CR $lastcr with $key: $value\n" if $debug eq 1;
				if (defined($lastcr)) {
					$flows_tls1->{$flowid}->{"CR"}->{ $lastcr } = $value;
				}
			}
		}
}

sub addflow_tls1_3 {
		#adds a flow with corresponding secrets
		#- each flow can have multiple client_randoms
		#- each client_random has one early_traffic_secret, client_handshake_secret, server_handshake_secret, 
		#  client_traffic_secret and server_traffic_secret
		my ($key, $value, $flowid) = @_;
		#skip values starting with zeros
		if (not $value =~ /^0000000/) {
			if ($key eq "1.3CR" and not defined($flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3ES"})) {
				#add new client_random for defined flow, other secrets are not known in this step
				print STDERR "Flow $flowid: Adding $key $value\n" if $debug eq 1;
				$flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3ES"} = 0;
				$flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3HSC"} = 0;
				$flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3HSS"} = 0;
				$flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3APPC"} = 0;
				$flows_tls1_3->{$flowid}->{"1.3CR"}->{$value}->{"1.3APPS"} = 0;
				$flows_tls1_3->{$flowid}->{"lastcr"} = $value;
			}
			elsif ($key eq "1.3ES" or $key eq "1.3HSC" or $key eq "1.3HSS" or $key eq "1.3APPC" or $key eq "1.3APPS") {
				#update secrets for last client_random for defined flow
				my $lastcr = $flows_tls1_3->{$flowid}->{"lastcr"};
				print STDERR "Flow $flowid: Updating 1.3CR $lastcr with $key: $value\n" if $debug eq 1;
				if (defined($lastcr)) {
					$flows_tls1_3->{$flowid}->{"1.3CR"}->{ $lastcr }->{$key} = $value;
				}
			}
		}
}

#main script
my $out;
if ($is_tcpdump_file eq 0) {
	open $out, $ARGV[0] or die "Can not open input file: ".$@;
}
else {
	open $out, "-|", "tcpdump -r $ARGV[0]" or die "Can not open tcpdump command: ".$@;
}
while (<$out>) {
	#tls 1.3
	addflow_tls1_3($1, $2, $3) if /\s(1\.3CR):(\S+).+flowid=(\S+)\s/;
	addflow_tls1_3($1, $2, $3) if /\s(1\.3ES):(\S+).+flowid=(\S+)\s/;
	addflow_tls1_3($1, $2, $3) if /\s(1\.3HSC):(\S+).+flowid=(\S+)\s/;
	addflow_tls1_3($1, $2, $3) if /\s(1\.3HSS):(\S+).+flowid=(\S+)\s/;
	addflow_tls1_3($1, $2, $3) if /\s(1\.3APPC):(\S+).+flowid=(\S+)\s/;
	addflow_tls1_3($1, $2, $3) if /\s(1\.3APPS):(\S+).+flowid=(\S+)\s/;
	
	#tls 1.x
	addflow_tls1($1, $2, $3) if /\s(CR):(\S+).+flowid=(\S+)\s/;
	addflow_tls1($1, $2, $3) if /\s(MS):(\S+).+flowid=(\S+)\s/;
}
close $out;

if ($dump_struct eq 1) {
	print STDERR Dumper $flows_tls1_3;
	print STDERR Dumper $flows_tls1;
}

#tls 1.3
my $num_tls1_3_flows = keys %$flows_tls1_3;
print STDERR "TLS 1.3 detected: $num_tls1_3_flows flows\n" if $num_tls1_3_flows > 0;
for my $flow (keys %$flows_tls1_3) {
	#go through all flows
	for my $cr (keys %{$flows_tls1_3->{$flow}->{"1.3CR"}}) {
		#go through all client_randoms in this flow
		print_ifdef("CLIENT_EARLY_TRAFFIC_SECRET", $cr, $flows_tls1_3->{$flow}->{"1.3CR"}->{$cr}->{"1.3ES"}, $flow);
		print_ifdef("CLIENT_HANDSHAKE_TRAFFIC_SECRET", $cr, $flows_tls1_3->{$flow}->{"1.3CR"}->{$cr}->{"1.3HSC"}, $flow);
		print_ifdef("SERVER_HANDSHAKE_TRAFFIC_SECRET", $cr, $flows_tls1_3->{$flow}->{"1.3CR"}->{$cr}->{"1.3HSS"}, $flow);
		print_ifdef("CLIENT_TRAFFIC_SECRET_0", $cr, $flows_tls1_3->{$flow}->{"1.3CR"}->{$cr}->{"1.3APPC"}, $flow);
		print_ifdef("SERVER_TRAFFIC_SECRET_0", $cr, $flows_tls1_3->{$flow}->{"1.3CR"}->{$cr}->{"1.3APPS"}, $flow);
	}
}

#tls 1.x
my $num_tls1_flows = keys %$flows_tls1;
print STDERR "TLS 1.x detected: $num_tls1_flows flows\n" if $num_tls1_flows > 0;
for my $flow (keys %$flows_tls1) {
	#go through all flows
	for my $cr (keys %{$flows_tls1->{$flow}->{"CR"}}) {
		#go through all client_randoms in this flow
		print_ifdef("CLIENT_RANDOM", $cr, $flows_tls1->{$flow}->{"CR"}->{$cr}, $flow);
	}
}

print STDERR "Skipped: $skipped flows\n" if $skipped > 0;
exit 0;
