#!/usr/bin/perl
use strict;
use warnings;

sub usage {
	print STDERR "Usage: $0\n";
	exit 2;
}

# black=30
# blue=34
# red=31
# yellow=33
# magenta=35
# sed_month_to_num="s/Jan/01/; s/Feb/02/; s/Mar/03/; s/Apr/04/; s/May/05/; s/Jun/06/; s/Jul/07/; s/Aug/08/; s/Sep/09/; s/Oct/10/; s/Nov/11/; s/Dec/12/;"

# PAM_SERVICE=sshd
# PAM_RHOST=127.0.0.1
# PAM_USER=pi
# PAM_TYPE=open_session
# PAM_TTY=ssh|open_session|close_session
my $pam = $ENV{PAM_TYPE} || "";
if($pam eq 'open_session') {
		# default to colour for PAM / logins
		#$col_ret=0;
} elsif($pam eq 'close_session') {
		exit 0
} else {
		# probably not run from pam
}

usage unless @ARGV == 0;

sub file_contents {
	my @c;

	for(@_){
		if($_ =~ /\.gz$/){
			push @c, split /\n/, `zcat '$_'`;
		}else{
			open(my $fh, '<', $_) or die "open $_: $!";
			push @c, <$fh>;
			close($fh);
		}
	}

	return @c;
}

sub filter_ssh {
	my @contents = file_contents(
		'/var/log/auth.log',
		'/var/log/auth.log.1',
		glob('/var/log/auth.log.[2345].gz'),
	);

	my %authed; # ips
	my %failed_users;
	my %failed_dates;
	my %failed_times;
	my %failed_desc;
	my %failed;

	for my $line (@contents){
		my @parts = split /\s+/, $line;
		next unless $parts[4] =~ '^sshd';

			# Oct 20 10:10:10 <host> sshd[pid]: Accepted publickey for <user> from <ip> port <port> <proto>: <key-type> SHA256:<key>
			# 0   1  2        3      4          5        6         7   8      9    10   11   12     13       14         15
			# Sep 11 10:10:10 <host> sshd[pid]: Failed password for <user> from <ip> port <port> <proto>
			# 0   1  2        3      4          5      6        7   8      9    10   11   12     13
			# Dec 13 08:05:46 <host> sshd[pid]: Failed password for invalid user <user> from <ip> port <port> <proto>
			# 0   1  2        3      4          5      6        7   8       9    10     11   12   13   14     15
			# Dec 13 08:05:46 <host> sshd[pid]: (Bad|Did not|Invalid|Protocol|Unable)
			# 0   1  2        3      4          5
			# May 24 02:01:52 <host> sshd[pid]: Bad protocol version identification '\003' from 141.98.9.13 port 64384
			# 0   1  2        3      4          5

			if($parts[5] eq "Accepted"){
				my $ip = $parts[10];
				$authed{$ip} = 1;
			} elsif($parts[5] eq "Failed"){
				my $ip;

				if($parts[8] eq "invalid" && $parts[9] eq "user") {
					$ip = $parts[12];
					$failed_users{$ip} = "$parts[3] ($parts[10])";
				} else {
					$ip = $parts[10];
					$failed_users{$ip} = "$parts[3] ($parts[8])";
				}

				$failed{$ip}++;
				$failed_dates{$ip} = "$parts[0] $parts[1]";
				$failed_times{$ip} = $parts[2];
				$failed_desc{$ip} = "invalid user/pw";
			} elsif($line =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
				my $ip = $&;
				$failed{$ip}++;
				$failed_users{$ip} = "?";
				$failed_dates{$ip} = "$parts[0] $parts[1]";
				$failed_times{$ip} = $parts[2];
				$failed_desc{$ip} = "$parts[5] $parts[6]";
			}
		}

		for my $ip (keys %failed) {
			if ($authed{$ip}) {
				print "ssh, failed ($failed{$ip} times) but auth'd: $ip\n";
			} else {
				# TODO
				#my $chosen_colour = failed_dates[ip] == today ? colour_red : colour_blue

				print "ssh, failed ($failed{$ip} times) and never auth'd! $ip (on $failed_dates{$ip} $failed_times{$ip}, as $failed_users{$ip}, desc: $failed_desc{$ip})\n";
			}
		}
		# ' \
		# 	| sed 's%on \([A-Za-z]*\) \([0-9]*\) %on yyyy/\1/\2 %; s%/\([0-9]\) %/0\1 %; '"$sed_month_to_num" \
		# 	| sort -k 10
		# # 06/Month/2022 --> 2022/Month/06
}

sub filter_http {
	my @contents = file_contents(
		'/var/log/nginx/access.log',
		'/var/log/nginx/access.log.1',
		'/var/log/nginx/access.log.2.gz'
	);

	my %unauth;
	my %authed;
	my %date_part;
	my %parts;
	my %private_access;
	my %useragent_part;

	for my $line (@contents){
		my @parts = split /\s+/, $line;

		my $ip = $parts[0];

		if ($parts[2] eq "-") {
			$unauth{$ip}++;

			my $ua = "";
			for(my $i = $#parts; $i > 0; $i -= 1){
				my $bit = $parts[$i];
				$ua = "$bit $ua";

				last if substr($bit, 0, 1) eq '"';
			}

			$ua =~ s/ *$//;
			$ua =~ s/[^(]*\(//;
			$ua =~ s/\).*//;
			$useragent_part{$ip} = $ua;

			my $path = $parts[6];
			if(index($path, "/sibble") != 1
			&& index($path, "/favicon") != 1
			&& $path !~ /^\/apple-touch-icon.*\.png$/)
			{
				$private_access{$ip} = 1;
			}

			my $when = "$parts[3] $parts[4]";
			$when =~ s/:/ /;
			$when =~ s/[][]//g;
			$date_part{$ip} = $when;
		} else {
			$authed{$ip}++;
		}
	}

	for my $ip (keys %unauth){
		if ($authed{$ip}) {
			print "http, auth'd: $ip\n";
		} else {
			my $desc = $private_access{$ip} ? "" : " (public only)";
			print "http, never auth'd! $ip ($unauth{$ip} times, on $date_part{$ip}$desc from $useragent_part{$ip})\n";
		}
	}

	#	' \
	#		| sed 's%\([0-9]*\)/\([A-Z][a-z]*\)/\([0-9]*\)%\3/\2/\1%;'"$sed_month_to_num" \
	#		| sort -k 8
	#	# 06/Month/2022 --> 2022/Month/06
}

filter_ssh();
filter_http();
