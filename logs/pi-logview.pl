#!/usr/bin/perl
use strict;
use warnings;

sub usage {
	print STDERR "Usage: $0 [-v]\n";
	exit 2;
}

my $verbose = 0;
for(@ARGV){
	if($_ eq "-v"){
		$verbose = 1;
	}else{
		usage();
	}
}

my %colours = (
	red => "\e[31m",
	black => "\e[30m",
	blue => "\e[34m",
	red => "\e[31m",
	yellow => "\e[33m",
	magenta => "\e[35m",
	off => "\e[0;0m",
);

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

my %ip_records;

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

sub add_auth {
	my($ip, $type) = @_;
	$ip_records{$ip}->{authed}->{$type}++;
}

sub add_fail {
	my ($type, $ip, $host, $user, $date, $time, $desc) = @_;

	push @{$ip_records{$ip}->{fails}}, {
		type => $type,
		host => $host,
		user => $user,
		date => $date,
		time => $time,
		desc => $desc,
	};
}

sub parse_ssh {
	my @contents = file_contents(
		'/var/log/auth.log',
		'/var/log/auth.log.1',
		glob('/var/log/auth.log.[2345].gz'),
	);

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

			my $time = $parts[2];
			my $date = "$parts[0] $parts[1]";

			if($parts[5] eq "Accepted"){
				my $ip = $parts[10];
				add_auth($ip, "ssh");
			}elsif($parts[5] eq "Failed"){
				my $ip;
				my $host = $parts[3];
				my $user;

				if($parts[8] eq "invalid" && $parts[9] eq "user") {
					$ip = $parts[12];
					$user = $parts[10];
				} else {
					$ip = $parts[10];
					$user = $parts[8];
				}

				my $desc = "invalid user/pw";

				add_fail("ssh", $ip, $host, $user, $date, $time, $desc);

			}elsif($line =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
				my $ip = $&;
				my $host = "?";
				my $user = "?";
				my $desc = "$parts[5] $parts[6]";

				add_fail("ssh", $ip, $host, $user, $date, $time, $desc);
			}
		}
		# ' \
		# 	| sed 's%on \([A-Za-z]*\) \([0-9]*\) %on yyyy/\1/\2 %; s%/\([0-9]\) %/0\1 %; '"$sed_month_to_num" \
		# 	| sort -k 10
		# # 06/Month/2022 --> 2022/Month/06
}

sub parse_http {
	my @contents = file_contents(
		'/var/log/nginx/access.log',
		'/var/log/nginx/access.log.1',
		'/var/log/nginx/access.log.2.gz'
	);

	for my $line (@contents){
		my @parts = split /\s+/, $line;

		my $ip = $parts[0];

		if ($parts[2] eq "-") {
			my $ua = "";
			for(my $i = $#parts; $i > 0; $i -= 1){
				my $bit = $parts[$i];
				$ua = "$bit $ua";

				last if substr($bit, 0, 1) eq '"';
			}

			$ua =~ s/ *$//;
			$ua =~ s/[^(]*\(//;
			$ua =~ s/\).*//;

			my $is_private = 0;
			my $path = $parts[6];
			if(index($path, "/sibble") != 1
			&& index($path, "/favicon") != 1
			&& $path !~ /^\/apple-touch-icon.*\.png$/)
			{
				$is_private = 1;
			}

			my $desc = " ua:$ua";
			if(!$is_private){
				$desc .= " (public)";
			}

			my $when = $parts[3];
			$when =~ s/:/ /; # 29/Mar/2023:HH:MM:SS
			#                             ^
			$when =~ s/\[//;
			my $tz = $parts[4];
			$tz =~ s/\]//;
			(my $date = $when) =~ s/ .*//;
			(my $time = $when) =~ s/.* //;

			add_fail("http", $ip, "", "", $date, $time, $desc);
		} else {
			add_auth($ip, "http");
		}
	}
	#	' \
	#		| sed 's%\([0-9]*\)/\([A-Z][a-z]*\)/\([0-9]*\)%\3/\2/\1%;'"$sed_month_to_num" \
	#		| sort -k 8
	#	# 06/Month/2022 --> 2022/Month/06
}

parse_ssh();
parse_http();


for my $ip (keys %ip_records) {
	my $rec = $ip_records{$ip};
	if ($rec->{authed}) {
		next unless $verbose;

		my $n = 0;
		for my $type (keys %{$rec->{authed}}){
			$n += $rec->{authed}->{$type};
		}
		my $types = join(", ", keys %{$rec->{authed}});
		print "$ip authed, $n accesses over $types\n";
	} else {
		# TODO
		#my $chosen_colour = failed_dates[ip] == today ? colour_red : colour_blue

		my %types;
		#my($earliest, $latest);
		#my $descs;
		#my $n = 0;

		for my $entry (@{$rec->{fails}}){
			$types{$entry->{type}}++;
			#$earliest = $entry->{}
		}

		my $n = 0;
		for my $type (keys %types) {
			$n += $types{$type};
		}

		my $types_desc = join(", ", keys %types);
		my $s = $n > 1 ? "s" : "";
		print "$colours{red}$n fail$s$colours{off} for $ip ($types_desc)\n";

		# ssh:
		# print "ssh, failed ($failed{$ip} times) and never auth'd! $ip (on $failed_dates{$ip} $failed_times{$ip}, as $failed_users{$ip}, desc: $failed_desc{$ip})\n";

		# http:
		# my $desc = $private_access{$ip} ? "" : " (public only)";
		# print "http, never auth'd! $ip ($unauth{$ip} times, on $date_part{$ip}$desc from $useragent_part{$ip})\n";
	}
}
