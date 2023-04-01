#!/usr/bin/perl
use strict;
use warnings;

use Time::Piece ();

my $today = Time::Piece->new;

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
	black => "\e[30m",
	red => "\e[31m",
	green => "\e[32m",
	yellow => "\e[33m",
	blue => "\e[34m",
	magenta => "\e[35m",
	cyan => "\e[36m",
	white => "\e[37m",
	off => "\e[0;0m",
);

my %extras = (
	extra => "magenta",
	ip => "blue",
	types => "yellow",
	warn => "red",
);
$colours{$_} = $colours{$extras{$_}} for keys %extras;

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

sub parse_time {
	my($fmt, $str) = @_;

	my $when = eval { Time::Piece->strptime($str, $fmt) };
	if(length($@)){
		# errror
		warn "couldn't parse \"$str\" as \"$fmt\"\n";
		return undef;
	}
	return $when;
}

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
	my ($type, $ip, $host, $user, $timestamp, $desc) = @_;

	push @{$ip_records{$ip}->{fails}}, {
		type => $type,
		host => $host,
		user => $user,
		timestamp => $timestamp,
		desc => $desc,
	};
}

sub parse_ssh {
	my @contents = file_contents(
		#"eg.log"
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

			my $timestamp = parse_time("%b %d %H:%M:%S %Y", "$parts[0] $parts[1] $parts[2] " . $today->year);

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

				add_fail("ssh", $ip, $host, $user, $timestamp, $desc);

			}elsif($line =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
				my $ip = $&;
				my $host = "?";
				my $user = "?";
				my $desc = "$parts[5] $parts[6]";

				add_fail("ssh", $ip, $host, $user, $timestamp, $desc);
			}
		}
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
			$ua =~ s/^"|" *$//g;

			my $desc = "ua:$ua";

			my $path = $parts[6];
			if($path =~ /^\/(sibble|favicon|^\/apple-touch-icon.*\.png$)/){
				$desc = "{public} $desc";
			}

			# [31/Mar/2023:06:58:45 +0100]
			my $timestamp = parse_time("[%d/%b/%Y:%H:%M:%S %z]", "$parts[3] $parts[4]");

			add_fail("http", $ip, "", "", $timestamp, $desc);
		} else {
			add_auth($ip, "http");
		}
	}
}

parse_ssh();
parse_http();


if($verbose){
	for my $ip (keys %ip_records) {
		my $rec = $ip_records{$ip};
		if ($rec->{authed}) {
			my $n = 0;
			for my $type (keys %{$rec->{authed}}){
				$n += $rec->{authed}->{$type};
			}
			my $types = join(", ", keys %{$rec->{authed}});
			print "$colours{ip}$ip$colours{off} authed, $n accesses over $colours{types}$types$colours{off}\n";
		}
	}
}

my @sorted;
for my $ip (keys %ip_records) {
	my $rec = $ip_records{$ip};

	next if $rec->{authed};

	# TODO
	#my $chosen_colour = failed_dates[ip] == today ? colour_red : colour_blue

	my %types;
	my($earliest, $latest);
	my $latest_desc;

	my $n = 0;
	for my $entry (@{$rec->{fails}}){
		$types{$entry->{type}}++;
		$n += 1;

		my $timestamp = $entry->{timestamp};
		$earliest = $timestamp if !defined($earliest) || $timestamp < $earliest;
		if(!defined($latest) || $timestamp > $latest){
			$latest = $timestamp;
			$latest_desc = $entry->{desc};
		}
	}

	push @sorted, {
		ip => $ip,
		fail_count => $n,
		types => [keys %types],
		earliest => $earliest,
		latest => $latest,
		latest_desc => $latest_desc,
	};
}

# sort by latest, then by count
@sorted = sort {
	my $d = $a->{latest} <=> $b->{latest};

	$d || ($a->{fail_count} <=> $b->{fail_count})
} @sorted;

for my $rec (@sorted) {
	my $ip = $rec->{ip};
	my $n = $rec->{fail_count};

	my $latest = $rec->{latest};
	my $days_ago = int(($today - $latest)->days);

	my $latest_str;
	if($days_ago == 0){
		$latest_str = "$colours{warn}today$colours{off}";
	}elsif($days_ago < 1){
		$latest_str = "$days_ago days ago";
	}elsif($days_ago <= 7){
		my $s = $days_ago > 1 ? "s" : "";
		$latest_str = "$days_ago day$s ago";

		if($days_ago < 3){
			$latest_str .= " @ " . $latest->strftime("%H:%M");
		}
	}else{
		$latest_str = $latest->strftime("%Y-%m-%d");
	}

	my $extra = "";
	if($n > 1){
		my $diff = $rec->{latest} - $rec->{earliest};

		if(int($diff->days) > 1){
			$extra = " (over " . int($diff->days) . " days)";
		}elsif(int($diff->hours) > 1){
			$extra = " (over " . int($diff->hours) . " hours)";
		}elsif(int($diff->minutes) > 1){
			$extra = " (over " . int($diff->minutes) . " minutes)";
		}else{
			my $s = $diff->seconds == 1 ? "" : "s";
			$extra = " (over " . int($diff->seconds) . " second$s)";
		}

		$extra = "$colours{extra}$extra$colours{off}";
	}

	my $types_desc = join(", ", @{$rec->{types}});
	my $s = $n > 1 ? "s" : "";
	my $latest_desc = $rec->{latest_desc};

	if($latest_desc){
		$extra .= " $colours{extra}($latest_desc)$colours{off}";
	}

	my $ip_col = "$colours{ip}$ip$colours{off}";
	my $types_col = "$colours{types}$types_desc$colours{off}";
	print "$n fail$s for $ip_col ($types_col), latest $latest_str$extra\n";
}
