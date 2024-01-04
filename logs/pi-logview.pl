#!/usr/bin/perl
use strict;
use warnings;

use Time::Piece ();

# bigger => more severe
use constant {
	SEV_SAFE => 0,
	SEV_DISCONNECT  => 1,
	SEV_PROTO_MISMATCH => 2,
	SEV_UNKNOWN => 3,
	SEV_DISCONNECT_POSTAUTH => 4,
	SEV_LOGIN_ATTEMPT => 5,

	# anything >=4 is major
	SEV_major => 4,
};

my $today = Time::Piece->new;
my $HOME = $ENV{HOME};
my $cachepath = $HOME ? "$HOME/.pi-logview.cache" : "/var/lib/pi-logview.cache";

sub usage {
	print STDERR "Usage: $0 [-v] [-d] [--cidr=<cidr>]\n";
	exit 2;
}

my $verbose = 0;
my $debug = 0;
my $filter_cidr;
for(my $i = 0; $i < @ARGV; $i++){
	$_ = $ARGV[$i];
	if($_ eq "-v"){
		$verbose = 1;
	}elsif($_ eq "-d"){
		$debug = 1;
	}elsif($_ =~ /^--cidr=(.*)/){
		$filter_cidr = $1;
	}elsif($_ eq "--cidr"){
		usage if ++$i == @ARGV;
		$filter_cidr = $_ = $ARGV[$i];
	}else{
		usage();
	}
}

if($debug){
	use Time::HiRes qw(gettimeofday);
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
	duration => "magenta",
	severity => "green",
	severity_major => "red",
	ip => "blue",
	types => "yellow",
	warn => "red",
	banned => "cyan",
	fail2banned => "blue",
);
$colours{$_} = $colours{$extras{$_}} for keys %extras;
if(!-t 1){
	# keep colours if we're invoked via PAM
	unless(($ENV{PAM_TYPE} || "") eq "open_session"){
		$colours{$_} = "" for keys %colours;
	}
}

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
my @banned;
my @fail2banned;

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
			push @c, map { chomp; $_ } <$fh>;
			close($fh);
		}
	}

	return @c;
}

sub debug_time {
	my($name, $f) = @_;
	if($debug == 0){
		$f->();
		return;
	}
	my $now = gettimeofday();
	$f->();
	my $fin = gettimeofday();
	my $diff = sprintf("%.3f", $fin - $now);
	print STDERR "$0: ${diff}ms for $name\n";
}

sub add_auth {
	my($ip, $type) = @_;
	$ip_records{$ip}->{authed}->{$type}++;
}

sub add_fail {
	my ($type, $ip, $host, $user, $timestamp, $desc, $desc_sev) = @_;

	push @{$ip_records{$ip}->{fails}}, {
		type => $type,
		host => $host,
		user => $user,
		timestamp => $timestamp,
		desc => $desc,
		desc_sev => $desc_sev,
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
			if($timestamp > $today){
				$timestamp = $timestamp->add_years(-1);
			}

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
				my $desc_sev = SEV_LOGIN_ATTEMPT;

				add_fail("ssh", $ip, $host, $user, $timestamp, $desc, $desc_sev);

			}elsif($line =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
				my $ip = $&;
				my $host = "?";
				my $user = "?";

				my $desc;
				my $desc_sev;

				if("$parts[5] $parts[6]" eq "Connection closed"){
					$desc = "eof";
					$desc_sev = SEV_DISCONNECT;
				}elsif($parts[5] eq "Disconnected"){
					my $user = $parts[8];
					$desc = "disconnect:$user";
					$desc_sev = SEV_DISCONNECT_POSTAUTH;
				}elsif("$parts[5] $parts[6]" eq "Invalid user"){
					my $user = $parts[7];
					$desc = "invalid:$user";
					$desc_sev = SEV_LOGIN_ATTEMPT;
				}elsif(
					join(" ", @parts[5 .. 8]) eq "PAM 1 more authentication" ||
					$parts[5] eq "pam_unix(sshd:auth):"
				){
					my %pam = (
						tty => "<unknown>",
						user => "<unknown>",
					);
					for my $eq (@parts[8 .. $#parts]){
						if($eq =~ /(.*)=(.*)/){
							$pam{$1} = $2;
						}
					}
					$desc = "pam:$pam{tty},$pam{user}";
					$desc_sev = SEV_LOGIN_ATTEMPT;
				}elsif("$parts[5] $parts[6]" eq "Received disconnect"){
					$desc = "disconnect-no-user";
					$desc_sev = SEV_DISCONNECT;
				}elsif("$parts[5] $parts[6]" eq "banner exchange:"){
					$desc = "banner-exchange";
					$desc_sev = SEV_PROTO_MISMATCH;
				}elsif("$parts[5] $parts[6]" eq "Connection reset"){
					$desc = "conn-reset";
					$desc_sev = SEV_DISCONNECT;
				}elsif("$parts[5] $parts[6] $parts[7] $parts[8]" eq "Unable to negotiate with"){
					$desc = "negotiation-fail";
					$desc_sev = SEV_PROTO_MISMATCH;
				}else{
					$desc = "unknown ($parts[5] $parts[6])";
					$desc_sev = SEV_UNKNOWN;
				}

				add_fail("ssh", $ip, $host, $user, $timestamp, $desc, $desc_sev);
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
			my $desc_sev = SEV_UNKNOWN;

			my $path = $parts[6];
			if($path =~ /^\/(sibble|favicon|^\/apple-touch-icon.*\.png$)/){
				$desc = "{public} $desc";
				$desc_sev = SEV_SAFE;
			}

			# [31/Mar/2023:06:58:45 +0100]
			my $timestamp = parse_time("[%d/%b/%Y:%H:%M:%S %z]", "$parts[3] $parts[4]");

			add_fail("http", $ip, undef, undef, $timestamp, $desc, $desc_sev);
		} else {
			add_auth($ip, "http");
		}
	}
}

sub parse_fail2bans_slow {
	if(open(my $fh, '-|', '/usr/local/bin/doas /usr/bin/fail2ban-client-su banned')){
		chomp(my $json = join ",", <$fh>);
		$json =~ s/][^[]*\[/,/g; # sep
		$json =~ s/^\[[^[]*\[//; # start
		$json =~ s/][^]]*\]$//; # end
		$json =~ s/'//g;

		my @ips = grep { length } split /,+/, $json;
		push @fail2banned, map { s/^ *//; s/ *$//; $_ } @ips;
	}else{
		@fail2banned = ();
		warn "$0: couldn't get fail2ban IPs";
	}
	cache_fail2bans();
}

sub cache_fail2bans {
	if(open(my $fh, '>', $cachepath)){
		my $now = gettimeofday();
		print $fh "$now\n";
		print $fh join("\n", @fail2banned);
		print $fh "\n";
		close $fh;

		warn "$0: wrote \"$cachepath\"\n" if $debug;
	}else{
		warn "$0: open \"$cachepath\": $!";
	}
}

sub parse_banned {
	sub parse_pi_bans {
		for(file_contents("/etc/pi-bans")){
			s/\s*#.*//;
			push @banned, $_ if length;
		}
	}

	sub parse_fail2bans {
		if(open(my $fh, '<', $cachepath)){
			die "parse_fail2bans: need ip records" unless keys(%ip_records) > 0;

			my $latest_ts = undef;

			for my $ip (keys %ip_records){
				for my $fail (@{$ip_records{$ip}->{fails}}){
					my $ts = $fail->{timestamp};
					$latest_ts = $ts if !defined($latest_ts) || $ts > $latest_ts;
				}
			}

			chomp(my $timestamp = <$fh>);

			if($latest_ts > $timestamp){
				warn "$0: \"$cachepath\" expired, reloading\n" if $debug;
				parse_fail2bans_slow();
			}else{
				warn "$0: \"$cachepath\" still relevant, using\n" if $debug;
				@fail2banned = map { chomp; $_ } <$fh>;
			}
			close $fh;
		}else{
			warn "$0: no \"$cachepath\"\n" if $debug;
			parse_fail2bans_slow();
		}
	}

	debug_time("parse pi-bans", \&parse_pi_bans);
	debug_time("parse fail2bans", \&parse_fail2bans);
}

sub ip_to_hex {
	my $s = shift;

	if(index($s, ":") >= 0){
		warn "$0: skipping IPv6 address (\"$s\")\n" if $debug;
		return 0
	}

	# ipv4
	if(index($s, '.') == -1){
		# already a number
		return $s;
	}
	return hex(join("", map { sprintf "%02x", $_ } split(/\./, $s)));
}

sub cidr_match {
	my($cidr, $candidate) = @_; # (string, string|number)

	my($addr, $mask);
	if($cidr =~ m@(.*)/(.*)@){
		$addr = $1;
		$mask = $2;
	}else{
		$addr = $cidr;
		$mask = 32;
	}
	my $shift = 32 - $mask;

	# addr: string -> number
	my $addr_hex = ip_to_hex($addr);
	my $addr_hex_shifted = $addr_hex >> $shift;

	$candidate = ip_to_hex($candidate);
	my $candidate_shifted = $candidate >> $shift;

	return $addr_hex_shifted == $candidate_shifted;
}

sub banned_type {
	my $ip = shift;
	my $ip_hex = ip_to_hex($ip);

	for my $entry (@banned){
		return 1 if cidr_match($entry, $ip_hex);
	}
	for my $entry (@fail2banned){
		return 2 if $entry eq $ip;
	}
	return 0;
}

sub ban_desc {
	my $t = banned_type(shift());
	return ($colours{banned}, "banned") if $t == 1;
	return ($colours{fail2banned}, "f2banned") if $t == 2;
	return 0, "";
}

sub show_verbose {
	return unless $verbose;
	my $ip = shift;

	my $cmd = join(
		' ',
		'zgrep',
		'-F',
		$ip,
		'/var/log/nginx/access.log',
		'/var/log/nginx/access.log.1',
		glob('/var/log/nginx/access.log.[0-9].gz'),
		'/var/log/auth.log',
		'/var/log/auth.log.1',
		glob('/var/log/auth.log.[0-9].gz'),
	);

	system("$cmd | sed 's/^/\t/'");
}

debug_time("parse ssh", \&parse_ssh);
debug_time("parse http", \&parse_http);
parse_banned();

if($filter_cidr){
	my $found = 0;
	for my $ip (keys %ip_records){
		next unless cidr_match($filter_cidr, $ip);
		$found = 1;

		my $rec = $ip_records{$ip};

		my($ban_col, $ban_name) = ban_desc($ip);

		print "$colours{ip}$ip$colours{off}"
		. ($ban_col ? " $ban_col($ban_name)$colours{off}" : "")
		. ":\n";

		print "\tauthed\n" if $rec->{authed};

		my @sorted = sort {
			$a->{timestamp} <=> $b->{timestamp}
		} @{$rec->{fails}};
		my $http_unauths = 0;

		for my $fail (@sorted){
			if($fail->{type} eq "http"){
				if($rec->{authed}){
					$http_unauths++;
					if($http_unauths == 1){
						# show first one
					}else{
						print "\t(multiple http challenges)\n" if $http_unauths == 2;
						next;
					}
				}
			}

			my $when = timestamp_to_approx($fail->{timestamp});
			my $host = $fail->{host} || "<nohost>";
			my $user = $fail->{user} || "<none>";

			print "\t$when: $colours{types}$fail->{type}$colours{off} "
			. "failure from $host, "
			. "user $user "
			. "($colours{severity}$fail->{desc}$colours{off})\n";
		}

		show_verbose($ip);
	}

	exit if $found;
	die "$0: no records for $filter_cidr\n";
}

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

	my %types;
	my($earliest, $latest);
	my $latest_desc;
	my($severest_desc, $severest_desc_val) = ("", 0);

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
		if($entry->{desc_sev} >= $severest_desc_val){
			$severest_desc_val = $entry->{desc_sev};
			$severest_desc = $entry->{desc};
		}
		#print "$ip: $entry->{desc_sev} @ $entry->{desc}\n";
	}

	push @sorted, {
		ip => $ip,
		fail_count => $n,
		types => [keys %types],
		earliest => $earliest,
		latest => $latest,
		latest_desc => $latest_desc,
		severest_desc => $severest_desc,
		severity => $severest_desc_val,
	};
}

sub timestamp_to_approx {
	my $t = shift;
	my $days_ago = int(($today - $t)->days);
	$days_ago += 365 if $days_ago < 0;
	my $r;
	if($days_ago == 0){
		$r = "$colours{warn}within-24-hrs$colours{off}";
	}elsif($days_ago < 1){
		$r = "$days_ago days ago";
	}elsif($days_ago <= 7){
		my $s = $days_ago > 1 ? "s" : "";
		$r = "$days_ago day$s ago";
	}else{
		return $t->strftime("%Y-%m-%d");
	}

	if($days_ago < 3){
		$r .= " @ " . $t->strftime("%H:%M");
	}
	return $r;
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

	my $latest_str = timestamp_to_approx($latest);

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

		$extra = "$colours{duration}$extra$colours{off}";
	}

	my $types_desc = join(", ", @{$rec->{types}});
	my $s = $n > 1 ? "s" : "";
	my $severest_desc = $rec->{severest_desc};

	if($severest_desc){
		my $sev_col = $rec->{severity} >= SEV_major ? $colours{severity_major} : $colours{severity};
		$extra .= " $sev_col($severest_desc)$colours{off}";
	}
	my($ban_col, $ban_name) = ban_desc($ip);
	my $ip_col;
	if($ban_col){
		$ip_col = "$ban_col$ip$colours{off}";
		$extra .= " $ban_col($ban_name)$colours{off}";
	}else{
		$ip_col = "$colours{ip}$ip$colours{off}";
	}

	my $types_col = "$colours{types}$types_desc$colours{off}";
	print "$n fail$s for $ip_col ($types_col), latest $latest_str$extra\n";

	show_verbose($ip);
}
