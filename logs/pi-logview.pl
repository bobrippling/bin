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
my %cfg;
my $cachepath;

# XDG_CONFIG_HOME (default ~/.config)
# XDG_STATE_HOME (default ~/.local/state)
# XDG_CACHE_HOME (default ~/.cache)
sub path_cache {
	my $name = shift();

	my $f = $ENV{XDG_CACHE_HOME}
		? "$ENV{XDG_CACHE_HOME}/$name"
		: $HOME
		? "$HOME/.$name"
		: "/var/lib/$name";

	warn "$0: cache @ \"$f\"\n" if $debug;
	return $f;
}

sub path_config {
	my $name = shift();
	my @paths;

	# we're reading, so look for one that exists first
	push @paths, "$ENV{XDG_CONFIG_HOME}/$name" if $ENV{XDG_CONFIG_HOME};
	push @paths, "$HOME/.$name" if $HOME;
	push @paths, "/etc/$name";

	for(@paths){
		if(-e $_){
			warn "$0: found config @ \"$_\"\n" if $debug;
			return $_
		}
	}

	my $r;
	if($ENV{XDG_CONFIG_HOME}){
		if(!mkdir $ENV{XDG_CONFIG_HOME} && $! !~ /exists/i){
			die "mkdir $ENV{XDG_CONFIG_HOME}: $!";
		}
		$r = "$ENV{XDG_CONFIG_HOME}/$name";
	}elsif($HOME){
		$r = "$HOME/.$name";
	}else{
		$r = "/etc/$name";
	}

	warn "$0: no config, creating @ \"$r\"\n" if $debug;
	return $r;
}

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

sub dirname {
	my $d = shift();
	return $1 if $d =~ m;/([^/]+)/?$;;
	return $d;
}

sub debug_time {
	my($name, $f, @args) = @_;
	if($debug == 0){
		$f->(@args);
		return;
	}
	my $now = gettimeofday();
	$f->(@args);
	my $fin = gettimeofday();
	my $diff = sprintf("%.3f", $fin - $now);
	print STDERR "$0: ${diff}ms for $name\n";
}

sub ip_record {
	my $ip = shift();

	my $obj = IpAddr->parse($ip);
	my $canon = $obj->{canon};

	if(!exists $ip_records{$canon}){
		$ip_records{$canon} = { parsed => $obj };
	}

	return $ip_records{$canon};
}

sub add_auth {
	my($ip, $type) = @_;
	ip_record($ip)->{authed}->{$type}++;
}

sub add_fail {
	my ($type, $ip, $host, $user, $timestamp, $desc, $desc_sev) = @_;

	push @{ip_record($ip)->{fails}}, {
		type => $type,
		host => $host,
		user => $user,
		timestamp => $timestamp,
		desc => $desc,
		desc_sev => $desc_sev,
	};
}

sub auth_log_paths {
	my($all) = @_;
	return (
		'/var/log/auth.log',
		'/var/log/auth.log.1',
		glob(
			$all
			? '/var/log/auth.log.[0-9].gz'
			: '/var/log/auth.log.[2345].gz'
		),
	);
}

sub parse_ssh {
	my @contents = file_contents(auth_log_paths(0));
	my $found_openssh = 0;
	my $found_dropbear = 0;

	for my $line (@contents){
		my @parts = split /\s+/, $line;
		my $off = 2;

		if($parts[$off] =~ '^sshd'){
			$found_openssh = 1;
			parse_openssh($off, $line, @parts);
		}elsif($parts[$off] =~ /^dropbear/){
			$found_dropbear = 1;
			parse_dropbear($off, $line, @parts);
		}
	}

	warn "$0: no sshd entries found in `auth.log`s!\n" unless $found_openssh;
	warn "$0: no dropbear entries found in `auth.log`s!\n" unless $found_dropbear;
}

sub parse_auth_timestamp {
	(my $when = shift()) =~ s/\.\d+\+\S*//; # ditch ms & tz
	my $timestamp = parse_time("%Y-%m-%dT%H:%M:%S", $when);
	if($timestamp > $today){
		$timestamp = $timestamp->add_years(-1);
	}
	return $timestamp;
}

sub parse_dropbear {
	my ($off, $line, @parts) = @_;

	my $user = undef;
	if($off + 5 < $#parts){
		($user = $parts[$off + 5]) =~ s/^'|'$//;
	}

	my $ip = undef;
	my $port = undef;
	if($parts[$#parts] =~ /(.*):(\d+)$/){
		$ip = $1;
		$port = $2;
	}elsif($line =~ /<(\d[^>]*|[0-9:]+):(\d+)>:/){
		$ip = $1; #$ipv6 = 1 if $ip =~ /:/;
		$port = $2;
		if(!defined($user) && $line =~ /user '([^']+)'/){
			$user = $1;
		}
	}

	if("$parts[$off + 2] $parts[$off + 3]" eq "auth succeeded"){
		my $type = $parts[$off + 1]; # Pubkey | Password
		add_auth($ip, "dropbear ($type)");
	}elsif($parts[$off + 1] eq "Bad"){
		my $timestamp = parse_auth_timestamp($parts[0]);

		my $desc = "invalid user/pw";
		my $desc_sev = SEV_LOGIN_ATTEMPT;
		add_fail("dropbear", $ip, undef, $user, $timestamp, $desc, $desc_sev);
	}else{
		my $msg = join(" ", @parts[$off + 1 ... $#parts]);
		return if $msg =~ m;^Failed loading /etc/dropbear/dropbear_dss_host_key *$;;
		return if $msg =~ /^Exit \(.*\) from <.*>: Disconnect received *$/;
		return if $msg =~ /^Exit \(.*\) from <.*>: Exited normally *$/;
		return if $msg =~ /^Early exit: /;
		return if $msg =~ /^Failed listening on '/;
		return if $msg =~ /^Running in background/;

		if(!defined($ip)){
			warn "$0: unknown dropbear auth-log line with no IP: \"$msg\"\n";
			return;
		}

		# The main one we pick up here is "Child connection from ..."
		# But also "Exit before auth from <ip:port>: (user '<user>', 1 fails): Exited normally"

		my $timestamp = parse_auth_timestamp($parts[0]);
		my $desc = "unknown ($msg)";
		my $desc_sev = SEV_UNKNOWN;
		add_fail("dropbear", $ip, undef, undef, $timestamp, $desc, $desc_sev);
	}
}

sub parse_openssh {
	# old format:
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

	# new format:
	# 2024-04-28T09:00:00.000000+00:00 <host> sshd[pid]: Accepted publickey for <user> from <ip> port <port> <proto>: <key-type> SHA256:<key>
	my ($off, $line, @parts) = @_;

	if($parts[$off + 1] eq "Accepted"){
		my $ip = $parts[$off + 6];
		add_auth($ip, "ssh");
	}elsif($parts[$off + 1] eq "Failed"){
		my $ip;
		my $host = $parts[$off + -1];
		my $user;

		if($parts[$off + 4] eq "invalid" && $parts[$off + 5] eq "user") {
			$ip = $parts[$off + 8];
			$user = $parts[$off + 6];
		} else {
			$ip = $parts[$off + 6];
			$user = $parts[$off + 4];
		}

		my $desc = "invalid user/pw";
		my $desc_sev = SEV_LOGIN_ATTEMPT;

		my $timestamp = parse_auth_timestamp($parts[0]);
		add_fail("ssh", $ip, $host, $user, $timestamp, $desc, $desc_sev);

	}elsif($line =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/){
		my $ip = $&;
		my $host = "?";
		my $user = "?";

		my $desc;
		my $desc_sev;

		if("$parts[$off + 1] $parts[$off + 2]" eq "Connection closed"){
			$desc = "eof";
			$desc_sev = SEV_DISCONNECT;
		}elsif($parts[$off + 1] eq "Disconnected"){
			my $user = $parts[$off + 4];
			$desc = "disconnect:$user";
			$desc_sev = SEV_DISCONNECT_POSTAUTH;
		}elsif("$parts[$off + 1] $parts[$off + 2]" eq "Invalid user"){
			my $user = $parts[$off + 3];
			$desc = "invalid:$user";
			$desc_sev = SEV_LOGIN_ATTEMPT;
		}elsif(
			join(" ", @parts[$off + 1 .. $off + 4]) eq "PAM 1 more authentication" ||
			$parts[$off + 1] eq "pam_unix(sshd:auth):"
		){
			my %pam = (
				tty => "<unknown>",
				user => "<unknown>",
			);
			for my $eq (@parts[$off + 4 .. $#parts]){
				if($eq =~ /(.*)=(.*)/){
					$pam{$1} = $2;
				}
			}
			$desc = "pam:$pam{tty},$pam{user}";
			$desc_sev = SEV_LOGIN_ATTEMPT;
		}elsif("$parts[$off + 1] $parts[$off + 2]" eq "Received disconnect"){
			$desc = "disconnect-no-user";
			$desc_sev = SEV_DISCONNECT;
		}elsif("$parts[$off + 1] $parts[$off + 2]" eq "banner exchange:"){
			$desc = "banner-exchange";
			$desc_sev = SEV_PROTO_MISMATCH;
		}elsif("$parts[$off + 1] $parts[$off + 2]" eq "Connection reset"){
			$desc = "conn-reset";
			$desc_sev = SEV_DISCONNECT;
		}elsif("$parts[$off + 1] $parts[$off + 2] $parts[$off + 3] $parts[$off + 4]" eq "Unable to negotiate with"){
			$desc = "negotiation-fail";
			$desc_sev = SEV_PROTO_MISMATCH;
		}elsif("$parts[$off + 1] $parts[$off + 2]" eq "Server listening"){
			return;
		}else{
			$desc = "unknown ($parts[$off + 1] $parts[$off + 2])";
			$desc_sev = SEV_UNKNOWN;
		}

		my $timestamp = parse_auth_timestamp($parts[0]);
		add_fail("ssh", $ip, $host, $user, $timestamp, $desc, $desc_sev);
	}
}

sub nginx_log_paths {
	my($all) = @_;
	my $silence_skip = $all;

	my %paths;

	%paths = (
		'/var/log/nginx/access.log' => 1,
		'/var/log/nginx/access.log.1' => 1,
		'/var/log/nginx/access.log.2.gz' => 1,
	);

	if($all){
		$paths{$_} = 1 for glob '/var/log/nginx/access.log.[0-9]*.gz';
	}

	for(keys %paths){
		delete $paths{$_} unless -e $paths{$_};
	}

	outer:
	for my $d (glob('/var/log/nginx/*/')){
		my $dir = dirname($d);
		if(exists $cfg{skip_paths}->{$dir}){
			warn "$0: skipping $d\n" if $debug && !$silence_skip;
			next outer
		}

		my $dh;
		if(!opendir($dh, $d)){
			warn "$0: open $d: $!\n";
			continue;
		}
		my @ents = map { "$d/$_" } grep /^access\.log/, readdir($dh);
		closedir($dh);

		if($all){
			$paths{$_} = 1 for @ents;
		}else{
			for(@ents){
				$paths{$_} = 1 if /\.log(\.(1|2\.gz))?$/;
			}
		}
	}

	return keys %paths;
}

sub parse_http {
	for my $fname (nginx_log_paths(0)) {
		debug_time("parse http, $fname", \&parse_http_1, $fname);
	}
}

sub parse_http_1 {
	my $fname = shift;
	my @contents = file_contents($fname);

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
			if($path =~ /$cfg{public}/){
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

sub knockd_log_paths {
	my($all) = @_;
	return (
			'/var/log/knockd.log',
			'/var/log/knockd.log.1',
			glob(
				$all
				? '/var/log/knockd.log.[0-9].gz'
				: '/var/log/knockd.log.[12345].gz'
			),
	);
}

sub parse_knockd {
	my @contents = file_contents(knockd_log_paths(0));
	my $found = 0;

	for(@contents){
		next unless /^\[(\S+ \S+)\] (\S+): \S+: (Stage [123]$|OPEN SESAME)/;
		my ($time, $ip, $what) = ($1, $2, $3);

		if($what =~ /Stage 3$|OPEN SESAME$/){
			add_auth($ip, "knockd");
		}elsif($what =~ /Stage 1$/){
			# ignore
		}else{
			my $timestamp = parse_time("%Y-%m-%d %H:%M", $time);
			add_fail("knockd", $ip, undef, undef, $timestamp, undef, SEV_UNKNOWN);
		}

		$found = 1;
	}

	warn "$0: no knockd entries found!\n" unless $found;
}

sub parse_podsync {
	my @paths = (
		'/var/log/podsync/podsync.log',
		'/var/log/podsync/podsync.log.1',
		glob('/var/log/podsync/podsync.log.[0-9]*.gz'),
	);
	my @contents = file_contents(@paths);
	my $found = 0;

	for(@contents){
		next unless /^\s*(\S+)\s[^>]*> (.*)/;
		my ($what, $rest) = ($1, $2);

		my $ip;
		my $port;
		my $time;
		if($rest =~ m%(\S+):(\d+) (\d+-\d+\S*T\S+)\s%){
			$ip = $1;
			$port = $2;
			$time = $3;
		}

		if($what eq 'INFO'){
			# ignore
			add_auth($ip, "podsync") if defined $ip;
		}else{
			my $timestamp = defined($time) ? parse_time("%Y-%m-%dT%H:%M:%SZ", $time) : undef;
			add_fail("podsync", $ip, undef, undef, $timestamp, undef, SEV_UNKNOWN);
		}

		$found = 1;
	}

	warn "$0: no podsync entries found!\n" unless $found;
}

sub parse_fail2bans_slow {
	if(open(my $fh, '-|', '/usr/local/bin/doas /usr/bin/fail2ban-client-su banned')){
		chomp(my $json = join ",", <$fh>);
		$json =~ s/][^[]*\[/,/g; # sep
		$json =~ s/^\[[^[]*\[//; # start
		$json =~ s/][^]]*\]$//; # end
		$json =~ s/'//g;

		my @ips = grep { length } split /,+/, $json;
		push @fail2banned, map { s/^ *//; s/ *$//; IpAddr->parse($_) } @ips;
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
				@fail2banned = map { chomp; IpAddr->parse($_) } <$fh>;
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

sub banned_type {
	my $ip = shift;

	for my $entry (@banned){
		return 1 if $ip->matches_cidr($entry);
	}
	for my $entry (@fail2banned){
		return 2 if $ip->eq($entry);
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
		'-Fw',
		$ip,
		nginx_log_paths(1),
		auth_log_paths(1),
		knockd_log_paths(0), # 0 is intended here
	);

	system("$cmd | sed 's/^/\t/'");
}

sub read_cfg {
	my $f = path_config("pi-logview.cfg");
	my %cfg;

	my $fh;
	if(!open($fh, '<', $f)){
		warn "$0: open $f: $!\n";
		return;
	}
	while(<$fh>){
		s/#.*//;
		s/\s+$//;

		next unless length;

		if(/^public:\s*(.*)/){
			$cfg{public} = $1;
		}elsif(/^skip_paths:\s*(.*)/){
			for my $d (split / /, $1){
				$cfg{skip_paths}->{$d} = 1;
			}
		}else{
			die "$ARGV:$.: unknown config line\n";
		}
	}
	close($fh);

	return %cfg;
}

sub unreachable {
	die "unreachable"
}

package IpAddr {
	use overload '""' => \&stringify; # package-local

	sub parse {
		my ($pkg, $s) = @_;

		# ipv6
		if(index($s, ":") >= 0){
			# parse [::1] and ::1
			$s =~ s/^\[(.*)\]$/$1/;

			my $colon_cnt = ((my $discard = $s) =~ s/://g);
			my $orig = $s;
			if($colon_cnt != 8){
				my $replace = ":" x (8 - $colon_cnt + 1);
				#print "padding \"$s\" to ";
				$s =~ s/::/$replace/;
				#print "\"$s\"\n";
			}

			my @u16s = map { oct($_ ? "0x$_" : 0) } split(/:/, $s);

			#print
			#	"parsed $orig into: "
			#	. join(":", map { sprintf "%x", $_ } @u16s)
			#	. "\n";

			# canon isn't the easiest to read, but it's only used for hash lookup
			my $canon = join(":", map { sprintf "%x", $_ } @u16s);

			return bless {
				type => 6,
				orig => $orig,
				u16s => \@u16s,
				canon => $canon,
			};
		}

		my @octets = split(/\./, $s);

		return bless {
			type => 4,
			orig => $s,
			val => hex(join("", map { sprintf "%02x", $_ } @octets)),
			canon => join(".", map { sprintf "%d", $_ } @octets),
		};
	}

	sub matches_cidr {
		my($self, $cidr) = @_; # (_, string)

		my $cidr_type = $cidr =~ /:/ ? 6 : 4;
		return 0 if $cidr_type != $self->{type};
		my $addrlen = $self->{type} == 4 ? 32 : 128;

		my($cidr_addr, $mask);
		if($cidr =~ m@(.*)/(.*)@){
			$cidr_addr = $1;
			$mask = $2;
		}else{
			$cidr_addr = $cidr;
			$mask = $addrlen;
		}
		my $shift = $addrlen - $mask;

		if($self->{type} == 6){
			$cidr_addr = IpAddr->parse($cidr_addr);
			unreachable() if $cidr_addr->{type} != 6;

			my @self_u16s = @{$self->{u16s}};
			my @cidr_u16s = @{$cidr_addr->{u16s}};

			# shift is in bits, we compare u16s
			my $last_u16_index = 8 - $shift / 16;

			#print "  # shift = $shift\n";
			#print "  # last_u16_index = $last_u16_index (max = 8)\n";
			for(my $i = 0; $i < $last_u16_index; $i++){
				# final (subset) of bits?
				if($i + 1 >= $last_u16_index){
					my $mask = ~0 << $shift;
					my $self_u16 = $self_u16s[$i] & $mask;
					my $cidr_u16 = $cidr_u16s[$i] & $mask;

					#printf
					#	"  # %#x == %#x ?\n"
					#	. "  # mask=%#x from: shift=$shift\n"
					#	. "  # --> %#x == %#x\n"
					#	,
					#	$self_u16s[$i],
					#	$cidr_u16s[$i],
					#	$mask,
					#	$self_u16,
					#	$cidr_u16,
					#	;

					return 0 unless $self_u16 == $cidr_u16;
				}else{
					return 0 unless $self_u16s[$i] == $cidr_u16s[$i];
					#printf "  # %#x == %#x\n", $self_u16s[$i], $cidr_u16s[$i];
				}
			}

			return 1;

		}elsif($self->{type} == 4){
			my $cidr_addr_hex = IpAddr->parse($cidr_addr)->{val};
			my $cidr_addr_hex_shifted = $cidr_addr_hex >> $shift;

			my $self_shifted = $self->{val} >> $shift;

			return $cidr_addr_hex_shifted == $self_shifted;
		}else{
			unreachable();
		}
	}

	sub eq {
		my ($self, $other) = @_;

		return 0 unless $self->{type} == $other->{type};

		return $self->{val} == $other->{val} if $self->{type} == 4;

		if($self->{type} == 6){
			my @a = @{$self->{u16s}};
			my @b = @{$other->{u16s}};
			for(my $i = 0; $i < @a; $i++){
				return 0 unless $a[$i] == $b[$i];
			}
			return 1;
		}

		unreachable();
	}

	sub stringify {
		my($self) = @_;

		return $self->{orig};
	}
}

$cachepath = path_cache("pi-logview.cache");

debug_time("parse cfg", sub { %cfg = read_cfg() });

debug_time("parse ssh", \&parse_ssh);
debug_time("parse http", \&parse_http);
debug_time("parse knockd", \&parse_knockd);
debug_time("parse podsync", \&parse_podsync);
parse_banned();

if($filter_cidr){
	my $found = 0;
	for my $ip (keys %ip_records){
		my $rec = $ip_records{$ip};
		$ip = $ip_records{$ip}->{parsed};
		next unless $ip->matches_cidr($filter_cidr);
		$found = 1;

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
	for my $ip_canon (keys %ip_records) {
		my $rec = $ip_records{$ip_canon};
		if ($rec->{authed}) {
			my $n = 0;
			for my $type (keys %{$rec->{authed}}){
				$n += $rec->{authed}->{$type};
			}
			my $types = join(", ", keys %{$rec->{authed}});
			print "$colours{ip}$rec->{parsed}$colours{off} authed, $n accesses over $colours{types}$types$colours{off}\n";
		}
	}
}

my @sorted;
for my $ip_canon (keys %ip_records) {
	my $rec = $ip_records{$ip_canon};
	my $ip = $rec->{parsed};

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
