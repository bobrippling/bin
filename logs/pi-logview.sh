#!/bin/sh

#(cat /var/log/auth.log.1; tac /var/log/auth.log) | while read day date time host process rest
#do
#	if echo "$process" | grep '^sshd\[' >/dev/null
#	then
#		echo "$day $date $time $host $process $rest"
#	fi
#done

usage(){
	echo >&2 "Usage: $0 [--[no-]colour] [--danger-only]"
	exit 2
}

black=30
blue=34
red=31
yellow=33
magenta=35
sed_month_to_num="s/Jan/01/; s/Feb/02/; s/Mar/03/; s/Apr/04/; s/May/05/; s/Jun/06/; s/Jul/07/; s/Aug/08/; s/Sep/09/; s/Oct/10/; s/Nov/11/; s/Dec/12/;"

verbose=0
danger_only=0
col_ret=0
if ! test -t 1
then col_ret=1
fi

# PAM_SERVICE=sshd
# PAM_RHOST=127.0.0.1
# PAM_USER=pi
# PAM_TYPE=open_session
# PAM_TTY=ssh|open_session|close_session
case "$PAM_TYPE" in
	open_session)
		# default to colour for PAM / logins
		col_ret=0
		;;
	close_session)
		exit 0
		;;
	*)
		# probably not run from pam
		;;
esac

for arg
do
	case "$arg" in
		--no-colour)
			col_ret=1
			;;
		--colour)
			col_ret=0
			;;
		--danger-only)
			danger_only=1
			;;
		-v)
			verbose=1
			;;
		*)
			usage
			;;
	esac
done

have_col(){
	return $col_ret
}

col_off(){
	have_col && printf '[m'
}

if have_col
then
	awk_colours='
		-v colour_off=\x1b[0m
		-v colour_green=\x1b[32m
		-v colour_blue=\x1b[34m
		-v colour_red=\x1b[31m
	'
else
	awk_colours=
fi

danger_level_to_colour(){
	# 0: ok, 1: warning, 2: alert
	case $1 in
		0) printf '[0;'$black'm' ;;
		1) printf '[0;'$yellow'm' ;;
		2) printf '[0;'$red'm' ;;
		*) printf '[0;'$red'm' ;;
	esac
}

if have_col && test $verbose -ne 0
then
	seq 0 3 | while read x
	do
		danger_level_to_colour $x
		printf '%s ' $x
	done
	col_off
	echo
fi

file_contents(){
	for f
	do
		case "$f" in
			*.gz) zcat "$f" ;;
			*) cat "$f"
		esac
	done
}

filter_ssh(){
	file_contents \
		/var/log/auth.log \
		/var/log/auth.log.1 \
		/var/log/auth.log.[2345].gz \
		| awk $awk_colours -v today="$(date '+%b %e')" '
		$5 ~ "sshd" {
				# Oct 20 10:10:10 <host> sshd[pid]: Accepted publickey for <user> from <ip> port <port> <proto>: <key-type> SHA256:<key>
				# 1   2  3        4      5          6        7         8   9      10   11   12   13     14       15         16
				# Sep 11 10:10:10 <host> sshd[pid]: Failed password for <user> from <ip> port <port> <proto>
				# 1   2  3        4      5          6      7        8   9      10   11   12   13     14
				# Dec 13 08:05:46 <host> sshd[pid]: Failed password for invalid user <user> from <ip> port <port> <proto>
				# 1   2  3        4      5          6      7        8   9       10   11     12   13   14   15     16
				# Dec 13 08:05:46 <host> sshd[pid]: (Bad|Did not|Invalid|Protocol|Unable)
				# 1   2  3        4      5          6
				# May 24 02:01:52 <host> sshd[pid]: Bad protocol version identification '\003' from 141.98.9.13 port 64384
				# 1   2  3        4      5          6

				if($6 == "Accepted"){
					auth[$11] = 1;
				} else if($6 == "Failed"){
					if($9 == "invalid" && $10 == "user") {
						ip = $13
						failed_users[ip] = $4 " (" $11 ")"
					} else {
						ip = $11
						failed_users[ip] = $4 " (" $9 ")"
					}

					failed[ip]++;
					failed_dates[ip] = $1 " " $2
					failed_times[ip] = $3
					failed_desc[ip] = "invalid user/pw"
				} else {
					i = match($0, "[0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*")
					#echo "match" i
					if (i > 0) {
						ip = substr($0, i, RLENGTH)
						failed[ip]++;
						failed_users[ip] = "?"
						failed_dates[ip] = $1 " " $2
						failed_times[ip] = $3
						failed_desc[ip] = $6 " " $7
					}
				}
		}

		END {
			sub("  ", " ", today) # "Feb  4" --> "Feb 4"

			for (ip in failed) {
				if (auth[ip]) {
					#print "ssh, failed (" failed[ip] " times) but auth'\''d: " ip
				} else {
					chosen_colour = failed_dates[ip] == today ? colour_red : colour_blue

					print "ssh, failed (" failed[ip] " times) and never auth'\''d! " ip \
						" (" chosen_colour "on " failed_dates[ip] " " colour_green \
						"" failed_times[ip] "" colour_off \
						", as " failed_users[ip] \
						", desc: " failed_desc[ip] ")"
				}
			}
		}
		' \
			| sed 's%on \([A-Za-z]*\) \([0-9]*\) %on yyyy/\1/\2 %; s%/\([0-9]\) %/0\1 %; '"$sed_month_to_num" \
			| sort -k 10
		# 06/Month/2022 --> 2022/Month/06
}

filter_http(){
	file_contents \
		/var/log/nginx/access.log \
		/var/log/nginx/access.log.1 \
		/var/log/nginx/access.log.2.gz \
		| awk $awk_colours '
			{
				if ($3 == "-") {
					unauth[$1]++

					ua = ""
					for(i = NF; i > 0; i -= 1) {
						ua = $i " " ua

						if(substr($i, 1, 1) == "\"")
							break
					}

					sub(" *$", "", ua)
					sub("[^(]*\(", "", ua)
					sub("\).*", "", ua)
					useragent_part[$1] = ua

					if (index($7, "/sibble") != 1 \
					&& index($7, "/favicon") != 1 \
					&& match($7, "/apple-touch-icon.*\\.png$") != 1)
					{
						private_access[$1] = 1
					}

					when = $4 " " $5
					sub(":", " ", when)
					gsub("[][]", "", when)
					date_part[$1] = when

				} else {
					auth[$1]++
				}
			}
			END {
				for (u in unauth) {
					if (auth[u]) {
						#print "http, auth'\''d: " u
					} else {
						desc = private_access[u] ? "" : " (" colour_green "public only" colour_off ")"
						print "http, never auth'\''d! " u " (" unauth[u] " times, on " colour_blue "" date_part[u] "" colour_off "" desc " from " useragent_part[u] ")"
					}
				}
			}
		' \
			| sed 's%\([0-9]*\)/\([A-Z][a-z]*\)/\([0-9]*\)%\3/\2/\1%;'"$sed_month_to_num" \
			| sort -k 8
		# 06/Month/2022 --> 2022/Month/06
}

filter_ssh
filter_http
