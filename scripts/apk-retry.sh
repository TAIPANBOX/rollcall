# apk-retry.sh -- sourced inside the containers the feed scripts start, as `. /apk-retry.sh`.
#
# downloads.openwrt.org and the alpine mirrors cut a download off now and then, and apk itself
# never retries. So `apk` here is a function that runs the real one and, only when its output
# says a download was cut off, runs it again, up to eight times, with a pause that grows. Any
# other failure (an untrusted signature, a missing package, a conflict) returns at once with
# apk's own status and output, so a gate that expects apk to refuse still sees it refuse the
# first time.
#
# The output is apk's, stdout and stderr together, printed after each try. The same helper, with
# the same patterns, runs in the sibling project hermes-openwrt.
apk() {
	_ar_n=0
	while :; do
		# `|| _ar_rc=$?`, not `; _ar_rc=$?`: the scripts source this under set -e, and there a
		# failing command substitution ends the whole shell before the retry, and before apk's
		# own message is printed.
		_ar_rc=0; _ar_out=$(command apk "$@" 2>&1) || _ar_rc=$?
		[ -n "$_ar_out" ] && printf '%s\n' "$_ar_out"
		[ "$_ar_rc" -eq 0 ] && return 0
		case "$_ar_out" in
			*"Connection aborted"*|*"wget: exited with error"*|*"error 429"*|*"returned error: 429"*|*"Temporary failure"*|*"timed out"*|*"Connection reset"*) ;;
			# apk 3's own words for a fetch that failed on the way, not on the content
			*"temporary error"*|*"network error"*|*"remote server returned error"*|*"DNS lookup error"*|*"Connection refused"*|*"Network unreachable"*) ;;
			*) return "$_ar_rc" ;;
		esac
		_ar_n=$((_ar_n + 1))
		[ "$_ar_n" -lt 8 ] || return "$_ar_rc"
		echo "apk-retry: a download was cut off; try $((_ar_n + 1)) of 8 in $((_ar_n * 10)) s" >&2
		sleep $((_ar_n * 10))
	done
}
