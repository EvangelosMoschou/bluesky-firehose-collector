#!/bin/sh
# Regenerate the seed corpus for the Jetstream classifier.
#
# Real frames are not committed to this repository (the 24-hour dataset is
# aggregate metrics), so the corpus is synthesised to cover the shapes the
# classifier actually branches on, plus the malformed shapes a hostile peer
# would send.

set -e
cd "$(dirname "$0")"
rm -rf corpus
mkdir -p corpus

w() { printf '%s' "$2" > "corpus/$1"; }

# --- well-formed frames, one per counter -----------------------------------
w 01_commit '{"did":"did:plc:abc","time_us":1727000000000000,"kind":"commit","commit":{"rev":"3kxyz","operation":"create","collection":"app.bsky.feed.post","rkey":"3kabc","record":{"$type":"app.bsky.feed.post","text":"hello","createdAt":"2026-09-26T10:00:00.000Z"},"cid":"bafyrei"}}'

w 02_identity '{"did":"did:plc:abc","time_us":1727000000000001,"kind":"identity","identity":{"did":"did:plc:abc","handle":"user.bsky.social","seq":12345,"time":"2026-09-26T10:00:00.000Z"}}'

w 03_account '{"did":"did:plc:abc","time_us":1727000000000002,"kind":"account","account":{"active":true,"did":"did:plc:abc","seq":12346,"status":"active","time":"2026-09-26T10:00:00.000Z"}}'

w 04_unknown_kind '{"did":"did:plc:abc","time_us":1,"kind":"mystery"}'

# --- shapes that must classify as info, not crash ---------------------------
w 05_empty_object '{}'
w 06_not_object '[]'
w 07_bare_string '"kind":"commit"'
w 08_empty ''
w 09_kind_not_string '{"kind":1}'
w 10_kind_null '{"kind":null}'
w 11_kind_dup '{"kind":"commit","kind":"identity"}'
w 12_kind_nested '{"a":{"kind":"commit"}}'
w 13_kind_last '{"did":"x","time_us":1,"commit":{"rev":"r"},"kind":"commit"}'

# --- hostile / malformed ----------------------------------------------------
w 14_unterminated_string '{"kind":"commit'
w 15_unterminated_key '{"kind'
w 16_unterminated_escape '{"kind":"commit\\'
w 17_lone_backslash '{"kind":"\\"}'
w 18_nul_in_middle '{"kind":"com'
w 19_truncated_object '{"did":"x","kind":"commit","commit":{"rev":"3k'
w 20_bad_utf8 '{"kind":"commit","x":"\xff\xfe\xfd"}'
w 21_high_bytes '{"kind":"commit","x":"\x81\x82\x83"}'
w 22_escaped_unicode '{"kind":"\\u0063ommit"}'
w 23_deep_arrays '{"kind":"commit","a":[[[[[[[[[[1]]]]]]]]]]}'
w 24_deep_objects '{"kind":"commit","a":{"b":{"c":{"d":{"e":{"f":1}}}}}}'
w 25_long_string '{"kind":"commit","text":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
w 26_many_keys '{"kind":"commit","a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8}'
w 27_colon_no_value '{"kind":}'
w 28_trailing_comma '{"kind":"commit",}'
w 29_numbers '{"kind":"commit","n":-1.5e309,"m":0.0,"o":12345678901234567890}'
w 30_control_chars '{"kind":"commit","x":"\x01\x02\x03"}'

# Token exhaustion: more objects than JETSTREAM_MAX_TOKENS (256), which drives
# jsmn into its "ran out of slots" path while the scan is still walking tokens.
{
    printf '{"kind":"commit"'
    i=0
    while [ "$i" -lt 300 ]; do printf ',"k%s":%s' "$i" "$i"; i=$((i + 1)); done
    printf '}'
} > corpus/31_token_exhaustion

echo "wrote $(ls corpus | wc -l) seeds to $(pwd)/corpus"
