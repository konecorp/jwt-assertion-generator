#!/bin/bash

if [[ -z "$ISSUER" || -z "$SUBJECT" || -z "$AUDIENCE" || ! -f "$KEY" ]]; then
  echo "Usage: AUDIENCE=your_audience ISSUER=your_issuer SUBJECT=your_subject KEY=/path/to/your_private.key $0"
  exit 1
fi

uuid=
function generateUuid()
{
    local N B T X
    for (( N=0; N < 16; ++N )); do
        B=$(( $RANDOM%255 ))
        if (( N == 6 )); then
            printf -v X '4%x' $(( B%15 ))
            uuid+=$X
        elif (( N == 8 )); then
            local C='89ab'
            printf -v X '%c%x' ${C:$(( $RANDOM%${#C} )):1} $(( B%15 ))
            uuid+=$X
        else
            printf -v X '%02x' $B
            uuid+=$X
        fi
        for T in 3 5 7 9; do
            if (( T == N )); then
                uuid+='-'
                break
            fi
        done
    done
}

generateUuid

EXPIRY="$(date '+%s' -d "3600 seconds")"
JTI="$uuid"
HEADER="{\"alg\":\"RS256\"}"
BODY="{\"iss\": \"${ISSUER}\", \"sub\": \"${SUBJECT}\", \"aud\": \"${AUDIENCE}\", \"exp\": ${EXPIRY}, \"jti\": \"${JTI}\"}"

TOKEN="$(printf "%s" "$HEADER" | openssl base64 -A | tr '+/' '-_' | tr -d '=').$(printf "%s" "$BODY" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

SIGN="$(printf "%s" "$TOKEN" | openssl dgst -sha256 -sign "${KEY}" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

echo "${TOKEN}.${SIGN}"
