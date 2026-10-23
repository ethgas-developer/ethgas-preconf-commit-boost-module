#!/bin/sh
set -eu

fixtures=${1:?Usage: check-ca-trust.sh FIXTURE_DIRECTORY [CA_BUNDLE]}
bundle=${2:-/etc/ssl/certs/ca-certificates.crt}
# Fix the verification time inside the fixtures' validity period so expiration
# cannot hide a regression in the trust store after May 2027.
verification_time=1792713600
checked=0
for chain in "$fixtures"/*-emudhra.we-have-a-problem.com.pem; do
    if result=$(openssl verify -purpose sslserver -attime "$verification_time" \
        -CAfile "$bundle" -no-CApath -no-CAstore -untrusted "$chain" "$chain" 2>&1); then
        echo "Compromised certificate chain is still trusted: $chain" >&2
        exit 1
    fi
    # Only issuer/trust failures count as protection; parse, validity, and
    # unsupported-algorithm errors must fail this check.
    if ! printf '%s\n' "$result" | grep -Eq 'error (2|18|19|20|21|28) at '; then
        printf '%s\n' "$result" >&2
        exit 1
    fi
    checked=$((checked + 1))
done
test "$checked" -eq 12
echo "System CA bundle rejects all 12 compromised eMudhra TLS chains."
