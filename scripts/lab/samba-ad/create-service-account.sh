#!/usr/bin/env bash
# Create (or refresh) only the enrollment service account on a Samba AD DC.
#
#   ./create-service-account.sh svc-lab-msae 'password-modularca-generated'
#   ./create-service-account.sh svc-lab-msae                 # keep the current password
#
# Leaves: an AES-only account with no expiry holding SPN=HTTP/ca4.maroongang.net (override
# with SPN=...). Prints the key version number so the ModularCA Keys tab can match it.
set -euo pipefail

ACCOUNT="${1:?account name, e.g. svc-lab-msae}"
PASSWORD="${2:-}"
SPN="${SPN:-HTTP/ca4.maroongang.net}"

# Samba's base DN, from its own view of the domain.
base_dn="$(samba-tool domain info 127.0.0.1 2>/dev/null | awk -F': ' '/^Domain *:/{print $2}' | sed 's/\./,DC=/g; s/^/DC=/')"
[ -n "$base_dn" ] || base_dn="$(ldbsearch -H /var/lib/samba/private/sam.ldb -s base defaultNamingContext 2>/dev/null | awk '/^defaultNamingContext:/{print $2}')"

if ! samba-tool user show "$ACCOUNT" >/dev/null 2>&1; then
  if [ -n "$PASSWORD" ]; then
    samba-tool user create "$ACCOUNT" "$PASSWORD" --description="ModularCA Windows autoenrollment (CES/CEP) service principal" >/dev/null
  else
    samba-tool user create "$ACCOUNT" --random-password --description="ModularCA Windows autoenrollment (CES/CEP) service principal" >/dev/null
  fi
  echo "created ${ACCOUNT}"
elif [ -n "$PASSWORD" ]; then
  samba-tool user setpassword "$ACCOUNT" --newpassword="$PASSWORD" >/dev/null
  echo "password set on ${ACCOUNT}"
fi

samba-tool user setexpiry "$ACCOUNT" --noexpiry >/dev/null

# msDS-SupportedEncryptionTypes 0x18 = AES128 | AES256; no RC4 key is ever issued for this account.
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<EOF
dn: CN=${ACCOUNT},CN=Users,${base_dn}
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
EOF

samba-tool spn list "$ACCOUNT" 2>/dev/null | grep -qi "^ *${SPN}\$" || samba-tool spn add "$SPN" "$ACCOUNT"

echo
samba-tool user show "$ACCOUNT" --attributes=sAMAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes,msDS-KeyVersionNumber | grep -v '^dn:'
