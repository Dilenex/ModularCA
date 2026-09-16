#!/usr/bin/env bash
# Bind the lab domain controller to a ModularCA realm binding. Run as root on the DC after
# provision-dc.sh, once the realm exists on the ModularCA tenant page.
#
# Two ways to hand ModularCA the service key; both are worth exercising once.
#
#   Password path (ModularCA generated the password; you set it on the account):
#     ./bind-modularca.sh password 'the-password-modularca-showed-once'
#
#   Keytab path (the forest exports the key; you upload the file on the Keys tab):
#     ./bind-modularca.sh keytab            # writes /root/modularca-<spn>.keytab
#
# Either way the script prints the key version number (kvno) Active Directory holds for the
# account. ModularCA tries every live key version, so a mismatch does not break acceptance, but
# entering the right one keeps the Keys tab honest.
set -euo pipefail

MODE="${1:?password <pw> | keytab}"
SVC="${SVC:-svc-modularca-enroll}"
SPN="${SPN:-HTTP/ca4.maroongang.net}"
REALM="${REALM:-$(grep -m1 'default_realm' /etc/krb5.conf | awk '{print $3}')}"

case "$MODE" in
  password)
    PW="${2:?the password ModularCA generated}"
    samba-tool user setpassword "$SVC" --newpassword="$PW" >/dev/null
    echo "Password set on ${SVC}. ModularCA's derived keys match it if you chose account kind User and typed the same account name."
    ;;
  keytab)
    OUT="/root/modularca-$(echo "$SPN" | tr '/' '_').keytab"
    rm -f "$OUT"
    samba-tool domain exportkeytab "$OUT" --principal="${SPN}@${REALM}"
    chmod 600 "$OUT"
    echo "Keytab written to ${OUT}. Upload it on the realm's Keys tab (Upload a keytab file)."
    echo "Entries:"
    # ktutil is not always installed; the keytab format is what Kerberos.NET parses, so just show sizes.
    ls -l "$OUT"
    ;;
  *)
    echo "usage: $0 password <pw> | keytab" >&2; exit 2 ;;
esac

echo
echo "Key version number Active Directory holds for ${SVC}:"
samba-tool user show "$SVC" --attributes=msDS-KeyVersionNumber,msDS-SupportedEncryptionTypes,servicePrincipalName | grep -v '^dn:'
