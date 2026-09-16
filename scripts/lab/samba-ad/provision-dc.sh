#!/usr/bin/env bash
# Provision a Samba Active Directory domain controller for the MSAE Kerberos lab.
#
# Run as root inside a fresh Debian 12 container or VM with a static IP, or on a TurnKey
# Domain Controller appliance after its first-boot wizard. The container MUST be privileged:
# Samba AD stores Windows ACLs as extended attributes on SYSVOL and an unprivileged LXC cannot
# set them (provisioning dies with "Operation not permitted"). Idempotent enough to re-run after
# a failure; once /var/lib/samba/private/sam.ldb exists it only refreshes the lab accounts.
#
#   REALM=LAB.MSAE.TEST DOMAIN=LAB HOST_IP=192.168.1.10 ADMIN_PASSWORD='Lab-Admin-P@ss-1' \
#     DNS_FORWARDER=1.1.1.1 SPN=HTTP/ca4.maroongang.net ./provision-dc.sh
#
# What it leaves behind:
#   - a domain controller dc1.<realm> serving DNS (forwarding everything else upstream, so the
#     Windows client still resolves the public ca4 name), Kerberos and LDAP;
#   - service account svc-modularca-enroll, AES-only, holding the enrollment SPN. Its password is
#     NOT set here: ModularCA generates one on the tenant page and bind-modularca.sh applies it;
#   - test user alice / Alice-P@ss-1.
# Machines are created by joining, see client-enroll.ps1.
set -euo pipefail

REALM="${REALM:-LAB.MSAE.TEST}"
DOMAIN="${DOMAIN:-LAB}"
HOST_IP="${HOST_IP:?set HOST_IP to the static address of this host}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD for the domain Administrator}"
DNS_FORWARDER="${DNS_FORWARDER:-1.1.1.1}"
SPN="${SPN:-HTTP/ca4.maroongang.net}"
SVC="${SVC:-svc-modularca-enroll}"
DC_NAME="${DC_NAME:-dc1}"

lower_realm="$(echo "$REALM" | tr '[:upper:]' '[:lower:]')"
fqdn="${DC_NAME}.${lower_realm}"
base_dn="DC=$(echo "$lower_realm" | sed 's/\./,DC=/g')"

echo "==> Host identity: ${fqdn} (${HOST_IP})"
hostnamectl set-hostname "$fqdn" 2>/dev/null || echo "$fqdn" > /etc/hostname
sed -i "/[[:space:]]${DC_NAME}\(\.\| \|$\)/d" /etc/hosts
echo "${HOST_IP} ${fqdn} ${DC_NAME}" >> /etc/hosts

echo "==> Packages"
export DEBIAN_FRONTEND=noninteractive
# Pre-answer krb5-config so apt does not prompt; provisioning overwrites krb5.conf anyway.
debconf-set-selections <<EOF
krb5-config krb5-config/default_realm string ${REALM}
krb5-config krb5-config/kerberos_servers string ${fqdn}
krb5-config krb5-config/admin_server string ${fqdn}
EOF
apt-get update -q
apt-get install -y -q samba krb5-user winbind ldb-tools dnsutils chrony >/dev/null

echo "==> Stop the file-server units; the AD DC unit owns everything"
systemctl disable --now smbd nmbd winbind 2>/dev/null || true
systemctl unmask samba-ad-dc 2>/dev/null || true

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  echo "==> Provisioning ${REALM} (${DOMAIN})"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$ADMIN_PASSWORD" \
    --option="dns forwarder = ${DNS_FORWARDER}"
  cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
else
  echo "==> Domain already provisioned; refreshing lab objects only"
fi

echo "==> DNS: this host resolves through itself"
cat > /etc/resolv.conf <<EOF
search ${lower_realm}
nameserver 127.0.0.1
EOF

systemctl enable --now samba-ad-dc >/dev/null
sleep 3
systemctl is-active --quiet samba-ad-dc || { echo "samba-ad-dc failed to start"; journalctl -u samba-ad-dc --no-pager | tail -20; exit 1; }

echo "==> Sanity: DNS and Kerberos"
host -t SRV "_kerberos._udp.${lower_realm}" 127.0.0.1 | tail -1
echo "$ADMIN_PASSWORD" | kinit "administrator@${REALM}" && klist | head -3 && kdestroy

echo "==> Service account ${SVC} (AES only) with ${SPN}"
if ! samba-tool user show "$SVC" >/dev/null 2>&1; then
  # A placeholder password; bind-modularca.sh sets the one ModularCA generated.
  samba-tool user create "$SVC" --random-password \
    --description="ModularCA Windows autoenrollment (CES/CEP) service principal" >/dev/null
fi
samba-tool user setexpiry "$SVC" --noexpiry >/dev/null
# msDS-SupportedEncryptionTypes 0x18 = AES128 | AES256. No RC4 keys are ever issued for this account.
ldbmodify -H /var/lib/samba/private/sam.ldb <<EOF >/dev/null
dn: CN=${SVC},CN=Users,${base_dn}
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
EOF
samba-tool spn list "$SVC" 2>/dev/null | grep -qi "^ *${SPN}$" || samba-tool spn add "$SPN" "$SVC"

echo "==> Test user alice"
samba-tool user show alice >/dev/null 2>&1 || samba-tool user create alice 'Alice-P@ss-1' --given-name=Alice --surname=Lab >/dev/null
samba-tool user setexpiry alice --noexpiry >/dev/null

echo
echo "Domain controller ready."
echo "  Realm:            ${REALM}"
echo "  DNS domain:       ${lower_realm}"
echo "  DC / DNS server:  ${fqdn} (${HOST_IP})   <- point the Windows client's DNS here"
echo "  Service account:  ${SVC}   SPN: ${SPN}   (password not set yet: run bind-modularca.sh)"
echo "  Administrator:    ${DOMAIN}\\Administrator"
echo "  Test user:        alice / Alice-P@ss-1"
