#!/bin/sh
set -eu

mkdir -p /run/slapd
chown -R openldap:openldap /run/slapd /var/lib/bauble-ldap

# The DIT is preloaded at build time via slapadd; just serve it.
slapd -f /etc/ldap/slapd.conf -h "ldap:/// ldaps:/// ldapi:///" -u openldap -g openldap

exec sleep infinity
