#!/bin/sh
set -eu

# Start the 389 DS instance in the background.
/usr/lib/dirsrv/dscontainer -r &
DS_PID=$!

# Wait for the LDAP port to answer.
i=0
while [ $i -lt 60 ]; do
    if ldapsearch -x -H ldap://localhost:3389 \
        -D 'cn=Directory Manager' -w bauble-admin \
        -b '' -s base '(objectClass=*)' >/dev/null 2>&1; then
        break
    fi
    sleep 2
    i=$((i + 1))
done

# Create the backend suffix if it does not already exist.
if ! ldapsearch -x -H ldap://localhost:3389 \
    -D 'cn=Directory Manager' -w bauble-admin \
    -b 'dc=bauble,dc=test' -s base '(objectClass=*)' >/dev/null 2>&1; then
    dsconf localhost backend create --suffix dc=bauble,dc=test --be-name bauble
    ldapadd -x -H ldap://localhost:3389 \
        -D 'cn=Directory Manager' -w bauble-admin \
        -f /seed-389.ldif
fi

wait $DS_PID
