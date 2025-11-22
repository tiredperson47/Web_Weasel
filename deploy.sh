#!/bin/bash

PASSDB=$(/usr/bin/tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
# /usr/bin/sed -i "s/\(neo4j\/\).*/\1${PASSDB}/" ./neo4j_auth.txt
echo "neo4j/$PASSDB" > ./neo4j_auth.txt

/usr/bin/sudo /usr/bin/docker-compose up -d --build

echo
echo '===================================== DONE! ====================================='
echo ''