#!/bin/bash

PASSDB=$(/usr/bin/tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
# /usr/bin/sed -i "s/\(neo4j\/\).*/\1${PASSDB}/" ./neo4j_auth.txt
echo "neo4j/$PASSDB" > ./neo4j_auth.txt

/usr/bin/sudo /usr/bin/docker-compose up -d --build

echo """
===================================== DONE! =====================================

To login to the Web Weasel web interface, open your browser and go to:
http://localhost:8000

Login with the following credentials:
  Username: admin
  Password: admin

CHANGE THE DEFAULT PASSWORD IMMEDIATELY AFTER LOGGING IN!

=================================================================================
"""