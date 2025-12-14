#!/bin/bash

/usr/bin/sudo /usr/bin/apt install docker.io docker-compose -y

PASSDB=$(/usr/bin/tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
echo "neo4j/$PASSDB" > ./neo4j_auth.txt

/usr/bin/sudo /usr/bin/docker-compose up -d --build

echo '===================================== DONE! ====================================='
echo ''
echo 'To login to the Web Weasel web interface, open your browser and go to:'
echo 'http://localhost:8000'
echo ''
echo 'Login with the following credentials:'
echo '  Username: admin'
echo '  Password: admin'
echo ''
echo 'CHANGE THE DEFAULT PASSWORD IMMEDIATELY AFTER LOGGING IN!'
echo ''
echo '================================================================================='
