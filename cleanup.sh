#!/bin/bash


read -p "This script will stop all Web Weasel containers and DELETE ALL DATA. Continue? (y/n) " choice

if [[ $choice == y || $choice == Y ]] then
    /usr/bin/sudo /usr/bin/docker stop neo4j
    /usr/bin/sudo /usr/bin/docker container prune
    /usr/bin/sudo /usr/bin/docker builder prune
    /usr/bin/sudo /usr/bin/docker network prune
    /usr/bin/sudo /usr/bin/docker image prune
    /usr/bin/sudo rm -r neo4j
else
    echo "[!] Quitting script..."
fi
