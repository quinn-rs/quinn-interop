#!/usr/bin/env bash

/setup.sh

if [ "${ROLE}" == "client" ]; then
    echo "Executing client"
    /wait-for-it.sh sim:57832 -s -t 30
    sleep 3
    ./client 2>&1 > ${CLIENT_LOGS}/logs.txt
elif [ "${ROLE}" == "server" ]; then
    echo "Executing server"
    ./server 2>&1 > ${SERVER_LOGS}/logs.txt
else
    exit 127
fi
