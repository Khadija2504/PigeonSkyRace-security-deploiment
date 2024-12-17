#!/bin/bash

echo "Starting Keycloak..."
/opt/keycloak/bin/kc.sh start-dev --http-port=8180 &

echo "Starting Jenkins..."
/usr/bin/tini -- /usr/local/bin/jenkins.sh
