#!/bin/bash

echo "Starting Keycloak..."
/opt/keycloak/bin/kc.sh start-dev --http-port=8180 &

echo "Starting Jenkins..."
/usr/bin/tini -- /usr/local/bin/jenkins.sh

/opt/keycloak/bin/kc.sh start-dev &
sleep 10
/opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/keycloak-realm.json
tail -f /dev/null
