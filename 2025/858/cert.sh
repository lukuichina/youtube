#!/bin/bash
ACCOUNT_ID=account id
ACCOUNT_EMAIL=email
ACCOUNT_KEY=Global API Key

WORKER_DOMAIN=*.domain.com
WORKER_NAME=worker name
ZONE_ID=zone id

curl https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/domains \
    -X PUT \
    -H 'Content-Type: application/json' \
    -H "X-Auth-Email: $ACCOUNT_EMAIL" \
    -H "X-Auth-Key: $ACCOUNT_KEY" \
    -d '{
          "hostname": "'$WORKER_DOMAIN'",
          "service": "'$WORKER_NAME'",
          "zone_id": "'$ZONE_ID'",
          "environment": "production"
        }' > cert.log
