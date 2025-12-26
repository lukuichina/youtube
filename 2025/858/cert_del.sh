#!/bin/bash
ACCOUNT_ID=account id
ACCOUNT_EMAIL=email
ACCOUNT_KEY=Global API Key
DOMAIN_ID=domain id

curl https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/domains/$DOMAIN_ID \
    -X DELETE \
    -H "X-Auth-Email: $ACCOUNT_EMAIL" \
    -H "X-Auth-Key: $ACCOUNT_KEY" > cert_del.log
