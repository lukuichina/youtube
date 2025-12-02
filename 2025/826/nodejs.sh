#!/bin/bash
DOMAIN=domain.com
WAITING=120

mv ~/nodevenv/domains/${DOMAIN} ~/nodevenv/domains/${DOMAIN}_bak

date;sleep ${WAITING};date

mv ~/nodevenv/domains/${DOMAIN}_bak ~/nodevenv/domains/${DOMAIN}

curl "https://${DOMAIN}/info" > ~/nodejs.log
