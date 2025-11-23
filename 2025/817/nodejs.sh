#!/bin/bash
#USER=ucjsgufh
DOMAIN=it.frii.site
VERSION=22

ls ~/nodevenv/domains/${DOMAIN}/public_html

if [ $? -eq 0 ]; then
  echo "nodejs app Found"
  exit
else
  echo "nodejs app not Found"
fi

pkill -f lsnode
#or
#pgrep -f lsnode | xargs kill -9

cloudlinux-selector create --json --interpreter=nodejs --domain=${DOMAIN} --app-root=public_html --app-uri=/ --version=${VERSION} --app-mode=Development --startup-file=app.js
#or
#cloudlinux-selector create --json --interpreter=nodejs --user=${USER} --app-root=public_html --app-uri=/ --version=${VERSION} --app-mode=Development --startup-file=app.js

cp -f ~/app.js ~/domains/${DOMAIN}/public_html
cp -f ~/package.json ~/domains/${DOMAIN}/public_html

source ~/nodevenv/domains/${DOMAIN}/public_html/${VERSION}/bin/activate && cd ~/domains/${DOMAIN}/public_html
npm i

curl -f "https://${DOMAIN}/info" > ~/nodejs.log
