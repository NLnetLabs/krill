#!/bin/bash

DIR=`dirname $0`

cd $DIR/ui
if [ ! -d "node_modules" ]; then
  npm install
fi

yarn run build
