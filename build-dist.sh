#!/bin/bash

cd ui
if [ ! -d "node_modules" ]; then
  npm install
fi

yarn run build
