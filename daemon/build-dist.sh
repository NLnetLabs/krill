#!/bin/bash

cd ui
if [ ! -d "node_modules" ]; then
  npm install
fi

if [ ! -d "ui/dist" ]; then
  yarn run build
fi
