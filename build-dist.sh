#!/bin/bash

cd ui
export PATH="./node_modules/.bin:$PATH"
yarn run build
