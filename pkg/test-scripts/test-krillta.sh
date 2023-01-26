#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nKRILLTA VERSION:"
    krillta --version

    echo -e "\nKRILLTA MAN PAGE:"
    man -P cat krillta
    ;;

  post-upgrade)
    ;;
esac
