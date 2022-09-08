#!/usr/bin/env -S bash -eo pipefail -x
case $1 in
  post-install)
    echo -e "\nKRILLUP VERSION:"
    krillup --version

    echo -e "\nKRILLUP MAN PAGE:"
    man -P cat krillup
    ;;

  post-upgrade)
    ;;
esac
