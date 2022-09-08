#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nKRILLC VERSION:"
    krillc --version
    echo -e "\nKRILL VERSION:"
    krill --version
    echo -e "\nKRILL CONF:"
    cat /etc/krill.conf
    echo -e "\nKRILL DATA DIR:"
    ls -la /var/lib/krill
    echo -e "\nKRILL SERVICE STATUS BEFORE ENABLE:"
    systemctl status krill || true
    echo -e "\nENABLE KRILL SERVICE:"
    systemctl enable krill
    echo -e "\nKRILL SERVICE STATUS AFTER ENABLE:"
    systemctl status krill || true
    echo -e "\nSTART KRILL SERVICE:"
    systemctl start krill
    
    echo -e "\nKRILL SERVICE STATUS AFTER START:"
    sleep 1s
    systemctl status krill
    echo -e "\nKRILL MAN PAGE:"
    man -P cat krill
    ;;

  post-upgrade)
    echo -e "\nKRILLC VERSION:"
    krillc --version

    echo -e "\nKRILL VERSION:"
    krill --version

    echo -e "\nKRILL CONF:"
    cat /etc/krill.conf

    echo -e "\nKRILL DATA DIR:"
    ls -la /var/lib/krill

    echo -e "\nKRILL SERVICE STATUS:"
    systemctl status krill || true

    echo -e "\nKRILL MAN PAGE:"
    man -P cat krill
    ;;
esac
