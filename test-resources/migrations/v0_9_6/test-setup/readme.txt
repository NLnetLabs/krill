Perconfigure CLI:

  export KRILL_CLI_MY_CA="krill-upgrade-test"
  export KRILL_CLI_TOKEN=03e3ce77ebc2bf14753ee4783d1ceffb

and make sure that (random, not used) token is in /etc/krill.conf


Add CA
  krillc add --ca krill-upgrade-test

Show CA
  krillc show

Get child request for parent
  krillc parents request

Upload XML to testbed, get response, and add it:

  vi parent-res.xml
  krillc parents add --parent testbed --response ./parent-res.xml 

Get publisher request:
  krillc repo request

Upload XML to testbed, get response and add it:
  
  vi repo-response.xml
  krillc repo configure --response ./repo-response.xml 

Show CA:
  krillc show

Some ROA changes:
  krillc roas update --add 192.168.0.0/16 => 64496
  krillc roas update --add "192.168.0.0/16 => 64496"
  krillc roas update --add "2001:db8::/64 => 64496"
  krillc roas update --remove "192.168.0.0/16 => 64496"
  krillc roas update --add "192.168.0.0/24 => 64496"
  krillc roas update --add "192.168.0.0/22 => 0"
  krillc roas list

Some ASPA changes:

  We need to use the API directly in older Krill versions:

  Add an ASPA:
    curl --insecure -H "Authorization: Bearer 03e3ce77ebc2bf14753ee4783d1ceffb" -X POST -d @./add-aspa-65000.json https://localhost:3000/api/v1/cas/krill-upgrade-test/aspas

  Update it:
    curl --insecure -H "Authorization: Bearer 03e3ce77ebc2bf14753ee4783d1ceffb" -X POST -d @./update.json  https://localhost:3000/api/v1/cas/krill-upgrade-test/aspas/as/as65000

  Remove it:
    curl --insecure -H "Authorization: Bearer 03e3ce77ebc2bf14753ee4783d1ceffb" -X POST -d @./remove-aspa-65000.json https://localhost:3000/api/v1/cas/krill-upgrade-test/aspas

  Add it back:
    curl --insecure -H "Authorization: Bearer 03e3ce77ebc2bf14753ee4783d1ceffb" -X POST -d @./add-aspa-65000.json https://localhost:3000/api/v1/cas/krill-upgrade-test/aspas


Key Roll over:
  krillc keyroll init
  krillc keyroll activate

Show history:
  krillc history commands
