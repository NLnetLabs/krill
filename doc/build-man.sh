cd manual
make man
gzip -cvf ./build/man/krill.1 > ../krill.1.gz
gzip -cvf ./build/man/krillc.1 > ../krillc.1.gz
gzip -cvf ./build/man/krillta.1 > ../krillta.1.gz
gzip -cvf ./build/man/krillup.1 > ../krillup.1.gz
gzip -cvf ./build/man/krill.conf.5 > ../krill.conf.5.gz