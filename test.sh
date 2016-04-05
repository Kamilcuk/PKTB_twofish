#!/bin/bash

scons > /dev/null

tryby="ECB CBC PCBC CFB OFB";

set -x
for tryb in $tryby; do
        echo "## Szyfrowanie i deszyfracja trybem szyfrowania ${tryb}. Wynik operacji:"
	./twofish -e -k ./klucz.txt -i ./tekst.txt            -t ${tryb} -o /tmp/tekst_${tryb}_ct.txt
	./twofish -d -k ./klucz.txt -i /tmp/tekst_${tryb}_ct.txt -t ${tryb} -o /tmp/tekst_${tryb}.txt

	#head -n 10 /tmp/tekst_${tryb}.txt | cut -c 1-50
	cat /tmp/tekst_${tryb}.txt
done
set +x

