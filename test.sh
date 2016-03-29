#!/bin/bash

scons > /dev/null

tryby="ECB CBC PCBC CFB OFB";

for tryb in $tryby; do
        echo "## Szyfrowanie i deszyfracja trybem szyfrowania ${tryb}. Wynik operacji:"
        set -x
	./twofish -e -k ./klucz.txt -i ./tekst.txt            -t ${tryb} -o /tmp/tekst_${tryb}_ct.txt
	./twofish -d -k ./klucz.txt -i /tmp/tekst_${tryb}_ct.txt -t ${tryb} -o /tmp/tekst_${tryb}.txt
        set +x

	#head -n 10 /tmp/tekst_${tryb}.txt | cut -c 1-50
	cat /tmp/tekst_${tryb}.txt
done

