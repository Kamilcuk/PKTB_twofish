# PTKB_twofish
Project for university about twofish implementation for PTKB class.
# Usage
[USAGE] twofish [OPTION]...
Program wykonuje szyfrowanie algorytmem twofish 
 z zadanym trybem szyfrowania 
	-k <file>	plik zawierający klucz
	-i <file>	plik z wejściowym tekstem
	-o <file>	plik z wyjściowym tekstem
	-t  <ECB|CBC|CFB|OCB>	tryb szyfrowania blokowego
	-e	szyfruj tekst (default)
	-d	deszyfruj tekst

# Compile
scons

