#include "twofishtest.hpp"
#include "szyfrowanie.hpp"
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>

std::ofstream outputFile;
std::ifstream inputFile;
std::ifstream keyFile;
bool szyfruj = true;
Szyfrowanie szyfrowanie;

static void parse_cmd(int argc, char *argv[])
{
	int tmp = 0;
	int c = 0;
	extern char *optarg;
	while (c != -1) {
        c = getopt(argc, argv, "hk:i:o:t:ed");
		switch (c) {
		case 'h':
            std::cout << "[USAGE] twofish [OPTION]...\n"
			       "Program wykonuje szyfrowanie algorytmem twofish \n"
			       " z zadanym trybem szyfrowania \n"
			       "\t-k <file>\tplik zawierający klucz\n"
			       "\t-i <file>\tplik z wejściowym tekstem\n"
			       "\t-o <file>\tplik z wyjściowym tekstem\n"
			       "\t-t  <ECB|CBC|CFB|OCB>\ttryb szyfrowania blokowego\n"
			       "\t-e\tszyfruj tekst (default)\n"
                   "\t-d\tdeszyfruj tekst\n";
			exit(0);
		case 'k':
            keyFile = std::ifstream(optarg);
			break;
		case 'i':
            inputFile = std::ifstream(optarg);
			break;
		case 'o':
            outputFile = std::ofstream(optarg, std::ios_base::trunc);
			break;
		case 't':
			tmp = szyfrowanie.setTryb(std::string(optarg));
			if (tmp < 0) {
				std::cout << "zly tryb szyfrowania" << std::
				    endl;
				exit(-1);
			}
			break;
		case 'e':
			szyfruj = true;
			break;
        case 'd':
            szyfruj = false;
			break;
		}
	}
    if ( !inputFile.is_open() ) {
        std::cout << "Nie podałeś lub źle podany plik wejściowy.\n";
        exit(-1);
    }
    if ( !outputFile.is_open() ) {
        std::cout << "Nie podałeś lub źle podany plik wyjściowy.\n";
        exit(-1);
    }
    if ( !keyFile.is_open() ) {
        std::cout << "Nie podałeś lub źle podany plik z kluczem.\n";
        exit(-1);
    }
}

int main(int argc, char *argv[])
{
	parse_cmd(argc, argv);

	TwofishTest t;
    t.runTests();

    if ( szyfruj ) {
        szyfrowanie.encrypt(inputFile, outputFile);
    } else {
        szyfrowanie.decrypt(inputFile, outputFile);
    }

	return 0;
}
