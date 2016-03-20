#!/bin/python3
# Sconstruct file, Kamil Cukrowski
env = Environment();
env.Append(CCFLAGS = ' -Wall -std=c++11 -O2 -g ');
SetOption('num_jobs', 3)
sources = [ Glob('src/*') ];
twofish = env.Program(target = 'twofish', source = sources);
Default(twofish);
