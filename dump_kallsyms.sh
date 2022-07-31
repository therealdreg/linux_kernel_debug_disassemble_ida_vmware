#!/usr/bin/env bash

set -x 
cat /proc/kallsyms > dump_kallsyms
head dump_kallsyms
tail dump_kallsyms