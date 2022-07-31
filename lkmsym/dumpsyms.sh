#!/usr/bin/env bash

set -x
insmod lkmsym.ko
cat /dev/lkmsym > symbols
wc -l symbols
rmmod lkmsym
