#!/bin/bash
set -x
cp /boot/vmlinuz-$(uname -r) .
cp /boot/System.map-$(uname -r) .
wc -l System.map-$(uname -r)
./extract-vmlinux.sh vmlinuz-$(uname -r) > vmlinux
file vmlinux