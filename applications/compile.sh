#!/bin/bash

tput reset 2>/dev/null || true

if [ -z "${1}" ]; then
  export TARGET=z1
else
  export TARGET=${1}
fi

rm -f *.$TARGET

set -e

make clean -f Makefile_enabled_node
# CFLAGS=-DDEMO
make -f Makefile_enabled_node sink-node management-sink attack-fdff enabled-node
rm -rf obj_$TARGET contiki-$TARGET.a contiki-$TARGET.map symbols.c symbols.h

# make clean -f Makefile_enabled_node
# make -f Makefile_enabled_node attack-two

# make clean -f Makefile_intrusion_node
# make -f Makefile_intrusion_node attack-three

make -f Makefile_controller_node
rm -rf obj_$TARGET contiki-$TARGET.a contiki-$TARGET.map symbols.c symbols.h

size *.$TARGET
