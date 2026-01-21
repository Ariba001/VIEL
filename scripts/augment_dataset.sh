#!/bin/bash

SRC_DIR="binaries"
OUT_DIR="binaries_augmented"

mkdir -p $OUT_DIR

for file in $(find $SRC_DIR -name "*.c.src"); do
    base=$(basename $file .c.src)

    gcc -x c $file -o $OUT_DIR/${base}_O0 -O0 -fno-stack-protector -no-pie
    gcc -x c $file -o $OUT_DIR/${base}_O1 -O1 -fno-stack-protector -no-pie
    gcc -x c $file -o $OUT_DIR/${base}_O2 -O2 -fno-stack-protector -no-pie
done
