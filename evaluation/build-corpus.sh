#!/bin/sh
set -eu

mkdir -p /out
x86_64-w64-mingw32-gcc -O0 -Wall -Wextra -o /out/hello_pe_x64.exe /src/hello_pe_x64.c
x86_64-w64-mingw32-gcc -O0 -Wall -Wextra -o /out/persist_reg.exe /src/persist_reg.c -ladvapi32
x86_64-w64-mingw32-gcc -O0 -Wall -Wextra -o /out/inject_pattern.exe /src/inject_pattern.c
echo "Built three synthetic PE x64 samples in /out. They were compiled, never executed."
