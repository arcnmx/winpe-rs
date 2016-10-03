#!/bin/bash

cargo rustc --lib --profile test --target i686-pc-windows-gnu -- -C linker=i686-w64-mingw32-gcc -C link-args="/usr/i686-w64-mingw32/lib/libpthread.a -pie -Wl,-e_mainCRTStartup,--nxcompat,--dynamicbase" && RUST_TEST_THREADS=1 wine ./target/i686-pc-windows-gnu/debug/winpe_loader-dfd19710084ec13a.exe --nocapture
