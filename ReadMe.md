signatureCandidatesAutoDiscover.py [![Unlicensed work](https://raw.githubusercontent.com/unlicense/unlicense.org/master/static/favicon.png)](https://unlicense.org/)
==================================
~~[wheel (GitLab)](https://gitlab.com/KOLANICH-tools/signatureCandidatesAutoDiscover.py/-/jobs/artifacts/master/raw/dist/signatureCandidatesAutoDiscover-0.CI-py3-none-any.whl?job=build)~~
[wheel (GHA via `nightly.link`)](https://nightly.link/KOLANICH-tools/signatureCandidatesAutoDiscover.py/workflows/CI/master/signatureCandidatesAutoDiscover-0.CI-py3-none-any.whl)
~~![GitLab Build Status](https://gitlab.com/KOLANICH-tools/signatureCandidatesAutoDiscover.py/badges/master/pipeline.svg)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH-tools/signatureCandidatesAutoDiscover.py/badges/master/coverage.svg)~~
~~![GitHub Actions](https://github.com/KOLANICH-tools/signatureCandidatesAutoDiscover.py/workflows/CI/badge.svg)](https://github.com/KOLANICH-tools/signatureCandidatesAutoDiscover.py/actions/)~~
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH-tools/signatureCandidatesAutoDiscover.py.svg)](https://libraries.io/github/KOLANICH-tools/signatureCandidatesAutoDiscover.py)
[![Code style: antiflash](https://img.shields.io/badge/code%20style-antiflash-FFF.svg)](https://codeberg.org/KOLANICH-tools/antiflash.py)

This is a tool that helps you to automatically discover signatures used in file formats and/or protocols using disassembly listings of the software and the dataset of the files used by it.

It relies on the following assumptions, causing the limitations of the tool:
1. in order to create a valid file in a certain format using signatures software has to write the signature somewhere.
2. the software is not obfuscated or packed and the decompiler/disassembler has done its work correctly
3. the signature is usually `4` bytes, so `uint32_t`. 4 bytes give enough low probability of false identification of file format.
4. when using in-memory structures, including memory-mapped files the signature is usually aligned **within ith own struct** (it may be not aligned relative to root struct base). It makes appending it easier.
5. when reading signature from files using stream API (`fread` and so on) it is usually convenient for a programmer to read the block as whole rather than read it byte-by-byte in a random order.
6. when comparing/writing signatures read this way the compiler will optimize compares and writes by using the corresponding integer types.
7. the compiler will put the signatures into immediate values into the instructions
8. signatures should have low probability to occur by chance.


So the principle of the tool is simple:
1. Read the disassembly/decompilation of the software and identify the instructions doing 4-byte integer assignments and comparisons. Collect their operands.
2. Because certain low-entropy integers like `0x000000FF` will likely occur by chance, filter them out heuristically.
3. Check the presence of the remaining candidates within files, count occurences, print the listing.
4. Remove the integers seen only once within the dataset.
5. Print the rest as a nice table.


## How to use

0. Get prior knowledge that the format in question uses signatures.
1. Create a dataset of files containing the signatures.
2. Collect enough different implemetations of the software dealing with the format. Disassemble and/or decompile it with `retdec` or other decompiler.
3. Execute the tool within the directory with decompilation results, providing it with the glob expression to the files containing the data.
4. The tool will give you the list of signature candidates with their counts of occurences within the dataset and different representations convenient for grepping within disassembly listings and decompilation results.


