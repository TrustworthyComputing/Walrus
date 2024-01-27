<h1 align="center">Walrus <a href="https://github.com/TrustworthyComputing/Walrus/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a> </h1>


Walrus is a library that constitutes a high-level wrapper around Microsoft SEAL
that handles parameterization for BFV/BGV and CKKS. Programs are executed in two
passes; the first pass analyzes the application and gathers statistics to
determine suitable parameters and the second pass constitutes the actual HE
computation with SEAL over secure data. 

## Walrus API

Ciphertexts are represented by the WalrusCtxt class, which encapsulates a
Microsoft SEAL ciphertext as well as additional metadata to aid in
parameterization. Encryption and decryption procedures are also provided through
the class. 
The core supported arithmetic operations with WalrusCtxt include encrypted
addition, multiplication, and subtraction as well as variants of each with mixed
operands (i.e. a ciphertext and plaintext). 
For the first pass, SEAL engines and keys should not be supplied to the
arithmetic functions. 

![API
Graph](https://github.com/TrustworthyComputing/Walrus/blob/main/images/api.png)

## Examples
Two example applications are included in the form of a [simple neural network
inference](https://github.com/TrustworthyComputing/Walrus/blob/main/examples/neural_network.cpp) as well as a [Chi-squared test](https://github.com/TrustworthyComputing/Walrus/blob/main/examples/chi_squared.cpp). 
Both examples include the aforementioned first and second passes, where the
first pass is solely for parameterization while the latter is the actual
encrypted evaluation.
These examples are automatically compiled when the library is built.

## Prerequisites
* [Microsoft SEAL](https://github.com/microsoft/SEAL) (v4.1)
* cmake (v3.10 or higher)

## Building Walrus
The provided examples can be built in Linux with the following commands:
```
mkdir build
cd build
cmake ..
make
```
Custom executables can be readily added to the provided [CMakeLists.txt](https://github.com/TrustworthyComputing/Walrus/blob/main/CMakeLists.txt) in the same
way both examples have been added (for instance, lines 31-34).

<p align="center">
    <img src="https://github.com/TrustworthyComputing/Walrus/blob/main/images/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>