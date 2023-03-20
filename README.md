# pypicohsm
Pico HSM tools for Python

## Introduction

Pico HSM firmware allows to convert a Raspberry Pico into a Hardware Security Module (HSM), to store private and secret keys, perform signing and ciphering operations, without exposing the key.

Pico HSM is compatible with PKCS-11 interface and it can be used with multiple tools, such as OpenSC or SmartCardShell 3. Nevertheless, pypicohsm is an extended interface to perform advanced operations, such as ChaChaPoly encryption, HMAC, PBHKDF2 or AES CBC, ECB, CFG, OFB and XTS, amongst others.

## Install

```
pip install pypicohsm
```

## Usage

pypicohsm can be used as a Python module (PicoHSM.py) or through command line.
