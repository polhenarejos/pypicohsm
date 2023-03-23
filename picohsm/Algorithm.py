"""
/*
 * This file is part of the pypicohsm distribution (https://github.com/polhenarejos/pypicohsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
"""

class Algorithm:
    ALGO_AES_CBC_ENCRYPT    = 0x10
    ALGO_AES_CBC_DECRYPT    = 0x11
    ALGO_AES_CMAC           = 0x18
    ALGO_EXT_CIPHER_ENCRYPT = 0x51
    ALGO_EXT_CIPHER_DECRYPT = 0x52
    ALGO_AES_DERIVE         = 0x99

    ALGO_EC_RAW             = 0x70
    ALGO_EC_SHA1            = 0x71
    ALGO_EC_SHA224          = 0x72
    ALGO_EC_SHA256          = 0x73
    ALGO_EC_SHA384          = 0x74
    ALGO_EC_SHA512          = 0x75
    ALGO_EC_ECDH            = 0x80
    ALGO_EC_ECDH_XKEK       = 0x84
    ALGO_EC_DERIVE          = 0x98

    ALGO_RSA_RAW            = 0x20
    ALGO_RSA_DECRYPT        = 0x21
    ALGO_RSA_DECRYPT_PKCS1  = 0x22
    ALGO_RSA_DECRYPT_OEP    = 0x23
    ALGO_RSA_PKCS1          = 0x30
    ALGO_RSA_PKCS1_SHA1     = 0x31
    ALGO_RSA_PKCS1_SHA224   = 0x32
    ALGO_RSA_PKCS1_SHA256   = 0x33
    ALGO_RSA_PKCS1_SHA384   = 0x34
    ALGO_RSA_PKCS1_SHA512   = 0x35
    ALGO_RSA_PSS            = 0x40
    ALGO_RSA_PSS_SHA1       = 0x41
    ALGO_RSA_PSS_SHA224     = 0x42
    ALGO_RSA_PSS_SHA256     = 0x43
    ALGO_RSA_PSS_SHA384     = 0x44
    ALGO_RSA_PSS_SHA512     = 0x45

class Padding:
    RAW         = 0x21
    PKCS        = 0x22
    OAEP        = 0x23

class AES:
    ECB         = 1
    CBC         = 2
    OFB         = 3
    CFB         = 4
    GCM         = 5
    XTS         = 6
    CTR         = 7
    CCM         = 8
