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

class OID:
    SHA1    = b'\x2A\x86\x48\x86\xF7\x0D\x02\x07'
    SHA224  = b'\x2A\x86\x48\x86\xF7\x0D\x02\x08'
    SHA256  = b'\x2A\x86\x48\x86\xF7\x0D\x02\x09'
    SHA384  = b'\x2A\x86\x48\x86\xF7\x0D\x02\x0A'
    SHA512  = b'\x2A\x86\x48\x86\xF7\x0D\x02\x0B'

    HKDF_SHA256 = b'\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x1D'
    HKDF_SHA384 = b'\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x1E'
    HKDF_SHA512 = b'\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x1F'

    PBKDF2      = b'\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C'

    KDF_X963    = b'\x2B\x81\x05\x10\x86\x48\x3F'

    RSA     = b'\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02'
    EC      = b'\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03'
    AES     = b'\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01'
