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

import sys
import os
from .APDU import APDUResponse
from .DO import DOPrefixes
from .Algorithm import Algorithm, Padding, AES
from .utils import int_to_bytes
from .const import DEFAULT_PIN, DEFAULT_SOPIN, DEFAULT_RETRIES, EF_TERMCA, DEFAULT_DKEK_SHARES
from .oid import OID
import hashlib
import base58
from .RescuePicoKey import RescuePicoKey

try:
    from cvc.asn1 import ASN1
    from cvc import oid
    from cvc.certificates import CVC
    from cvc.ec_curves import EcCurve, Curve25519, Curve448
except ModuleNotFoundError:
    print('ERROR: cvc module not found! Install pycvc package.\nTry with `pip install pycvc`')
    sys.exit(-1)

try:
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils, padding, x25519, x448, ed25519, ed448
    from cryptography.hazmat.primitives import hashes, cmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
except ModuleNotFoundError:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)

class Platform:
    RP2040 = 0
    RP2350 = 1
    ESP32  = 2

class Product:
    HSM     = 1
    FIDO    = 2
    OPENPGP = 3

class KeyType:
    RSA                     = 1
    ECC                     = 2
    AES                     = 3

class EncryptionMode:
    ENCRYPT     = 1
    DECRYPT     = 2

class PinType:
    USER_PIN    = 0x81
    SO_PIN      = 0x88

class Options:
    RESET_RETRY_COUNTER = 0x0001    # Enable or disable RESET RETRY COUNTER command
    TRANSPORT_PIN       = 0x0002    # Enable or disable transport PIN mode
    SESSION_PIN         = 0x0004    # Enable session PIN (clear on reset)
    SESSION_PIN_EXPL    = 0x000C    # Enable session PIN (explicit clear)
    PKA_REPLACEABLE     = 0x0008    # Enable or disable replacing of a PKA key
    AUTH_PIN_PKA        = 0x0010    # Enable the combined authentication mode of user pin and public key authentication
    RRC_ONLY_RESET      = 0x0020    # If enabled RESET RETRY COUNTER only resets the error counter

class PHYOpts:
    PHY_OPT_WCID    = 0x01      # Enable or disable the use of the WCID
    PHY_OPT_LED_DIM = 0x10      # Enable or disable the LED dimming

class SecureChannel:
    OID_ID_CA_ECDH_AES_CBC_CMAC_128 = b'\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x02'
    BLOCK_SIZE = 16

    PROTO_OID = OID_ID_CA_ECDH_AES_CBC_CMAC_128

    def __init__(self, shared=None, nonce=None):
        self.__derive_sm_keys(shared=shared, nonce=nonce)

    def __derive_sm_key(input=None, counter=0, nonce=None):
        b = b''
        if (input):
            b += input
        if (nonce):
            b += nonce
        b += counter.to_bytes(4, 'big')
        digest = hashlib.sha1(b).digest()
        return digest[:16]

    def __derive_sm_keys(self, shared, nonce):
        self.__sm_kenc = SecureChannel.__derive_sm_key(shared, 1, nonce)
        self.__sm_kmac = SecureChannel.__derive_sm_key(shared, 2, nonce)
        self.__sm_counter = 0

    def __sm_sign(self, data):
        c = cmac.CMAC(algorithms.AES(self.__sm_kmac))
        c.update(data)
        return c.finalize()

    def __sm_inc_counter(self):
        self.__sm_counter += 1

    def __sm_iv(self):
        iv = b'\x00'*16
        cipher = Cipher(algorithms.AES(self.__sm_kenc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        message = self.__sm_counter.to_bytes(self.BLOCK_SIZE, 'big')
        ct = encryptor.update(message) + encryptor.finalize()
        return ct

    def verify_token(self, token, pbkey):
        a = ASN1().add_tag(0x7F49, ASN1().add_oid(self.PROTO_OID).add_tag(0x86, pbkey).encode())
        signature = self.__sm_sign(a.encode())
        return signature[:len(token)] == token

    def wrap_apdu(self, apdu):
        cla, ins, p1, p2, lc, data, le = apdu[0], apdu[1], apdu[2], apdu[3], apdu[4:7], apdu[7:-2], apdu[-2:]
        cla |= 0x0C

        data += [0x80]
        data += [0x00] * (self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE))

        self.__sm_inc_counter()
        iv = self.__sm_iv()
        cipher = Cipher(algorithms.AES(self.__sm_kenc), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(bytes(data)) + encryptor.finalize()
        if (ins & 0x1 == 0):
            tlv_body = [0x01] + list(ct)
            body = ASN1().add_tag(0x87, tlv_body).encode()
        else:
            body = ASN1().add_tag(0x85, list(ct)).encode()
        do_le = [0x97, 0x02] + le

        macb = list(self.__sm_counter.to_bytes(self.BLOCK_SIZE, 'big')) + [cla, ins, p1, p2, 0x80] + [0x00] * (self.BLOCK_SIZE - 5) + list(body) + do_le + [0x80]
        macb += [0x00] * (self.BLOCK_SIZE - (len(macb) % self.BLOCK_SIZE))
        macc = self.__sm_sign(bytes(macb))
        do_mac = ASN1().add_tag(0x8E, list(macc)).encode()

        new_lc = list((len(body) + len(do_le) + len(do_mac)).to_bytes(3, 'big'))

        apdu = [cla, ins, p1, p2] + new_lc + list(body) + do_le + list(do_mac) + [0x00, 0x00]
        return apdu

    def unwrap_rapdu(self, apdu):
        self.__sm_inc_counter()
        signature = ASN1().decode(apdu).find(0x8E).data()
        body = ASN1().decode(apdu).find(0x87)
        sw = ASN1().decode(apdu).find(0x99)
        if (not sw):
            raise ValueError("SM: no sw found")
        sw = sw.data()
        do_sw = ASN1.make_tag(0x99, sw)
        macb = bytearray(self.__sm_counter.to_bytes(self.BLOCK_SIZE, 'big'))
        if (body):
            body = body.data()
            if (body and body[0] != 0x1):
                raise ValueError("SM: data not consistent")
            do_body = ASN1.make_tag(0x87, body)
            macb += do_body
        macb += do_sw
        macb += bytearray([0x80])
        macb += bytearray([0x00] * (self.BLOCK_SIZE - (len(macb) % self.BLOCK_SIZE)))
        sign = self.__sm_sign(bytes(macb))[:len(signature)]
        if (signature != sign):
            raise ValueError("SM: signature mismatch")
        rapdu = []
        if (body):
            body = body[1:]
            iv = self.__sm_iv()
            cipher = Cipher(algorithms.AES(self.__sm_kenc), modes.CBC(iv))
            decryptor = cipher.decryptor()
            ct = decryptor.update(bytes(body)) + decryptor.finalize()
            l = len(ct) - 1
            while (l >= 0 and ct[l] == 0x00):
                l -= 1
            if (l < 0 or ct[l] != 0x80):
                raise ValueError("SM: body malformed")
            rapdu = list(ct[:l])
        return rapdu, sw[0] << 8 | sw[1]


class PicoHSM:
    __sc = None

    def __init__(self, pin=None):
        self.__pin = pin or '648219'
        cardtype = AnyCardType()
        try:
            # request card insertion
            cardrequest = CardRequest(timeout=1, cardType=cardtype)
            self.__card = cardrequest.waitforcard().connection

            # connect to the card and perform a few transmits
            self.__card.connect()

        except CardRequestTimeoutException:
            try:
                self.__card = RescuePicoKey()
            except Exception:
                raise Exception('time-out: no card inserted')
        try:
            resp, sw1, sw2 = self.select_applet(rescue=True)
            if (sw1 == 0x90 and sw2 == 0x00):
                if (resp[1] != Product.HSM):
                    raise Exception('Not a PicoHSM')
                self.platform = resp[0]
        except APDUResponse:
            self.platform = Platform.RP2040
        self.select_applet()
        data = self.get_contents(p1=0x2f02)
        self.device_id = CVC().decode(data).chr() if data else None
        try:
            self.login()
        except APDUResponse:
            pass

    def select_applet(self, rescue=False):
        if (rescue):
            return self.__card.transmit([0x00, 0xA4, 0x04, 0x04, 0x08, 0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21, 0x00])
        return self.__card.transmit([0x00, 0xA4, 0x04, 0x00, 0xB, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01, 0x0])

    def send(self, command, cla=0x00, p1=0x00, p2=0x00, ne=None, data=None, codes=[]):
        lc = []
        dataf = []
        if (data):
            lc = [0x00] + list(len(data).to_bytes(2, 'big'))
            dataf = list(data)
        else:
            lc = [0x00*3]
        if (ne is None):
            le = [0x00, 0x00]
        else:
            le = list(ne.to_bytes(2, 'big'))
        if (isinstance(command, list) and len(command) > 1):
            apdu = command
        else:
            apdu = [cla, command]

        apdu = apdu + [p1, p2] + lc + dataf + le
        if (self.__sc):
            apdu = self.__sc.wrap_apdu(apdu)

        try:
            response, sw1, sw2 = self.__card.transmit(apdu)
        except CardConnectionException:
            self.__card.reconnect()
            response, sw1, sw2 = self.__card.transmit(apdu)

        code = (sw1<<8|sw2)
        if (sw1 != 0x90):
            if (sw1 == 0x63 and sw2 & 0xF0 == 0xC0):
                pass
            # elif (code == 0x6A82):
            #     self.select_applet()
            #     if (sw1 == 0x90):
            #         response, sw1, sw2 = self.__card.transmit(apdu)
            #         if (sw1 == 0x90):
            #             return response
            elif (code == 0x6982):
                response, sw1, sw2 = self.__card.transmit([0x00, 0x20, 0x00, 0x81, len(self.__pin)] + list(self.__pin.encode()) + [0x0])
                if (sw1 == 0x90):
                    response, sw1, sw2 = self.__card.transmit(apdu)
                    if (sw1 == 0x90):
                        return response
            elif (sw1 == 0x61):
                response = []
                while (sw1 == 0x61):
                    apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
                    resp, sw1, sw2 = self.__card.transmit(apdu)
                    response += resp
                code = (sw1<<8|sw2)
            if (code not in codes and code != 0x9000):
                raise APDUResponse(sw1, sw2)
        if (self.__sc):
            response, code = self.__sc.unwrap_rapdu(response)
            if (code not in codes and code != 0x9000):
                raise APDUResponse(code >> 8, code & 0xff)
        if (len(codes) > 1):
            return bytes(response), code
        return bytes(response)

    def get_login_retries(self):
        self.select_applet()
        try:
            self.send(command=0x20, p2=0x81)
        except APDUResponse as e:
            if (e.sw1 == 0x63 and e.sw2 & 0xF0 == 0xC0):
                return e.sw2 & 0x0F
            raise e

    def is_logged(self):
        try:
            self.send(command=0x20, p2=0x81)
            return True
        except APDUResponse:
            pass
        return False

    def logout(self):
        self.select_applet()

    def initialize(self, pin=DEFAULT_PIN, sopin=DEFAULT_SOPIN, options=Options.RESET_RETRY_COUNTER, retries=DEFAULT_RETRIES, dkek_shares=None, puk_auts=None, puk_min_auts=None, key_domains=None):
        if (retries is not None and not 0 < retries <= 10):
            raise ValueError('Retries must be in the range (0,10]')
        if (dkek_shares is not None and not 0 <= dkek_shares <= 10):
            raise ValueError('DKEK shares must be in the range [0,10]')
        if ((puk_auts is not None and puk_min_auts is None) or (puk_auts is None and puk_min_auts is not None)):
            raise ValueError('PUK Auts and PUK Min Auts must be specified both')
        if (puk_auts is not None and not 0 < puk_auts <= 8):
            raise ValueError('PUK Auts must be in the range (0,8]')
        if (puk_min_auts is not None and not 0 < puk_min_auts <= 8):
            raise ValueError('PUK Min Auts must be in the range (0,8]')
        if (puk_auts is not None and puk_min_auts is not None and puk_min_auts > puk_auts):
            raise ValueError('PUK Min Auts must be less or equal to PUK Auts')
        if (key_domains is not None and not 0 < key_domains <= 8):
            raise ValueError('Key Domains must be in the range (0,8]')

        a = ASN1()
        if (options is not None):
            a = a.add_tag(0x80, options.to_bytes(2, 'big'))
        if (pin is not None):
            a = a.add_tag(0x81, pin.encode())
        if (sopin is not None):
            a = a.add_tag(0x82, sopin.encode())
        if (retries is not None):
            a = a.add_tag(0x91, bytes([retries]))
        if (dkek_shares is not None):
            a = a.add_tag(0x92, bytes([dkek_shares]))
        if (puk_auts is not None and puk_min_auts is not None):
            a = a.add_tag(0x93, bytes([puk_auts, puk_min_auts]))
        if (key_domains is not None):
            a = a.add_tag(0x97, bytes([key_domains]))

        data = a.encode()

        self.send(cla=0x80, command=0x50, data=data)

    def login(self, pin=None, who=PinType.USER_PIN):
        if (pin is None):
            pin = self.__pin
        self.send(command=0x20, p2=who, data=pin.encode())

    def get_first_free_id(self):
        kids = self.list_keys(prefix=DOPrefixes.KEY_PREFIX)
        mset = set(range(max(kids)))-set(kids)
        if (len(mset) > 0):
            return min(mset)
        if (max(kids) == 255):
            raise ValueError('Max number of key id reached')
        return max(kids)+1

    def list_keys(self, prefix=None):
        resp = self.send(command=0x58)
        if (prefix is not None):
            grouped = [(resp[i],resp[i+1]) for i in range(0, len(resp), 2) if resp[i] == prefix]
            _, kids = zip(*grouped)
            return kids
        return [(resp[i],resp[i+1]) for i in range(0, len(resp), 2)]

    def key_generation(self, type, param, use_counter=None, algorithms=None, key_domain=None):
        meta_data = b''
        if (use_counter is not None):
            meta_data += b'\x90\x04' + use_counter.to_bytes(4, 'big')
        if (algorithms is not None):
            meta_data += b'\x91' + bytes([len(algorithms)] + algorithms)
        if (key_domain is not None):
            meta_data += b'\x92\x01' + bytes([key_domain])
        if (type in [KeyType.RSA, KeyType.ECC]):
            a = ASN1().add_tag(0x5f29, bytes([0])).add_tag(0x42, 'UTCA00001'.encode())
            if (type == KeyType.RSA):
                if (not 1024 <= param <= 4096):
                    raise ValueError('RSA bits must be in the range [1024,4096]')
                a.add_tag(0x7f49, ASN1().add_oid(oid.ID_TA_RSA_V1_5_SHA_256).add_tag(0x2, param.to_bytes(2, 'big')).encode())
            elif (type == KeyType.ECC):
                if (param not in ('secp192r1', 'secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp192k1', 'secp256k1', 'curve25519', 'curve448', 'ed25519', 'ed448')):
                    raise ValueError('Bad elliptic curve name')

                dom = EcCurve.from_name(param)
                if (param in ('curve25519', 'curve448', 'ed25519', 'ed448')):
                    pubctx = {1: dom.P, 2: dom.O, 3: dom.G}
                else:
                    pubctx = {1: dom.P, 2: dom.A, 3: dom.B, 4: dom.G, 5: dom.O, 7: dom.F}
                a.add_object(0x7f49, oid.ID_TA_ECDSA_SHA_256, pubctx)
            a.add_tag(0x5f20, 'UTCDUMMY00001'.encode())
            data = a.encode()

            keyid = self.get_first_free_id()
            self.send(command=0x46, p1=keyid, data=list(data + meta_data))
        elif (type == KeyType.AES):
            if (param == 128):
                p2 = 0xB0
            elif (param == 192):
                p2 = 0xB1
            elif (param == 256):
                p2 = 0xB2
            elif (param == 512):
                p2 = 0xB3
            else:
                raise ValueError('Bad AES key size')
            keyid = self.get_first_free_id()
            self.send(command=0x48, p1=keyid, p2=p2)
        else:
            raise ValueError('Bad KeyType')
        return keyid

    def delete_file(self, p1, p2=None):
        if (p2 is not None):
            self.send(command=0xE4, data=[p1, p2])
        else:
            resp = self.delete_file(p1=p1 >> 8, p2=p1 & 0xff)

    def get_contents(self, p1, p2=None):
        if (p2 is not None):
            resp = self.send(command=0xB1, p1=p1, p2=p2, data=[0x54, 0x02, 0x00, 0x00])
        else:
            resp = self.get_contents(p1=p1 >> 8, p2=p1 & 0xff)
        return resp

    def select_file(self, p1, p2=None):
        if (p2 is not None):
            resp = self.send(command=0xA4, data=[p1, p2])
        else:
            resp = self.select_file(p1=p1 >> 8, p2=p1 & 0xff)
        return resp

    def put_contents(self, p1, p2=None, data=None):
        if (p2 is not None):
            self.send(command=0xD7, p1=p1, p2=p2, data=[0x54, 0x02, 0x00, 0x00, 0x53, 0x82] + list(len(data).to_bytes(2, 'big') if data else [0,0]) + list(data) if data else [])
        else:
            self.put_contents(p1=p1 >> 8, p2=p1 & 0xff, data=data)

    def public_key(self, keyid, param=None):
        response = self.get_contents(p1=DOPrefixes.EE_CERTIFICATE_PREFIX, p2=keyid)

        cert = bytearray(response)
        roid = CVC().decode(cert).pubkey().oid()
        if (roid == oid.ID_TA_ECDSA_SHA_256):
            curve = EcCurve.from_name(param).to_crypto()
            Y = bytes(CVC().decode(cert).pubkey().find(0x86).data())
            return ec.EllipticCurvePublicKey.from_encoded_point(
                        curve,
                        Y,
                    )
        elif (roid == oid.ID_RI_ECDH_SHA_256):
            Y = bytes(CVC().decode(cert).pubkey().find(0x84).data())
            G = bytes(CVC().decode(cert).pubkey().find(0x83).data())
            P = bytes(CVC().decode(cert).pubkey().find(0x81).data())
            curve = EcCurve.from_P(P)
            if (isinstance(curve, Curve25519)):
                if (G[0] != 9):
                    from binascii import hexlify
                    print(hexlify(G))
                    return ed25519.Ed25519PublicKey.from_public_bytes(Y)
                return x25519.X25519PublicKey.from_public_bytes(Y)
            elif (isinstance(curve, Curve448)):
                if (len(G) != 56 or G[0] != 5):
                    return ed448.Ed448PublicKey.from_public_bytes(Y)
                return x448.X448PublicKey.from_public_bytes(Y)
        elif (roid == oid.ID_TA_RSA_V1_5_SHA_256):
            n = int.from_bytes(bytes(CVC().decode(cert).pubkey().find(0x81).data()), 'big')
            e = int.from_bytes(bytes(CVC().decode(cert).pubkey().find(0x82).data()), 'big')
            return rsa.RSAPublicNumbers(e, n).public_key()
        return None

    def sign(self, keyid, data, scheme=None):
        resp = self.send(cla=0x80, command=0x68, p1=keyid, p2=scheme or 0x00, data=data)
        return resp

    def verify(self, pubkey, data, signature, scheme=None):
        if (scheme):
            if (Algorithm.ALGO_EC_RAW <= scheme <= Algorithm.ALGO_EC_SHA512):
                if (scheme == Algorithm.ALGO_EC_SHA1):
                    hsh = hashes.SHA1()
                elif (scheme == Algorithm.ALGO_EC_SHA224):
                    hsh = hashes.SHA224()
                elif (scheme == Algorithm.ALGO_EC_SHA256):
                    hsh = hashes.SHA256()
                elif (scheme == Algorithm.ALGO_EC_RAW):
                    hsh = utils.Prehashed(hashes.SHA512())
                elif (scheme == Algorithm.ALGO_EC_SHA384):
                    hsh = hashes.SHA384()
                elif (scheme == Algorithm.ALGO_EC_SHA512):
                    hsh = hashes.SHA512()
                return pubkey.verify(signature, data, ec.ECDSA(hsh))
            elif (Algorithm.ALGO_RSA_PKCS1_SHA1 <= scheme <= Algorithm.ALGO_RSA_PSS_SHA512):
                if (scheme == Algorithm.ALGO_RSA_PKCS1_SHA1 or scheme == Algorithm.ALGO_RSA_PSS_SHA1):
                    hsh = hashes.SHA1()
                elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA224 or scheme == Algorithm.ALGO_RSA_PSS_SHA224):
                    hsh = hashes.SHA224()
                elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA256 or scheme == Algorithm.ALGO_RSA_PSS_SHA256):
                    hsh = hashes.SHA256()
                elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA384 or scheme == Algorithm.ALGO_RSA_PSS_SHA384):
                    hsh = hashes.SHA384()
                elif (scheme == Algorithm.ALGO_RSA_PKCS1_SHA512 or scheme == Algorithm.ALGO_RSA_PSS_SHA512):
                    hsh = hashes.SHA512()
                if (Algorithm.ALGO_RSA_PKCS1_SHA1 <= scheme <= Algorithm.ALGO_RSA_PKCS1_SHA512):
                    padd = padding.PKCS1v15()
                elif (Algorithm.ALGO_RSA_PSS_SHA1 <= scheme <= Algorithm.ALGO_RSA_PSS_SHA512):
                    padd = padding.PSS(
                        mgf=padding.MGF1(hsh),
                        salt_length=padding.PSS.AUTO
                    )
                return pubkey.verify(signature, data, padd, hsh)
        return pubkey.verify(signature, data)

    def decrypt(self, keyid, data, pad):
        if (isinstance(pad, padding.OAEP)):
            p2 = Padding.OAEP
        elif (isinstance(pad, padding.PKCS1v15)):
            p2 = Padding.PKCS
        else:
            p2 = Padding.RAW
        resp = self.send(command=0x62, p1=keyid, p2=p2, data=list(data))
        return resp

    def import_dkek(self, dkek, key_domain=0):
        resp = self.send(cla=0x80, command=0x52, p1=0x0, p2=key_domain, data=dkek)
        return PicoHSM.__parse_key_domain(resp)

    def __pubkey_uncompressed(pubkey):
        if (isinstance(pubkey, ec.EllipticCurvePrivateKey)):
            pubkey = pubkey.public_key()
        return pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def wrap_key(pkey, dkek=None, purposes=None):
        data = b''
        kcv = hashlib.sha256(dkek or b'\x00'*32).digest()[:8]
        kenc = hashlib.sha256((dkek or b'\x00'*32) + b'\x00\x00\x00\x01').digest()
        kmac = hashlib.sha256((dkek or b'\x00'*32) + b'\x00\x00\x00\x02').digest()
        data += kcv
        if (isinstance(pkey, rsa.RSAPrivateKey)):
            data += b'\x05'
            algo = OID.RSA
        elif (isinstance(pkey, (ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))):
            data += b'\x0C'
            algo = OID.EC
        elif (isinstance(pkey, bytes)):
            data += b'\x0F'
            algo = OID.AES

        data += algo
        if (not purposes and isinstance(pkey, bytes)):
            purposes = [Algorithm.ALGO_AES_CBC_ENCRYPT, Algorithm.ALGO_AES_CBC_DECRYPT, Algorithm.ALGO_AES_CMAC, Algorithm.ALGO_AES_DERIVE, Algorithm.ALGO_EXT_CIPHER_ENCRYPT, Algorithm.ALGO_EXT_CIPHER_DECRYPT]
        if (purposes):
            data += b'\x00' + bytes([len(purposes)]) + bytes(purposes) + b'\x00'*4
        else:
            data += b'\x00'*6

        kb = os.urandom(8)
        if (isinstance(pkey, rsa.RSAPrivateKey)):
            kb += int_to_bytes(pkey.key_size, length=2)
            pubnum = pkey.public_key().public_numbers()
            pnum = pkey.private_numbers()
            kb += int_to_bytes((pnum.d.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pnum.d)
            kb += int_to_bytes((pubnum.n.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pubnum.n)
            kb += int_to_bytes((pubnum.e.bit_length()+7)//8, length=2)
            kb += int_to_bytes(pubnum.e)
        elif (isinstance(pkey, (ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))):
            if (isinstance(pkey, x25519.X25519PrivateKey)):
                name = 'curve25519'
            elif (isinstance(pkey, x448.X448PrivateKey)):
                name = 'curve448'
            elif (isinstance(pkey, ed25519.Ed25519PrivateKey)):
                name = 'Ed25519'
            elif (isinstance(pkey, ed448.Ed448PrivateKey)):
                name = 'Ed448'
            else:
                name = pkey.curve.name
            curve = EcCurve.from_name(name)
            kb += int_to_bytes(len(curve.P)*8, length=2)
            kb += int_to_bytes(len(curve.A), length=2)
            kb += curve.A
            kb += int_to_bytes(len(curve.B), length=2)
            kb += curve.B
            kb += int_to_bytes(len(curve.P), length=2)
            kb += curve.P
            kb += int_to_bytes(len(curve.O), length=2)
            kb += curve.O
            kb += int_to_bytes(len(curve.G), length=2)
            kb += curve.G
            if (isinstance(pkey, (x25519.X25519PrivateKey, x448.X448PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))):
                raw = pkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                kb += int_to_bytes(len(raw), length=2)
                kb += raw
                raw = pkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                kb += int_to_bytes(len(raw), length=2)
                kb += raw
            else:
                kb += int_to_bytes((pkey.private_numbers().private_value.bit_length()+7)//8, length=2)
                kb += int_to_bytes(pkey.private_numbers().private_value)
                p = PicoHSM.__pubkey_uncompressed(pkey)
                kb += int_to_bytes(len(p), length=2)
                kb += p
        elif (isinstance(pkey, bytes)):
            kb += int_to_bytes(len(pkey), length=2)
            kb += pkey

        kb_len_pad = (len(kb)//16)*16
        if (len(kb) % 16 > 0):
            kb_len_pad = (len(kb)//16 + 1)*16
        if (len(kb) < kb_len_pad):
            kb += b'\x80'
            kb += b'\x00' * (kb_len_pad-len(kb))
        cipher = Cipher(algorithms.AES(kenc), modes.CBC(b'\x00'*16))
        encryptor = cipher.encryptor()
        ct = encryptor.update(kb) + encryptor.finalize()
        data += ct
        c = cmac.CMAC(algorithms.AES(kmac))
        c.update(data)
        data += c.finalize()
        return data

    def import_key(self, pkey, dkek=None, purposes=None):
        data = PicoHSM.wrap_key(pkey, dkek, purposes)

        p1 = self.get_first_free_id()
        _ = self.send(cla=0x80, command=0x74, p1=p1, p2=0x93, data=data)
        return p1

    def export_key(self, keyid):
        resp = self.send(cla=0x80, command=0x72, p1=keyid, p2=0x92)
        return resp

    def exchange(self, keyid, pubkey):
        if (isinstance(pubkey, x25519.X25519PublicKey) or isinstance(pubkey, x448.X448PublicKey)):
            data = pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            data = PicoHSM.__pubkey_uncompressed(pubkey)
        resp = self.send(cla=0x80, command=0x62, p1=keyid, p2=Algorithm.ALGO_EC_ECDH, data=data)
        return resp[1:]

    def parse_cvc(self, data):
        car = CVC().decode(data).car()
        chr = CVC().decode(data).chr()
        return {'car': car, 'chr': chr, 'data': data}

    def get_termca(self):
        resp = self.get_contents(EF_TERMCA)
        if (resp):
            cv_data = self.parse_cvc(resp)
            a = ASN1().decode(resp).find(0x7f21).data()
            tlen = len(ASN1.calculate_len(len(a)))
            ret = {'cv': cv_data}
            if (len(a)+2+tlen < len(resp)): # There's more certificate
                resp = resp[2+len(a)+tlen:]
                dv_data = self.parse_cvc(resp)
                ret['dv'] = dv_data
            return ret
        return None

    def get_version(self):
        resp = self.send(cla=0x80, command=0x50)
        return resp[5]+0.1*resp[6]

    def __parse_key_domain(resp):
        ret = {
                'dkek': {
                    'total': resp[0],
                    'missing': resp[1]
                },
                'kcv': resp[2:10]
            }
        if (len(resp) > 10):
            ret.update({'xkek': resp[10:]})
        return ret

    def get_key_domain(self, key_domain=0):
        resp, code = self.send(cla=0x80, command=0x52, p2=key_domain, codes=[0x9000, 0x6A88, 0x6A86])
        if (code == 0x9000):
            return PicoHSM.__parse_key_domain(resp)
        return {'error': code}

    def get_key_domains(self):
        for k in range(0xFF):
            _, code = self.send(cla=0x80, command=0x52, p2=k, codes=[0x9000, 0x6A88, 0x6A86])
            if (code == 0x6A86):
                return k
        return 0

    def set_key_domain(self, key_domain=0, total=DEFAULT_DKEK_SHARES):
        resp = self.send(cla=0x80, command=0x52, p1=0x1, p2=key_domain, data=[total])
        return PicoHSM.__parse_key_domain(resp)

    def clear_key_domain(self, key_domain=0):
        resp = self.send(cla=0x80, command=0x52, p1=0x4, p2=key_domain)
        return resp

    def delete_key_domain(self, key_domain=0):
        self.send(cla=0x80, command=0x52, p1=0x3, p2=key_domain, codes=[0x6A88])

    def get_challenge(self, length):
        resp = self.send(cla=0x80, command=0x84, ne=length)
        return resp

    def cipher(self, algo, keyid, data):
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=algo, data=data)
        return resp

    def hmac(self, hash, keyid, data):
        if (hash == hashes.SHA1):
            algo = OID.SHA1
        elif (hash == hashes.SHA224):
            algo = OID.SHA224
        elif (hash == hashes.SHA256):
            algo = OID.SHA256
        elif (hash == hashes.SHA384):
            algo = OID.SHA384
        elif (hash == hashes.SHA512):
            algo = OID.SHA512
        else:
            raise ValueError("Hash not supported")
        data = [0x06, len(algo)] + list(algo) + [0x81, len(data)] + list(data)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=0x51, data=data)
        return resp

    def cmac(self, keyid, data):
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=Algorithm.ALGO_AES_CMAC, data=data)
        return resp

    def hkdf(self, hash, keyid, data, salt, out_len=None):
        if (hash == hashes.SHA256):
            algo = OID.HKDF_SHA256
        elif (hash == hashes.SHA384):
            algo = OID.HKDF_SHA384
        elif (hash == hashes.SHA512):
            algo = OID.HKDF_SHA512
        data = [0x06, len(algo)] + list(algo) + [0x81, len(data)] + list(data) + [0x82, len(salt)] + list(salt)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=0x51, data=data, ne=out_len)
        return resp

    def pbkdf2(self, hash, keyid, salt, iterations, out_len=None):
        oid = OID.PBKDF2
        salt = b'\x04' + bytes([len(salt)]) + salt
        iteration = b'\x02' + bytes([len(int_to_bytes(iterations))]) + int_to_bytes(iterations)
        prf = b'\x30\x0A\x06\x08'
        if (hash == hashes.SHA1):
            prf += OID.SHA1
        elif (hash == hashes.SHA224):
            prf += OID.SHA224
        elif (hash == hashes.SHA256):
            prf += OID.SHA256
        elif (hash == hashes.SHA384):
            prf += OID.SHA384
        elif (hash == hashes.SHA512):
            prf += OID.SHA512
        data = list(salt + iteration + prf)
        data = [0x06, len(oid)] + list(oid) + [0x81, len(data)] + list(data)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=0x51, data=data, ne=out_len)
        return resp

    def x963(self, hash, keyid, data, out_len=None):
        oid = OID.KDF_X963
        if (hash == hashes.SHA1):
            enc = OID.SHA1
        elif (hash == hashes.SHA224):
            enc = OID.SHA224
        elif (hash == hashes.SHA256):
            enc = OID.SHA256
        elif (hash == hashes.SHA384):
            enc = OID.SHA384
        elif (hash == hashes.SHA512):
            enc = OID.SHA512
        else:
            raise ValueError("Hash not supported")
        data = [0x06, len(oid)] + list(oid) + [0x81, len(enc)] + list(enc) + [0x83, len(data)] + list(data)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=0x51, data=data, ne=out_len)
        return resp

    def verify_certificate(self, cert):
        chr = CVC().decode(cert).chr()
        pukref = ASN1().add_tag(0x83, chr).encode()
        _, code = self.send(command=0x22, p1=0x81, p2=0xB6, data=pukref, codes=[0x9000, 0x6A88])
        if (code == 0x9000):
            return

        car = CVC().decode(cert).car()
        pukref = ASN1().add_tag(0x83, car).encode()
        self.send(command=0x22, p1=0x81, p2=0xB6, data=pukref)

        data = ASN1().decode(cert).find(0x7F21).data()
        self.send(command=0x2A, p2=0xBE, data=data)

    def register_puk(self, puk, devcert, dicacert, replace=0):
        self.verify_certificate(devcert)
        self.verify_certificate(dicacert)

        car = CVC().decode(puk).outer_car()
        pukref = ASN1().add_tag(0x83, car).encode()
        self.send(command=0x22, p1=0x81, p2=0xB6, data=pukref)

        data = ASN1().decode(puk).find(0x67).data()
        p1,p2 = 0,0
        if (replace > 0):
            p1 = 0x1
            p2 = replace
        status = self.send(cla=0x80, command=0x54, p1=p1, p2=p2, data=data)
        return status

    def get_puk_status(self):
        status = self.send(cla=0x80, command=0x54)
        return status

    def enumerate_puk(self):
        puk_no = self.get_puk_status()[0]
        puks = []
        for i in range(puk_no):
            bin, code = self.send(cla=0x80, command=0x54, p1=0x02, p2=i, codes=[0x9000, 0x9001, 0x6A88])
            if (code == 0x6A88):
                puks.append({'status': -1})
            else:
                puks.append({'status': code & 0x1, 'chr': bin})
        return puks

    def is_puk(self):
        _, code = self.send(cla=0x80, command=0x54, p1=0x02, codes=[0x9000, 0x9001, 0x6A88, 0x6A86])
        return code != 0x6A86

    def check_puk_key(self, chr):
        pukref = ASN1().add_tag(0x83, chr).encode()
        _, code = self.send(command=0x22, p1=0x81, p2=0xA4, data=pukref, codes=[0x9000, 0x6A88, 0x6985])
        if (code == 0x9000):
            return 0
        elif (code == 0x6985):
            return 1
        return -1

    def puk_prepare_signature(self):
        challenge = self.send(command=0x84, ne=8)
        input = self.device_id + bytes(challenge)
        return input

    def authenticate_puk(self, chr, signature):
        pukref = ASN1().add_tag(0x83, chr).encode()
        self.send(command=0x22, p1=0x81, p2=0xA4, data=pukref)
        self.send(command=0x82, data=signature)

    def create_xkek(self, kdm):
        dicacert = ASN1().decode(kdm).find(0x30).find(0x61).data()
        devcert = ASN1().decode(kdm).find(0x30).find(0x62).data()
        gskcert = ASN1().decode(kdm).find(0x30).find(0x63).data()
        gsksign = ASN1().decode(kdm).find(0x30).find(0x54).data(return_tag=True)
        gskdata = CVC().decode(gskcert).req().data()
        self.verify_certificate(devcert)
        self.verify_certificate(dicacert)
        status = self.send(cla=0x80, command=0x52, p1=0x02, data=gskdata + gsksign)
        return status[2:10], status[10:]

    def generate_xkek_key(self, key_domain=0):
        key_id = self.key_generation(KeyType.ECC, 'brainpoolP256r1', algorithms=[Algorithm.ALGO_EC_ECDH_XKEK], key_domain=key_domain)
        return key_id

    def derive_xkek(self, keyid, cert):
        self.send(cla=0x80, command=0x62, p1=keyid, p2=Algorithm.ALGO_EC_ECDH_XKEK, data=cert)

    def delete_xkek(self, key_domain=0):
        self.send(cla=0x80, command=0x52, p1=0x04, p2=key_domain)

    def chachapoly(self, keyid, mode, data, iv=None, aad=None):
        oid = OID.CHACHAPOLY
        data = [0x06, len(oid)] + list(oid) + [0x81, len(data)] + list(data)
        if (iv is not None):
            data += [0x82, len(iv)] + list(iv)
        if (aad is not None):
            data += [0x83, len(aad)] + list(aad)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=Algorithm.ALGO_EXT_CIPHER_ENCRYPT if mode == EncryptionMode.ENCRYPT else Algorithm.ALGO_EXT_CIPHER_DECRYPT, data=data)
        return resp

    def keyinfo(self, keyid):
        resp = self.get_contents(DOPrefixes.PRKD_PREFIX, keyid)
        ret = {}
        if (resp):
            key_size = b''
            if (resp[0] == 0x30):
                ret['type'] = KeyType.RSA
                key_size = ASN1().decode(resp).find(0x30).find(0xA1).find(0x30).find(0x2).data()
            elif (resp[0] == 0xA0):
                ret['type'] = KeyType.ECC
                key_size = ASN1().decode(resp).find(0xA0).find(0xA1).find(0x30).find(0x2).data()
            elif (resp[0] == 0xA8):
                ret['type'] = KeyType.AES
                key_size = ASN1().decode(resp).find(0xA8).find(0xA0).find(0x30).find(0x2).data()
            ret['key_size'] = int.from_bytes(key_size, 'big')
            ret['label'] = bytes(ASN1().decode(resp).find(resp[0]).find(0x30).find(0xC).data()).decode()
            ret['key_id'] = bytes(ASN1().decode(resp).find(resp[0]).find(0x30, pos=1).find(0x4).data())
        return ret

    def aes(self, keyid, mode, algorithm, data, iv=None, aad=None):
        resp = self.keyinfo(keyid)
        if ('key_size' not in resp):
            raise ValueError('Key info not found')
        key_size = resp['key_size']
        oid = None
        if (algorithm == AES.ECB):
            if (key_size == 128):
                oid = OID.AES128_ECB
            elif (key_size == 192):
                oid = OID.AES192_ECB
            elif (key_size == 256):
                oid = OID.AES256_ECB
        elif (algorithm == AES.CBC):
            if (key_size == 128):
                oid = OID.AES128_CBC
            elif (key_size == 192):
                oid = OID.AES192_CBC
            elif (key_size == 256):
                oid = OID.AES256_CBC
        elif (algorithm == AES.OFB):
            if (key_size == 128):
                oid = OID.AES128_OFB
            elif (key_size == 192):
                oid = OID.AES192_OFB
            elif (key_size == 256):
                oid = OID.AES256_OFB
        elif (algorithm == AES.CFB):
            if (key_size == 128):
                oid = OID.AES128_CFB
            elif (key_size == 192):
                oid = OID.AES192_CFB
            elif (key_size == 256):
                oid = OID.AES256_CFB
        elif (algorithm == AES.GCM):
            if (key_size == 128):
                oid = OID.AES128_GCM
            elif (key_size == 192):
                oid = OID.AES192_GCM
            elif (key_size == 256):
                oid = OID.AES256_GCM
        elif (algorithm == AES.XTS):
            if (key_size == 256):
                oid = OID.AES128_XTS
            elif (key_size == 512):
                oid = OID.AES256_XTS
        elif (algorithm == AES.CTR):
            if (key_size == 128):
                oid = OID.AES128_CTR
            elif (key_size == 192):
                oid = OID.AES192_CTR
            elif (key_size == 256):
                oid = OID.AES256_CTR
        elif (algorithm == AES.CCM):
            if (key_size == 128):
                oid = OID.AES128_CCM
            elif (key_size == 192):
                oid = OID.AES192_CCM
            elif (key_size == 256):
                oid = OID.AES256_CCM
        if (oid is None):
            raise ValueError('Algorithm not valid')
        data = [0x06, len(oid)] + list(oid) + [0x81, len(data)] + list(data)
        if (iv is not None):
            data += [0x82, len(iv)] + list(iv)
        if (aad is not None):
            data += [0x83, len(aad)] + list(aad)
        resp = self.send(cla=0x80, command=0x78, p1=keyid, p2=Algorithm.ALGO_EXT_CIPHER_ENCRYPT if mode == EncryptionMode.ENCRYPT else Algorithm.ALGO_EXT_CIPHER_DECRYPT, data=data)
        return resp

    def delete_key(self, keyid):
        try:
            self.delete_file(DOPrefixes.KEY_PREFIX, keyid)
            self.delete_file(DOPrefixes.PRKD_PREFIX, keyid)
            self.delete_file(DOPrefixes.EE_CERTIFICATE_PREFIX, keyid)
        except APDUResponse:
            pass

    def _hd_encode_path(path):
        data = b''
        for ix, c in enumerate(path):
            if ((ix == 0 and c >= 256) or (isinstance(c, int) and c >= 2**32)):
                raise ValueError('Only integers allowed')
            if (isinstance(c, int)):
                data += b'\x02'
                if (ix == 0):
                    data += b'\x01' + bytes([c])
                else:
                    data += b'\x04' + c.to_bytes(4, 'big')
            elif (isinstance(c, bytes)):
                if (len(c) >= 128):
                    raise ValueError('Path larger than 127 bytes')
                data += b'\x04' + bytes([len(c)]) + c
        return data

    def hd_generate_master_node(self, curve='secp256k1', id=0x0, seed=None):
        if (curve not in ['secp256k1', 'secp256r1', 'symmetric']):
            raise ValueError('Unknown curve. Only \'secp256k1\', \'secp256r1\' and \'symmetric\' are supported')
        p1 = 0x1
        if (curve == 'secp256r1'):
            p1 = 0x2
        elif (curve == 'symmetric'):
            p1 = 0x3
        resp = self.send(cla=0x80, command=0x4A, p1=p1, p2=id, data=seed)
        return resp

    def hd_derive_node(self, path):
        data = PicoHSM._hd_encode_path(path)
        resp = self.send(cla=0x80, command=0x4A, p1=0x0A, p2=0x00, data=data)
        resp = base58.b58encode_check(resp)
        return resp

    def hd_decode_xpub(xpub):
        data = base58.b58decode_check(xpub)
        return {
            'type': data[:4],
            'depth': data[4],
            'fingerprint': data[5:9],
            'child': int.from_bytes(data[9:13], 'big'),
            'chain': data[13:45],
            'public': data[45:78]
        }

    def hd_signature(self, path, data):
        path = PicoHSM._hd_encode_path(path)
        self.send(cla=0x80, command=0x4A, p1=0x10, p2=0x00, data=path)
        resp = self.send(cla=0x80, command=0x68, p1=0x00, p2=0xA0, data=hashlib.sha256(data).digest())
        return resp

    def hd_cipher(self, path, aad, data, mode, ask_on_encrypt=True, ask_on_decrypt=True, iv=b""):
        if (len(data) % 16 > 0):
            raise ValueError("Input length must be a multiple of 16")
        oid = OID.HD
        data = [0x06, len(oid)] + list(oid) + [0x81, len(data)] + list(data)
        if (iv is not None):
            data += [0x82, len(iv)] + list(iv)
        if (aad is not None):
            aad += b"E1" if ask_on_encrypt else b"E0"
            aad += b"D1" if ask_on_decrypt else b"D0"
            data += [0x83, len(aad)] + list(aad)
        path = PicoHSM._hd_encode_path(path)
        self.send(cla=0x80, command=0x4A, p1=0x10, p2=0x00, data=path)
        resp = self.send(cla=0x80, command=0x78, p1=0x00, p2=Algorithm.ALGO_EXT_CIPHER_ENCRYPT if mode == EncryptionMode.ENCRYPT else Algorithm.ALGO_EXT_CIPHER_DECRYPT, data=data)
        return resp

    def general_authentication(self):
        self.send(command=0x22, p1=0x41, p2=0xA4, data=ASN1().add_tag(0x80, SecureChannel.PROTO_OID).encode())
        pkeyB = ec.generate_private_key(ec.SECP256R1())
        pbkeyB = pkeyB.public_key()
        pbkeyBbytes = PicoHSM.__pubkey_uncompressed(pbkeyB)
        dado = ASN1().add_tag(0x7C, ASN1().add_tag(0x80, pbkeyBbytes).encode()).encode()
        resp = self.send(command=0x86, data=dado)
        a = ASN1().decode(resp).find(0x7C)
        if (not a):
            raise ValueError("SM: cannot find tag 7C")
        t81 = ASN1().decode(resp).find(0x7C).find(0x81)
        if (not t81):
            raise ValueError("SM: cannot find tag 81")
        t82 = ASN1().decode(resp).find(0x7C).find(0x82)
        if (not t82):
            raise ValueError("SM: cannot find tag 82")
        nonce = t81.data()
        token = t82.data()
        return pkeyB, nonce, token

    def open_secure_channel(self):
        pkeyB, nonce, token = self.general_authentication()
        pbkeyA = self.public_key(0x00, param='secp256r1')
        shared = pkeyB.exchange(ec.ECDH(), pbkeyA)
        pbkeyBbytes = PicoHSM.__pubkey_uncompressed(pkeyB)
        sc = SecureChannel(shared=shared, nonce=nonce)
        res = sc.verify_token(token, pbkeyBbytes)
        if (not res):
            raise ValueError("SM: signature mismatch")
        self.__sc = sc

    def phy(self, subcommand, val):
        if (subcommand == 'vidpid'):
            p2 = 0x0
        elif (subcommand == 'led_gpio'):
            p2 = 0x4
        elif (subcommand == 'led_brightness'):
            p2 = 0x5
        elif (subcommand == 'wcid' or subcommand == 'led_dimmable'):
            p2 = 0x6
            if (val is not None):
                resp = self.send(cla=0x80, command=0x64, p1=0x1B, p2=p2)
                if (resp):
                    opts = (resp[p2] << 8) | resp[p2+1]
                else:
                    opts = 0
                opt = 0
                if (subcommand == 'wcid'):
                    opt = PHYOpts.PHY_OPT_WCID
                elif (subcommand == 'led_dimmable'):
                    opt = PHYOpts.PHY_OPT_LED_DIM
                if (val):
                    opts |= opt
                else:
                    opts &= ~opt
                val = [opts >> 8, opts & 0xFF]
        resp = None
        if (val):
            self.send(cla=0x80, command=0x64, p1=0x1B, p2=p2, data=val)
        else:
            resp = self.send(cla=0x80, command=0x64, p1=0x1B, p2=p2)
        return resp

    def otp(self, row, data=None, raw=False, redundant=0, length=16):
        p2 = 0x1 if raw else 0x0
        payload = list(row.to_bytes(2, 'big'))
        if (data):
            align = (4 if raw else 2)
            if (len(data) % align != 0):
                raise ValueError(f"Data length must be a multiple of {align}")
            self.send(cla=0x80, command=0x64, p1=0x4C, p2=p2, data=payload+list(data))
            for r in range(redundant):
                self.otp(row+r+1, data, raw=raw, redundant=0)
        else:
            resp = self.send(cla=0x80, command=0x64, p1=0x4C, p2=p2, ne=length, data=payload)
            for r in range(redundant):
                retr = self.otp(row+r+1, raw=raw, redundant=0, length=length)
                if (retr != resp):
                    raise ValueError("OTP register mismatch")
            return resp

    def _otp_register(self, row, length, raw=False, redundant=0):
        ret = []
        irow = row
        align = (4 if raw else 2)
        while len(ret) < length:
            resp = self.otp(irow, raw=raw, redundant=redundant, length=align)
            bts = min(length-len(ret), len(resp))
            ret += resp[:bts]
            irow += 1
        return ret

    def secure_boot(self, bootkey_hash, bootkey_index=0, lock=False):
        # Write bootkey hash
        if (len(bootkey_hash) != 32):
            raise ValueError("Bootkey hash must be 32 bytes")
        if (bootkey_index not in [0,1,2,3]):
            raise ValueError("Bootkey index must be between 0 and 3")
        row_index = [0x80, 0x90, 0xA0, 0xB0]
        self.otp(row_index[bootkey_index], bootkey_hash)
        bootkey = self._otp_register(row_index[bootkey_index], 32)
        assert(bootkey == bootkey_hash)

        # Write bootkey valid
        resp = self._otp_register(0x4b, 3, raw=True, redundant=2)
        boot_flag1 = resp[0] | (0x01 << bootkey_index)
        self.otp(0x4b, [boot_flag1, resp[1], resp[2], 0], raw=True, redundant=2)

        # Enable secure boot
        resp = self._otp_register(0x40, 3, raw=True, redundant=7)
        secure_boot_enable = resp[0] | 0x01
        self.otp(0x40, [secure_boot_enable, resp[1], resp[2], 0], raw=True, redundant=7)

        if (lock):
            inp = input("This will lock the chip without possibility to add more bootkeys and will run only with Pico Keys firmware. Type 'LOCK' to continue: ")
            if (inp != "LOCK"):
                print('Aborted')
                return

            # Disable debug, enable glitch detector and set glitch sensitivity
            debug_disable = (0x01 << 2)
            glitch_detector = (0x01 << 4)
            glitch_sens = (0x3 << 5)
            resp = self._otp_register(0x40, 3, raw=True, redundant=7)
            flags = resp[0] | debug_disable | glitch_detector | glitch_sens
            self.otp(0x40, [flags, resp[1], resp[2], 0], raw=True, redundant=7)

            # Invalid all remaining keys
            resp = self._otp_register(0x4b, 3, raw=True, redundant=2)
            key_invalid = resp[1] | (0xF & (~(0x01 << bootkey_index)))
            self.otp(0x4b, [resp[0], key_invalid, resp[2], 0], raw=True, redundant=2)

            # Lock Page 1 & 2
            resp = self._otp_register(0xf83, 3, raw=True)
            flags = resp[0] | 0x10
            self.otp(0xf83, [flags, flags, flags, 0], raw=True)
            resp = self._otp_register(0xf85, 3, raw=True)
            flags = resp[0] | 0x10
            self.otp(0xf85, [flags, flags, flags, 0], raw=True)

    def reboot(self):
        self.send(cla=0x80, command=0x64, p1=0xFB)

    def memory(self):
        resp = self.send(cla=0x80, command=0x64, p1=0x5)
        free = int.from_bytes(resp[:4], 'big')
        used = int.from_bytes(resp[4:8], 'big')
        total = int.from_bytes(resp[8:12], 'big')
        nfiles = int.from_bytes(resp[12:16], 'big')
        size = int.from_bytes(resp[16:20], 'big')
        return {'free': free, 'used': used, 'total': total, 'files': nfiles, 'size': size}
