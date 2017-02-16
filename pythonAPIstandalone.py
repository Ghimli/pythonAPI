#!/usr/bin/env python3

import base64,time,requests,hashlib,sys,ctypes.util,struct

apikey=""
secret=""

if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x[0]
    from io import BytesIO as _BytesIO
else:
    _bchr = chr
    _bord = ord
    from cStringIO import StringIO as _BytesIO

MAX_SIZE = 0x02000000

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')

class OpenSSLException(EnvironmentError):
    pass

# Thx to Sam Devlin for the ctypes magic 64-bit fix (FIXME: should this
# be applied to every OpenSSL call whose return type is a pointer?)
def _check_res_void_p(val, func, args): # pylint: disable=unused-argument
    if val == 0:
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise OpenSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)

_ssl.BN_add.restype = ctypes.c_int
_ssl.BN_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_bin2bn.restype = ctypes.c_void_p
_ssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

_ssl.BN_cmp.restype = ctypes.c_int
_ssl.BN_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_copy.restype = ctypes.c_void_p
_ssl.BN_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_free.restype = None
_ssl.BN_free.argtypes = [ctypes.c_void_p]

_ssl.BN_mod_inverse.restype = ctypes.c_void_p
_ssl.BN_mod_inverse.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mod_mul.restype = ctypes.c_int
_ssl.BN_mod_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mod_sub.restype = ctypes.c_int
_ssl.BN_mod_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mul_word.restype = ctypes.c_int
_ssl.BN_mul_word.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_new.errcheck = _check_res_void_p
_ssl.BN_new.restype = ctypes.c_void_p
_ssl.BN_new.argtypes = []

_ssl.BN_rshift.restype = ctypes.c_int
_ssl.BN_rshift.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

_ssl.BN_rshift1.restype = ctypes.c_int
_ssl.BN_rshift1.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_sub.restype = ctypes.c_int
_ssl.BN_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

# _ssl.BN_zero.restype = ctypes.c_int
# _ssl.BN_zero.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_free.restype = None
_ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_get.restype = ctypes.c_void_p
_ssl.BN_CTX_get.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_new.errcheck = _check_res_void_p
_ssl.BN_CTX_new.restype = ctypes.c_void_p
_ssl.BN_CTX_new.argtypes = []

_ssl.EC_GROUP_get_curve_GFp.restype = ctypes.c_int
_ssl.EC_GROUP_get_curve_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_GROUP_get_degree.restype = ctypes.c_int
_ssl.EC_GROUP_get_degree.argtypes = [ctypes.c_void_p]

_ssl.EC_GROUP_get_order.restype = ctypes.c_int
_ssl.EC_GROUP_get_order.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_KEY_free.restype = None
_ssl.EC_KEY_free.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_new_by_curve_name.errcheck = _check_res_void_p
_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

_ssl.EC_KEY_get0_group.restype = ctypes.c_void_p
_ssl.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_get0_public_key.restype = ctypes.c_void_p
_ssl.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_set_conv_form.restype = None
_ssl.EC_KEY_set_conv_form.argtypes = [ctypes.c_void_p, ctypes.c_int]

_ssl.EC_KEY_set_private_key.restype = ctypes.c_int
_ssl.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_KEY_set_public_key.restype = ctypes.c_int
_ssl.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_free.restype = None
_ssl.EC_POINT_free.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_is_at_infinity.restype = ctypes.c_int
_ssl.EC_POINT_is_at_infinity.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_new.errcheck = _check_res_void_p
_ssl.EC_POINT_new.restype = ctypes.c_void_p
_ssl.EC_POINT_new.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_mul.restype = ctypes.c_int
_ssl.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_set_compressed_coordinates_GFp.restype = ctypes.c_int
_ssl.EC_POINT_set_compressed_coordinates_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

_ssl.ECDSA_sign.restype = ctypes.c_int
_ssl.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.ECDSA_size.restype = ctypes.c_int
_ssl.ECDSA_size.argtypes = [ctypes.c_void_p]

_ssl.ECDSA_verify.restype = ctypes.c_int
_ssl.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

_ssl.ECDSA_SIG_free.restype = None
_ssl.ECDSA_SIG_free.argtypes = [ctypes.c_void_p]

_ssl.ECDH_compute_key.restype = ctypes.c_int
_ssl.ECDH_compute_key.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

_ssl.ERR_error_string_n.restype = None
_ssl.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

_ssl.ERR_get_error.restype = ctypes.c_ulong
_ssl.ERR_get_error.argtypes = []

_ssl.d2i_ECDSA_SIG.restype = ctypes.c_void_p
_ssl.d2i_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.d2i_ECPrivateKey.restype = ctypes.c_void_p
_ssl.d2i_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.i2d_ECDSA_SIG.restype = ctypes.c_int
_ssl.i2d_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2d_ECPrivateKey.restype = ctypes.c_int
_ssl.i2d_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2o_ECPublicKey.restype = ctypes.c_void_p
_ssl.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.o2i_ECPublicKey.restype = ctypes.c_void_p
_ssl.o2i_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

# test that OpenSSL supports secp256k1
_ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

class ECDSA_SIG_st(ctypes.Structure):
    _fields_ = [("r", ctypes.c_void_p),
                ("s", ctypes.c_void_p)]

class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()

    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()

    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) is not None
        return self

    @classmethod
    def recover_compact(cls, hash, sig): # pylint: disable=redefined-builtin
        """Recover a public key from a compact signature."""
        if len(sig) != 65:
            raise ValueError("Signature should be 65 characters, not [%d]" % (len(sig), ))

        recid = (_bord(sig[0]) - 27) & 3
        compressed = (_bord(sig[0]) - 27) & 4 != 0

        cec_key = CECKey()
        cec_key.set_compressed(compressed)

        sigR = sig[1:33]
        sigS = sig[33:65]

        result = cec_key.recover(sigR, sigS, hash, len(hash), recid, 0)

        if result < 1:
            return False

        pubkey = cec_key.get_pubkey()

        return CPubKey(pubkey, _cec_key=cec_key)

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        # Always have represent as b'<secret>' so test cases don't have to
        # change for py2/3
        if sys.version > '3':
            return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
        else:
            return '%s(b%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

class CKey(object):
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key

    is_compressed - True if compressed

    """
    def __init__(self, secret, compressed=True):
        self._cec_key = CECKey()
        self._cec_key.set_secretbytes(secret)
        self._cec_key.set_compressed(compressed)

        self.pub = CPubKey(self._cec_key.get_pubkey(), self._cec_key)

    @property
    def is_compressed(self):
        return self.pub.is_compressed

    def sign(self, hash):
        return self._cec_key.sign(hash)

    def sign_compact(self, hash):
        return self._cec_key.sign_compact(hash)

def CompareBigEndian(c1, c2):
    """
    Loosely matches CompareBigEndian() from eccryptoverify.cpp
    Compares two arrays of bytes, and returns a negative value if the first is
    less than the second, 0 if they're equal, and a positive value if the
    first is greater than the second.
    """
    c1 = list(c1)
    c2 = list(c2)

    # Adjust starting positions until remaining lengths of the two arrays match
    while len(c1) > len(c2):
        if c1.pop(0) > 0:
            return 1
    while len(c2) > len(c1):
        if c2.pop(0) > 0:
            return -1

    while len(c1) > 0:
        diff = c1.pop(0) - c2.pop(0)
        if diff != 0:
            return diff

    return 0

def IsLowDERSignature(sig):
    """
    Loosely correlates with IsLowDERSignature() from script/interpreter.cpp
    Verifies that the S value in a DER signature is the lowest possible value.
    Used by BIP62 malleability fixes.
    """
    length_r = sig[3]
    if isinstance(length_r, str):
        length_r = int(struct.unpack('B', length_r)[0])
    length_s = sig[5 + length_r]
    if isinstance(length_s, str):
        length_s = int(struct.unpack('B', length_s)[0])
    s_val = list(struct.unpack(str(length_s) + 'B', sig[6 + length_r:6 + length_r + length_s]))

    # If the S value is above the order of the curve divided by two, its
    # complement modulo the order could have been used instead, which is
    # one byte shorter when encoded correctly.
    max_mod_half_order = [
      0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,
      0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0]

    return CompareBigEndian(s_val, [0]) > 0 and \
      CompareBigEndian(s_val, max_mod_half_order) <= 0

class SerializationError(Exception):
    """Base class for serialization errors"""

def Hash(msg):
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()

class DeserializationExtraDataError(SerializationError):
    """Deserialized data had extra data at the end

    Thrown by deserialize() when not all data is consumed during
    deserialization. The deserialized object and extra padding not consumed are
    saved.
    """
    def __init__(self, msg, obj, padding):
        super(DeserializationExtraDataError, self).__init__(msg)
        self.obj = obj
        self.padding = padding

class Serializable(object):
    """Base class for serializable objects"""

    __slots__ = []

    def stream_serialize(self, f):
        """Serialize to a stream"""
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f):
        """Deserialize from a stream"""
        raise NotImplementedError

    def serialize(self):
        """Serialize, returning bytes"""
        f = _BytesIO()
        self.stream_serialize(f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf, allow_padding=False):
        """Deserialize bytes, returning an instance

        allow_padding - Allow buf to include extra padding. (default False)

        If allow_padding is False and not all bytes are consumed during
        deserialization DeserializationExtraDataError will be raised.
        """
        fd = _BytesIO(buf)
        r = cls.stream_deserialize(fd)
        if not allow_padding:
            padding = fd.read()
            if len(padding) != 0:
                raise DeserializationExtraDataError('Not all bytes consumed during deserialization',
                                                    r, padding)
        return r

    def GetHash(self):
        """Return the hash of the serialized object"""
        return Hash(self.serialize())

    def __eq__(self, other):
        if (not isinstance(other, self.__class__) and
            not isinstance(self, other.__class__)):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.serialize())

class ImmutableSerializable(Serializable):
    """Immutable serializable object"""

    __slots__ = ['_cached_GetHash', '_cached__hash__']

    def __setattr__(self, name, value):
        raise AttributeError('Object is immutable')

    def __delattr__(self, name):
        raise AttributeError('Object is immutable')

    def GetHash(self):
        """Return the hash of the serialized object"""
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = super(ImmutableSerializable, self).GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def __hash__(self):
        try:
            return self._cached__hash__
        except AttributeError:
            _cached__hash__ = hash(self.serialize())
            object.__setattr__(self, '_cached__hash__', _cached__hash__)
            return _cached__hash__

class Serializer(object):
    """Base class for object serializers"""
    def __new__(cls):
        raise NotImplementedError

    @classmethod
    def stream_serialize(cls, obj, f):
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f):
        raise NotImplementedError

    @classmethod
    def serialize(cls, obj):
        f = _BytesIO()
        cls.stream_serialize(obj, f)
        return f.getvalue()

    @classmethod
    def deserialize(cls, buf):
        if isinstance(buf, str) or isinstance(buf, bytes):
            buf = _BytesIO(buf)
        return cls.stream_deserialize(buf)

class VarIntSerializer(Serializer):
    """Serialization of variable length ints"""
    @classmethod
    def stream_serialize(cls, i, f):
        if i < 0:
            raise ValueError('varint must be non-negative integer')
        elif i < 0xfd:
            f.write(_bchr(i))
        elif i <= 0xffff:
            f.write(_bchr(0xfd))
            f.write(struct.pack(b'<H', i))
        elif i <= 0xffffffff:
            f.write(_bchr(0xfe))
            f.write(struct.pack(b'<I', i))
        else:
            f.write(_bchr(0xff))
            f.write(struct.pack(b'<Q', i))

    @classmethod
    def stream_deserialize(cls, f):
        r = _bord(ser_read(f, 1))
        if r < 0xfd:
            return r
        elif r == 0xfd:
            return struct.unpack(b'<H', ser_read(f, 2))[0]
        elif r == 0xfe:
            return struct.unpack(b'<I', ser_read(f, 4))[0]
        else:
            return struct.unpack(b'<Q', ser_read(f, 8))[0]

class SerializationTruncationError(SerializationError):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """
    
def ser_read(f, n):
    """Read from a stream safely

    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded' % n)
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r

class BytesSerializer(Serializer):
    """Serialization of bytes instances"""
    @classmethod
    def stream_serialize(cls, b, f):
        VarIntSerializer.stream_serialize(len(b), f)
        f.write(b)

    @classmethod
    def stream_deserialize(cls, f):
        l = VarIntSerializer.stream_deserialize(f)
        return ser_read(f, l)

class DERSignature(ImmutableSerializable):
    __slots__ = ['length', 'r', 's']

    def __init__(self, r, s, length):
        object.__setattr__(self, 'r', r)
        object.__setattr__(self, 's', s)
        object.__setattr__(self, 'length', length)

    @classmethod
    def stream_deserialize(cls, f):
        assert ser_read(f, 1) == b"\x30"
        rs = BytesSerializer.stream_deserialize(f)
        f = _BytesIO(rs)
        assert ser_read(f, 1) == b"\x02"
        r = BytesSerializer.stream_deserialize(f)
        assert ser_read(f, 1) == b"\x02"
        s = BytesSerializer.stream_deserialize(f)
        return cls(r, s, len(r + s))

    def stream_serialize(self, f):
        f.write(b"\x30")
        f.write(b"\x02")
        BytesSerializer.stream_serialize(self.r, f)
        f.write(b"\x30")
        BytesSerializer.stream_serialize(self.s, f)

    def __repr__(self):
        return 'DERSignature(%s, %s)' % (self.r, self.s)

class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

    def __del__(self):
        if _ssl:
            _ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = _ssl.BN_bin2bn(secret, 32, _ssl.BN_new())
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        if not _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _ssl.EC_POINT_free(pub_key)
        _ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = _ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        _ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = _ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        _ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = _ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 _ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash): # pylint: disable=redefined-builtin
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = _ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result
        if IsLowDERSignature(mb_sig.raw[:sig_size0.value]):
            return mb_sig.raw[:sig_size0.value]
        else:
            return self.signature_to_low_s(mb_sig.raw[:sig_size0.value])

    def sign_compact(self, hash): # pylint: disable=redefined-builtin
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = _ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result

        if IsLowDERSignature(mb_sig.raw[:sig_size0.value]):
            sig = mb_sig.raw[:sig_size0.value]
        else:
            sig = self.signature_to_low_s(mb_sig.raw[:sig_size0.value])

        sig = DERSignature.deserialize(sig)

        r_val = sig.r
        s_val = sig.s

        # assert that the r and s are less than 32 long, excluding leading 0s
        assert len(r_val) <= 32 or r_val[0:-32] == b'\x00'
        assert len(s_val) <= 32 or s_val[0:-32] == b'\x00'

        # ensure r and s are always 32 chars long by 0padding
        r_val = ((b'\x00' * 32) + r_val)[-32:]
        s_val = ((b'\x00' * 32) + s_val)[-32:]

        # tmp pubkey of self, but always compressed
        pubkey = CECKey()
        pubkey.set_pubkey(self.get_pubkey())
        pubkey.set_compressed(True)

        # bitcoin core does <4, but I've seen other places do <2 and I've never seen a i > 1 so far
        for i in range(0, 4):
            cec_key = CECKey()
            cec_key.set_compressed(True)

            result = cec_key.recover(r_val, s_val, hash, len(hash), i, 1)
            if result == 1:
                if cec_key.get_pubkey() == pubkey.get_pubkey():
                    return r_val + s_val, i

        raise ValueError

    def signature_to_low_s(self, sig):
        der_sig = ECDSA_SIG_st()
        _ssl.d2i_ECDSA_SIG(ctypes.byref(ctypes.pointer(der_sig)), ctypes.byref(ctypes.c_char_p(sig)), len(sig))
        group = _ssl.EC_KEY_get0_group(self.k)
        order = _ssl.BN_new()
        halforder = _ssl.BN_new()
        ctx = _ssl.BN_CTX_new()
        _ssl.EC_GROUP_get_order(group, order, ctx)
        _ssl.BN_rshift1(halforder, order)

        # Verify that s is over half the order of the curve before we actually subtract anything from it
        if _ssl.BN_cmp(der_sig.s, halforder) > 0:
          _ssl.BN_sub(der_sig.s, order, der_sig.s)

        _ssl.BN_free(halforder)
        _ssl.BN_free(order)
        _ssl.BN_CTX_free(ctx)

        derlen = _ssl.i2d_ECDSA_SIG(ctypes.pointer(der_sig), 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(der_sig)
            return None
        new_sig = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(ctypes.pointer(der_sig), ctypes.byref(ctypes.pointer(new_sig)))
        _ssl.BN_free(der_sig.r)
        _ssl.BN_free(der_sig.s)

        return new_sig.raw

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        """Verify a DER signature"""
        if not sig:
          return False

        # New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
        norm_sig = ctypes.c_void_p(0)
        _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return False

        norm_der = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))
        _ssl.ECDSA_SIG_free(norm_sig)

        # -1 = error, 0 = bad sig, 1 = good
        return _ssl.ECDSA_verify(0, hash, len(hash), norm_der, derlen, self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        _ssl.EC_KEY_set_conv_form(self.k, form)

    def recover(self, sigR, sigS, msg, msglen, recid, check):
        """
        Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields

        recid selects which key is recovered

        if check is non-zero, additional checks are performed
        """
        i = int(recid / 2)

        r = None
        s = None
        ctx = None
        R = None
        O = None
        Q = None

        assert len(sigR) == 32, len(sigR)
        assert len(sigS) == 32, len(sigS)

        try:
            r = _ssl.BN_bin2bn(bytes(sigR), len(sigR), _ssl.BN_new())
            s = _ssl.BN_bin2bn(bytes(   sigS), len(sigS), _ssl.BN_new())

            group = _ssl.EC_KEY_get0_group(self.k)
            ctx = _ssl.BN_CTX_new()
            order = _ssl.BN_CTX_get(ctx)
            ctx = _ssl.BN_CTX_new()

            if not _ssl.EC_GROUP_get_order(group, order, ctx):
                return -2

            x = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_copy(x, order):
                return -1
            if not _ssl.BN_mul_word(x, i):
                return -1
            if not _ssl.BN_add(x, x, r):
                return -1

            field = _ssl.BN_CTX_get(ctx)
            if not _ssl.EC_GROUP_get_curve_GFp(group, field, None, None, ctx):
                return -2

            if _ssl.BN_cmp(x, field) >= 0:
                return 0

            R = _ssl.EC_POINT_new(group)
            if R is None:
                return -2
            if not _ssl.EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx):
                return 0

            if check:
                O = _ssl.EC_POINT_new(group)
                if O is None:
                    return -2
                if not _ssl.EC_POINT_mul(group, O, None, R, order, ctx):
                    return -2
                if not _ssl.EC_POINT_is_at_infinity(group, O):
                    return 0

            Q = _ssl.EC_POINT_new(group)
            if Q is None:
                return -2

            n = _ssl.EC_GROUP_get_degree(group)
            e = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_bin2bn(msg, msglen, e):
                return -1

            if 8 * msglen > n:
                _ssl.BN_rshift(e, e, 8 - (n & 7))

            zero = _ssl.BN_CTX_get(ctx)
            # if not _ssl.BN_zero(zero):
            #     return -1
            if not _ssl.BN_mod_sub(e, zero, e, order, ctx):
                return -1
            rr = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_inverse(rr, r, order, ctx):
                return -1
            sor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(sor, s, rr, order, ctx):
                return -1
            eor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(eor, e, rr, order, ctx):
                return -1
            if not _ssl.EC_POINT_mul(group, Q, eor, R, sor, ctx):
                return -2

            if not _ssl.EC_KEY_set_public_key(self.k, Q):
                return -2

            return 1
        finally:
            if r: _ssl.BN_free(r)
            if s: _ssl.BN_free(s)
            if ctx: _ssl.BN_CTX_free(ctx)
            if R: _ssl.EC_POINT_free(R)
            if O: _ssl.EC_POINT_free(O)
            if Q: _ssl.EC_POINT_free(Q)

def SignECDSA(key, message):
    sig, i = key.sign_compact(message)

    meta = 27 + i
    if key.is_compressed:
        meta += 4

    return base64.b64encode(chr(meta) + sig)

privkey = CKey(base64.b64decode(secret),False)
nonce=str(int(time.time()))
msg = "nonce="+nonce
sign = SignECDSA(privkey, hashlib.sha256(hashlib.sha256("Bitmaszyna.pl API:\n"+msg).digest()).digest())
print(requests.post('https://bitmaszyna.pl/api/funds', data={'nonce':nonce},  headers={'Rest-Key' : apikey, 'Rest-Sign' : sign}).json())
