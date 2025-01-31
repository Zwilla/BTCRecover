"""tests for passlib.hash -- (c) Assurance Technologies 2003-2009"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement
# core
import re
import hashlib
from logging import getLogger
import warnings
# site
# pkg
from lib.passlib.hash import ldap_md5, sha256_crypt
from lib.passlib.exc import MissingBackendError, PasslibHashWarning
from lib.passlib.utils.compat import str_to_uascii, \
                                 uascii_to_str, unicode
import passlib.utils.handlers as uh
from lib.passlib.tests.utils import HandlerCase, TestCase
from lib.passlib.utils.compat import u
# module
log = getLogger(__name__)

#=============================================================================
# utils
#=============================================================================
def _makelang(alphabet, size):
    """generate all strings of given size using alphabet"""
    def helper(size):
        if size < 2:
            for char in alphabet:
                yield char
        else:
            for char in alphabet:
                for tail in helper(size-1):
                    yield char+tail
    return set(helper(size))

#=============================================================================
# test GenericHandler & associates mixin classes
#=============================================================================
class SkeletonTest(TestCase):
    """test hash support classes"""

    #===================================================================
    # StaticHandler
    #===================================================================
    def test_00_static_handler(self):
        """test StaticHandler class"""

        class d1(uh.StaticHandler):
            name = "d1"
            context_kwds = ("flag",)
            _hash_prefix = u("_")
            checksum_chars = u("ab")
            checksum_size = 1

            def __init__(self, flag=False, **kwds):
                super(d1, self).__init__(**kwds)
                self.flag = flag

            def _calc_checksum(self, secret):
                return u('b') if self.flag else u('a')

        # check default identify method
        self.assertTrue(d1.identify(u('_a')))
        self.assertTrue(d1.identify(b'_a'))
        self.assertTrue(d1.identify(u('_b')))

        self.assertFalse(d1.identify(u('_c')))
        self.assertFalse(d1.identify(b'_c'))
        self.assertFalse(d1.identify(u('a')))
        self.assertFalse(d1.identify(u('b')))
        self.assertFalse(d1.identify(u('c')))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)

        # check default genconfig method
        self.assertEqual(d1.genconfig(), d1.hash(""))

        # check default verify method
        self.assertTrue(d1.verify('s', b'_a'))
        self.assertTrue(d1.verify('s',u('_a')))
        self.assertFalse(d1.verify('s', b'_b'))
        self.assertFalse(d1.verify('s',u('_b')))
        self.assertTrue(d1.verify('s', b'_b', flag=True))
        self.assertRaises(ValueError, d1.verify, 's', b'_c')
        self.assertRaises(ValueError, d1.verify, 's', u('_c'))

        # check default hash method
        self.assertEqual(d1.hash('s'), '_a')
        self.assertEqual(d1.hash('s', flag=True), '_b')

    def test_01_calc_checksum_hack(self):
        """test StaticHandler legacy attr"""
        # release 1.5 StaticHandler required genhash(),
        # not _calc_checksum, be implemented. we have backward compat wrapper,
        # this tests that it works.

        class d1(uh.StaticHandler):
            name = "d1"

            @classmethod
            def identify(cls, hash):
                if not hash or len(hash) != 40:
                    return False
                try:
                    int(hash, 16)
                except ValueError:
                    return False
                return True

            @classmethod
            def genhash(cls, secret, hash):
                if secret is None:
                    raise TypeError("no secret provided")
                if isinstance(secret, unicode):
                    secret = secret.encode("utf-8")
                # NOTE: have to support hash=None since this is test of legacy 1.5 api
                if hash is not None and not cls.identify(hash):
                    raise ValueError("invalid hash")
                return hashlib.sha1(b"xyz" + secret).hexdigest()

            @classmethod
            def verify(cls, secret, hash):
                if hash is None:
                    raise ValueError("no hash specified")
                return cls.genhash(secret, hash) == hash.lower()

        # hash should issue api warnings, but everything else should be fine.
        with self.assertWarningList("d1.*should be updated.*_calc_checksum"):
            hash = d1.hash("test")
        self.assertEqual(hash, '7c622762588a0e5cc786ad0a143156f9fd38eea3')

        self.assertTrue(d1.verify("test", hash))
        self.assertFalse(d1.verify("xtest", hash))

        # not defining genhash either, however, should cause NotImplementedError
        del d1.genhash
        self.assertRaises(NotImplementedError, d1.hash, 'test')

    #===================================================================
    # GenericHandler & mixins
    #===================================================================
    def test_10_identify(self):
        """test GenericHandler.identify()"""
        class d1(uh.GenericHandler):
            @classmethod
            def from_string(cls, hash):
                if isinstance(hash, bytes):
                    hash = hash.decode("ascii")
                if hash == u('a'):
                    return cls(checksum=hash)
                else:
                    raise ValueError

        # check fallback
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertFalse(d1.identify(''))
        self.assertTrue(d1.identify('a'))
        self.assertFalse(d1.identify('b'))

        # check regexp
        d1._hash_regex = re.compile(u('@.'))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertTrue(d1.identify('@a'))
        self.assertFalse(d1.identify('a'))
        del d1._hash_regex

        # check ident-based
        d1.ident = u('!')
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)
        self.assertTrue(d1.identify('!a'))
        self.assertFalse(d1.identify('a'))
        del d1.ident

    def test_11_norm_checksum(self):
        """test GenericHandler checksum handling"""
        # setup helpers
        class d1(uh.GenericHandler):
            name = 'd1'
            checksum_size = 4
            checksum_chars = u('xz')

        def norm_checksum(checksum=None, **k):
            return d1(checksum=checksum, **k).checksum

        # too small
        self.assertRaises(ValueError, norm_checksum, u('xxx'))

        # right size
        self.assertEqual(norm_checksum(u('xxxx')), u('xxxx'))
        self.assertEqual(norm_checksum(u('xzxz')), u('xzxz'))

        # too large
        self.assertRaises(ValueError, norm_checksum, u('xxxxx'))

        # wrong chars
        self.assertRaises(ValueError, norm_checksum, u('xxyx'))

        # wrong type
        self.assertRaises(TypeError, norm_checksum, b'xxyx')

        # relaxed
        # NOTE: this could be turned back on if we test _norm_checksum() directly...
        #with self.assertWarningList("checksum should be unicode"):
        #    self.assertEqual(norm_checksum(b'xxzx', relaxed=True), u('xxzx'))
        #self.assertRaises(TypeError, norm_checksum, 1, relaxed=True)

        # test _stub_checksum behavior
        self.assertEqual(d1()._stub_checksum, u('xxxx'))

    def test_12_norm_checksum_raw(self):
        """test GenericHandler + HasRawChecksum mixin"""
        class d1(uh.HasRawChecksum, uh.GenericHandler):
            name = 'd1'
            checksum_size = 4

        def norm_checksum(*a, **k):
            return d1(*a, **k).checksum

        # test bytes
        self.assertEqual(norm_checksum(b'1234'), b'1234')

        # test unicode
        self.assertRaises(TypeError, norm_checksum, u('xxyx'))

        # NOTE: this could be turned back on if we test _norm_checksum() directly...
        # self.assertRaises(TypeError, norm_checksum, u('xxyx'), relaxed=True)

        # test _stub_checksum behavior
        self.assertEqual(d1()._stub_checksum, b'\x00'*4)

    def test_20_norm_salt(self):
        """test GenericHandler + HasSalt mixin"""
        # setup helpers
        class d1(uh.HasSalt, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('salt',)
            min_salt_size = 2
            max_salt_size = 4
            default_salt_size = 3
            salt_chars = 'ab'

        def norm_salt(**k):
            return d1(**k).salt

        def gen_salt(sz, **k):
            return d1.using(salt_size=sz, **k)(use_defaults=True).salt

        salts2 = _makelang('ab', 2)
        salts3 = _makelang('ab', 3)
        salts4 = _makelang('ab', 4)

        # check salt=None
        self.assertRaises(TypeError, norm_salt)
        self.assertRaises(TypeError, norm_salt, salt=None)
        self.assertIn(norm_salt(use_defaults=True), salts3)

        # check explicit salts
        with warnings.catch_warnings(record=True) as wlog:

            # check too-small salts
            self.assertRaises(ValueError, norm_salt, salt='')
            self.assertRaises(ValueError, norm_salt, salt='a')
            self.consumeWarningList(wlog)

            # check correct salts
            self.assertEqual(norm_salt(salt='ab'), 'ab')
            self.assertEqual(norm_salt(salt='aba'), 'aba')
            self.assertEqual(norm_salt(salt='abba'), 'abba')
            self.consumeWarningList(wlog)

            # check too-large salts
            self.assertRaises(ValueError, norm_salt, salt='aaaabb')
            self.consumeWarningList(wlog)

        # check generated salts
        with warnings.catch_warnings(record=True) as wlog:

            # check too-small salt size
            self.assertRaises(ValueError, gen_salt, 0)
            self.assertRaises(ValueError, gen_salt, 1)
            self.consumeWarningList(wlog)

            # check correct salt size
            self.assertIn(gen_salt(2), salts2)
            self.assertIn(gen_salt(3), salts3)
            self.assertIn(gen_salt(4), salts4)
            self.consumeWarningList(wlog)

            # check too-large salt size
            self.assertRaises(ValueError, gen_salt, 5)
            self.consumeWarningList(wlog)

            self.assertIn(gen_salt(5, relaxed=True), salts4)
            self.consumeWarningList(wlog, ["salt_size.*above max_salt_size"])

        # test with max_salt_size=None
        del d1.max_salt_size
        with self.assertWarningList([]):
            self.assertEqual(len(gen_salt(None)), 3)
            self.assertEqual(len(gen_salt(5)), 5)

    # TODO: test HasRawSalt mixin

    def test_30_init_rounds(self):
        """test GenericHandler + HasRounds mixin"""
        # setup helpers
        class d1(uh.HasRounds, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('rounds',)
            min_rounds = 1
            max_rounds = 3
            default_rounds = 2

        # NOTE: really is testing _init_rounds(), could dup to test _norm_rounds() via .replace
        def norm_rounds(**k):
            return d1(**k).rounds

        # check rounds=None
        self.assertRaises(TypeError, norm_rounds)
        self.assertRaises(TypeError, norm_rounds, rounds=None)
        self.assertEqual(norm_rounds(use_defaults=True), 2)

        # check rounds=non int
        self.assertRaises(TypeError, norm_rounds, rounds=1.5)

        # check explicit rounds
        with warnings.catch_warnings(record=True) as wlog:
            # too small
            self.assertRaises(ValueError, norm_rounds, rounds=0)
            self.consumeWarningList(wlog)

            # just right
            self.assertEqual(norm_rounds(rounds=1), 1)
            self.assertEqual(norm_rounds(rounds=2), 2)
            self.assertEqual(norm_rounds(rounds=3), 3)
            self.consumeWarningList(wlog)

            # too large
            self.assertRaises(ValueError, norm_rounds, rounds=4)
            self.consumeWarningList(wlog)

        # check no default rounds
        d1.default_rounds = None
        self.assertRaises(TypeError, norm_rounds, use_defaults=True)

    def test_40_backends(self):
        """test GenericHandler + HasManyBackends mixin"""
        class d1(uh.HasManyBackends, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ()

            backends = ("a", "b")

            _enable_a = False
            _enable_b = False

            @classmethod
            def _load_backend_a(cls):
                if cls._enable_a:
                    cls._set_calc_checksum_backend(cls._calc_checksum_a)
                    return True
                else:
                    return False

            @classmethod
            def _load_backend_b(cls):
                if cls._enable_b:
                    cls._set_calc_checksum_backend(cls._calc_checksum_b)
                    return True
                else:
                    return False

            def _calc_checksum_a(self, secret):
                return 'a'

            def _calc_checksum_b(self, secret):
                return 'b'

        # test no backends
        self.assertRaises(MissingBackendError, d1.get_backend)
        self.assertRaises(MissingBackendError, d1.set_backend)
        self.assertRaises(MissingBackendError, d1.set_backend, 'any')
        self.assertRaises(MissingBackendError, d1.set_backend, 'default')
        self.assertFalse(d1.has_backend())

        # enable 'b' backend
        d1._enable_b = True

        # test lazy load
        obj = d1()
        self.assertEqual(obj._calc_checksum('s'), 'b')

        # test repeat load
        d1.set_backend('b')
        d1.set_backend('any')
        self.assertEqual(obj._calc_checksum('s'), 'b')

        # test unavailable
        self.assertRaises(MissingBackendError, d1.set_backend, 'a')
        self.assertTrue(d1.has_backend('b'))
        self.assertFalse(d1.has_backend('a'))

        # enable 'a' backend also
        d1._enable_a = True

        # test explicit
        self.assertTrue(d1.has_backend())
        d1.set_backend('a')
        self.assertEqual(obj._calc_checksum('s'), 'a')

        # test unknown backend
        self.assertRaises(ValueError, d1.set_backend, 'c')
        self.assertRaises(ValueError, d1.has_backend, 'c')

        # test error thrown if _has & _load are mixed
        d1.set_backend("b")  # switch away from 'a' so next call actually checks loader
        class d2(d1):
            _has_backend_a = True
        self.assertRaises(AssertionError, d2.has_backend, "a")

    def test_41_backends(self):
        """test GenericHandler + HasManyBackends mixin (deprecated api)"""
        warnings.filterwarnings("ignore",
            category=DeprecationWarning,
            message=r".* support for \._has_backend_.* is deprecated.*",
            )

        class d1(uh.HasManyBackends, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ()

            backends = ("a", "b")

            _has_backend_a = False
            _has_backend_b = False

            def _calc_checksum_a(self, secret):
                return 'a'

            def _calc_checksum_b(self, secret):
                return 'b'

        # test no backends
        self.assertRaises(MissingBackendError, d1.get_backend)
        self.assertRaises(MissingBackendError, d1.set_backend)
        self.assertRaises(MissingBackendError, d1.set_backend, 'any')
        self.assertRaises(MissingBackendError, d1.set_backend, 'default')
        self.assertFalse(d1.has_backend())

        # enable 'b' backend
        d1._has_backend_b = True

        # test lazy load
        obj = d1()
        self.assertEqual(obj._calc_checksum('s'), 'b')

        # test repeat load
        d1.set_backend('b')
        d1.set_backend('any')
        self.assertEqual(obj._calc_checksum('s'), 'b')

        # test unavailable
        self.assertRaises(MissingBackendError, d1.set_backend, 'a')
        self.assertTrue(d1.has_backend('b'))
        self.assertFalse(d1.has_backend('a'))

        # enable 'a' backend also
        d1._has_backend_a = True

        # test explicit
        self.assertTrue(d1.has_backend())
        d1.set_backend('a')
        self.assertEqual(obj._calc_checksum('s'), 'a')

        # test unknown backend
        self.assertRaises(ValueError, d1.set_backend, 'c')
        self.assertRaises(ValueError, d1.has_backend, 'c')

    def test_50_norm_ident(self):
        """test GenericHandler + HasManyIdents"""
        # setup helpers
        class d1(uh.HasManyIdents, uh.GenericHandler):
            name = 'd1'
            setting_kwds = ('ident',)
            default_ident = u("!A")
            ident_values = (u("!A"), u("!B"))
            ident_aliases = { u("A"): u("!A")}

        def norm_ident(**k):
            return d1(**k).ident

        # check ident=None
        self.assertRaises(TypeError, norm_ident)
        self.assertRaises(TypeError, norm_ident, ident=None)
        self.assertEqual(norm_ident(use_defaults=True), u('!A'))

        # check valid idents
        self.assertEqual(norm_ident(ident=u('!A')), u('!A'))
        self.assertEqual(norm_ident(ident=u('!B')), u('!B'))
        self.assertRaises(ValueError, norm_ident, ident=u('!C'))

        # check aliases
        self.assertEqual(norm_ident(ident=u('A')), u('!A'))

        # check invalid idents
        self.assertRaises(ValueError, norm_ident, ident=u('B'))

        # check identify is honoring ident system
        self.assertTrue(d1.identify(u("!Axxx")))
        self.assertTrue(d1.identify(u("!Bxxx")))
        self.assertFalse(d1.identify(u("!Cxxx")))
        self.assertFalse(d1.identify(u("A")))
        self.assertFalse(d1.identify(u("")))
        self.assertRaises(TypeError, d1.identify, None)
        self.assertRaises(TypeError, d1.identify, 1)

        # check default_ident missing is detected.
        d1.default_ident = None
        self.assertRaises(AssertionError, norm_ident, use_defaults=True)

    #===================================================================
    # experimental - the following methods are not finished or tested,
    # but way work correctly for some hashes
    #===================================================================
    def test_91_parsehash(self):
        """test parsehash()"""
        # NOTE: this just tests some existing GenericHandler classes
        from passlib import hash

        #
        # parsehash()
        #

        # simple hash w/ salt
        result = hash.des_crypt.parsehash("OgAwTx2l6NADI")
        self.assertEqual(result, {'checksum': u('AwTx2l6NADI'), 'salt': u('Og')})

        # parse rounds and extra implicit_rounds flag
        h = '$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9'
        s = u('LKO/Ute40T3FNF95')
        c = u('U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9')
        result = hash.sha256_crypt.parsehash(h)
        self.assertEqual(result, dict(salt=s, rounds=5000,
                                      implicit_rounds=True, checksum=c))

        # omit checksum
        result = hash.sha256_crypt.parsehash(h, checksum=False)
        self.assertEqual(result, dict(salt=s, rounds=5000, implicit_rounds=True))

        # sanitize
        result = hash.sha256_crypt.parsehash(h, sanitize=True)
        self.assertEqual(result, dict(rounds=5000, implicit_rounds=True,
            salt=u('LK**************'),
             checksum=u('U0pr***************************************')))

        # parse w/o implicit rounds flag
        result = hash.sha256_crypt.parsehash('$5$rounds=10428$uy/jIAhCetNCTtb0$YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3')
        self.assertEqual(result, dict(
            checksum=u('YWvUOXbkqlqhyoPMpN8BMe.ZGsGx2aBvxTvDFI613c3'),
            salt=u('uy/jIAhCetNCTtb0'),
            rounds=10428,
        ))

        # parsing of raw checksums & salts
        h1 = '$pbkdf2$60000$DoEwpvQeA8B4T.k951yLUQ$O26Y3/NJEiLCVaOVPxGXshyjW8k'
        result = hash.pbkdf2_sha1.parsehash(h1)
        self.assertEqual(result, dict(
            checksum=b';n\x98\xdf\xf3I\x12"\xc2U\xa3\x95?\x11\x97\xb2\x1c\xa3[\xc9',
            rounds=60000,
            salt=b'\x0e\x810\xa6\xf4\x1e\x03\xc0xO\xe9=\xe7\\\x8bQ',
        ))

        # sanitizing of raw checksums & salts
        result = hash.pbkdf2_sha1.parsehash(h1, sanitize=True)
        self.assertEqual(result, dict(
            checksum=u('O26************************'),
            rounds=60000,
            salt=u('Do********************'),
        ))

    def test_92_bitsize(self):
        """test bitsize()"""
        # NOTE: this just tests some existing GenericHandler classes
        from passlib import hash

        # no rounds
        self.assertEqual(hash.des_crypt.bitsize(),
                         {'checksum': 66, 'salt': 12})

        # log2 rounds
        self.assertEqual(hash.bcrypt.bitsize(),
                         {'checksum': 186, 'salt': 132})

        # linear rounds
        # NOTE: +3 comes from int(math.log(.1,2)),
        #       where 0.1 = 10% = default allowed variation in rounds
        self.patchAttr(hash.sha256_crypt, "default_rounds", 1 << (14 + 3))
        self.assertEqual(hash.sha256_crypt.bitsize(),
                         {'checksum': 258, 'rounds': 14, 'salt': 96})

        # raw checksum
        self.patchAttr(hash.pbkdf2_sha1, "default_rounds", 1 << (13 + 3))
        self.assertEqual(hash.pbkdf2_sha1.bitsize(),
                         {'checksum': 160, 'rounds': 13, 'salt': 128})

        # TODO: handle fshp correctly, and other glitches noted in code.
        ##self.assertEqual(hash.fshp.bitsize(variant=1),
        ##                {'checksum': 256, 'rounds': 13, 'salt': 128})

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# PrefixWrapper
#=============================================================================
class dummy_handler_in_registry(object):
    """context manager that inserts dummy handler in registry"""
    def __init__(self, name):
        self.name = name
        self.dummy = type('dummy_' + name, (uh.GenericHandler,), dict(
            name=name,
            setting_kwds=(),
        ))

    def __enter__(self):
        from passlib import registry
        registry._unload_handler_name(self.name, locations=False)
        registry.register_crypt_handler(self.dummy)
        assert registry.get_crypt_handler(self.name) is self.dummy
        return self.dummy

    def __exit__(self, *exc_info):
        from passlib import registry
        registry._unload_handler_name(self.name, locations=False)

class PrefixWrapperTest(TestCase):
    """test PrefixWrapper class"""

    def test_00_lazy_loading(self):
        """test PrefixWrapper lazy loading of handler"""
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}", lazy=True)

        # check base state
        self.assertEqual(d1._wrapped_name, "ldap_md5")
        self.assertIs(d1._wrapped_handler, None)

        # check loading works
        self.assertIs(d1.wrapped, ldap_md5)
        self.assertIs(d1._wrapped_handler, ldap_md5)

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_01_active_loading(self):
        """test PrefixWrapper active loading of handler"""
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")

        # check base state
        self.assertEqual(d1._wrapped_name, "ldap_md5")
        self.assertIs(d1._wrapped_handler, ldap_md5)
        self.assertIs(d1.wrapped, ldap_md5)

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_02_explicit(self):
        """test PrefixWrapper with explicitly specified handler"""

        d1 = uh.PrefixWrapper("d1", ldap_md5, "{XXX}", "{MD5}")

        # check base state
        self.assertEqual(d1._wrapped_name, None)
        self.assertIs(d1._wrapped_handler, ldap_md5)
        self.assertIs(d1.wrapped, ldap_md5)

        # replace w/ wrong handler, make sure doesn't reload w/ dummy
        with dummy_handler_in_registry("ldap_md5") as dummy:
            self.assertIs(d1.wrapped, ldap_md5)

    def test_10_wrapped_attributes(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        self.assertEqual(d1.name, "d1")
        self.assertIs(d1.setting_kwds, ldap_md5.setting_kwds)
        self.assertFalse('max_rounds' in dir(d1))

        d2 = uh.PrefixWrapper("d2", "sha256_crypt", "{XXX}")
        self.assertIs(d2.setting_kwds, sha256_crypt.setting_kwds)
        self.assertTrue('max_rounds' in dir(d2))

    def test_11_wrapped_methods(self):
        d1 = uh.PrefixWrapper("d1", "ldap_md5", "{XXX}", "{MD5}")
        dph = "{XXX}X03MO1qnZdYdgyfeuILPmQ=="
        lph = "{MD5}X03MO1qnZdYdgyfeuILPmQ=="

        # genconfig
        self.assertEqual(d1.genconfig(), '{XXX}1B2M2Y8AsgTpgAmY7PhCfg==')

        # genhash
        self.assertRaises(TypeError, d1.genhash, "password", None)
        self.assertEqual(d1.genhash("password", dph), dph)
        self.assertRaises(ValueError, d1.genhash, "password", lph)

        # hash
        self.assertEqual(d1.hash("password"), dph)

        # identify
        self.assertTrue(d1.identify(dph))
        self.assertFalse(d1.identify(lph))

        # verify
        self.assertRaises(ValueError, d1.verify, "password", lph)
        self.assertTrue(d1.verify("password", dph))

    def test_12_ident(self):
        # test ident is proxied
        h = uh.PrefixWrapper("h2", "ldap_md5", "{XXX}")
        self.assertEqual(h.ident, u("{XXX}{MD5}"))
        self.assertIs(h.ident_values, None)

        # test lack of ident means no proxy
        h = uh.PrefixWrapper("h2", "des_crypt", "{XXX}")
        self.assertIs(h.ident, None)
        self.assertIs(h.ident_values, None)

        # test orig_prefix disabled ident proxy
        h = uh.PrefixWrapper("h1", "ldap_md5", "{XXX}", "{MD5}")
        self.assertIs(h.ident, None)
        self.assertIs(h.ident_values, None)

        # test custom ident overrides default
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{X")
        self.assertEqual(h.ident, u("{X"))
        self.assertIs(h.ident_values, None)

        # test custom ident must match
        h = uh.PrefixWrapper("h3", "ldap_md5", "{XXX}", ident="{XXX}A")
        self.assertRaises(ValueError, uh.PrefixWrapper, "h3", "ldap_md5",
                          "{XXX}", ident="{XY")
        self.assertRaises(ValueError, uh.PrefixWrapper, "h3", "ldap_md5",
                          "{XXX}", ident="{XXXX")

        # test ident_values is proxied
        h = uh.PrefixWrapper("h4", "phpass", "{XXX}")
        self.assertIs(h.ident, None)
        self.assertEqual(h.ident_values, (u("{XXX}$P$"), u("{XXX}$H$")))

        # test ident=True means use prefix even if hash has no ident.
        h = uh.PrefixWrapper("h5", "des_crypt", "{XXX}", ident=True)
        self.assertEqual(h.ident, u("{XXX}"))
        self.assertIs(h.ident_values, None)

        # ... but requires prefix
        self.assertRaises(ValueError, uh.PrefixWrapper, "h6", "des_crypt", ident=True)

        # orig_prefix + HasManyIdent - warning
        with self.assertWarningList("orig_prefix.*may not work correctly"):
            h = uh.PrefixWrapper("h7", "phpass", orig_prefix="$", prefix="?")
        self.assertEqual(h.ident_values, None) # TODO: should output (u("?P$"), u("?H$")))
        self.assertEqual(h.ident, None)

    def test_13_repr(self):
        """test repr()"""
        h = uh.PrefixWrapper("h2", "md5_crypt", "{XXX}", orig_prefix="$1$")
        self.assertRegex(repr(h),
            r"""(?x)^PrefixWrapper\(
                ['"]h2['"],\s+
                ['"]md5_crypt['"],\s+
                prefix=u?["']{XXX}['"],\s+
                orig_prefix=u?["']\$1\$['"]
            \)$""")

    def test_14_bad_hash(self):
        """test orig_prefix sanity check"""
        # shoudl throw InvalidHashError if wrapped hash doesn't begin
        # with orig_prefix.
        h = uh.PrefixWrapper("h2", "md5_crypt", orig_prefix="$6$")
        self.assertRaises(ValueError, h.hash, 'test')

#=============================================================================
# sample algorithms - these serve as known quantities
# to test the unittests themselves, as well as other
# parts of passlib. they shouldn't be used as actual password schemes.
#=============================================================================
class UnsaltedHash(uh.StaticHandler):
    """test algorithm which lacks a salt"""
    name = "unsalted_test_hash"
    checksum_chars = uh.LOWER_HEX_CHARS
    checksum_size = 40

    def _calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = b"boblious" + secret
        return str_to_uascii(hashlib.sha1(data).hexdigest())

class SaltedHash(uh.HasSalt, uh.GenericHandler):
    """test algorithm with a salt"""
    name = "salted_test_hash"
    setting_kwds = ("salt",)

    min_salt_size = 2
    max_salt_size = 4
    checksum_size = 40
    salt_chars = checksum_chars = uh.LOWER_HEX_CHARS

    _hash_regex = re.compile(u("^@salt[0-9a-f]{42,44}$"))

    @classmethod
    def from_string(cls, hash):
        if not cls.identify(hash):
            raise uh.exc.InvalidHashError(cls)
        if isinstance(hash, bytes):
            hash = hash.decode("ascii")
        return cls(salt=hash[5:-40], checksum=hash[-40:])

    def to_string(self):
        hash = u("@salt%s%s") % (self.salt, self.checksum)
        return uascii_to_str(hash)

    def _calc_checksum(self, secret):
        if isinstance(secret, unicode):
            secret = secret.encode("utf-8")
        data = self.salt.encode("ascii") + secret + self.salt.encode("ascii")
        return str_to_uascii(hashlib.sha1(data).hexdigest())

#=============================================================================
# test sample algorithms - really a self-test of HandlerCase
#=============================================================================

# TODO: provide data samples for algorithms
#       (positive knowns, negative knowns, invalid identify)

UPASS_TEMP = u('\u0399\u03c9\u03b1\u03bd\u03bd\u03b7\u03c2')

class UnsaltedHashTest(HandlerCase):
    handler = UnsaltedHash

    known_correct_hashes = [
        ("password", "61cfd32684c47de231f1f982c214e884133762c0"),
        (UPASS_TEMP, '96b329d120b97ff81ada770042e44ba87343ad2b'),
    ]

    def test_bad_kwds(self):
        self.assertRaises(TypeError, UnsaltedHash, salt='x')
        self.assertRaises(TypeError, UnsaltedHash.genconfig, rounds=1)

class SaltedHashTest(HandlerCase):
    handler = SaltedHash

    known_correct_hashes = [
        ("password", '@salt77d71f8fe74f314dac946766c1ac4a2a58365482c0'),
        (UPASS_TEMP, '@salt9f978a9bfe360d069b0c13f2afecd570447407fa7e48'),
    ]

    def test_bad_kwds(self):
        stub = SaltedHash(use_defaults=True)._stub_checksum
        self.assertRaises(TypeError, SaltedHash, checksum=stub, salt=None)
        self.assertRaises(ValueError, SaltedHash, checksum=stub, salt='xxx')

#=============================================================================
# eof
#=============================================================================
