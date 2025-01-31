"""tests for passlib.context

this file is a clone of the 1.5 test_context.py,
containing the tests using the legacy CryptPolicy api.
it's being preserved here to ensure the old api doesn't break
(until Passlib 1.8, when this and the legacy api will be removed).
"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement
# core
from logging import getLogger
import os
import warnings
# site
try:
    from pkg_resources import resource_filename
except ImportError:
    resource_filename = None
# pkg
from passlib import hash
from lib.passlib.context import CryptContext, CryptPolicy, LazyCryptContext
from lib.passlib.utils import to_bytes, to_unicode
import passlib.utils.handlers as uh
from lib.passlib.tests.utils import TestCase, set_file
from lib.passlib.registry import (register_crypt_handler_path,
                        _has_crypt_handler as has_crypt_handler,
                        _unload_handler_name as unload_handler_name,
                        )
# module
log = getLogger(__name__)

#=============================================================================
#
#=============================================================================
class CryptPolicyTest(TestCase):
    """test CryptPolicy object"""

    # TODO: need to test user categories w/in all this

    descriptionPrefix = "CryptPolicy"

    #===================================================================
    # sample crypt policies used for testing
    #===================================================================

    #---------------------------------------------------------------
    # sample 1 - average config file
    #---------------------------------------------------------------
    # NOTE: copy of this is stored in file passlib/tests/sample_config_1s.cfg
    sample_config_1s = """\
[passlib]
schemes = des_crypt, md5_crypt, bsdi_crypt, sha512_crypt
default = md5_crypt
all.vary_rounds = 10%%
bsdi_crypt.max_rounds = 30000
bsdi_crypt.default_rounds = 25000
sha512_crypt.max_rounds = 50000
sha512_crypt.min_rounds = 40000
"""
    sample_config_1s_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "sample_config_1s.cfg"))
    if not os.path.exists(sample_config_1s_path) and resource_filename:
        # in case we're zipped up in an egg.
        sample_config_1s_path = resource_filename("passlib.tests",
                                                  "sample_config_1s.cfg")

    # make sure sample_config_1s uses \n linesep - tests rely on this
    assert sample_config_1s.startswith("[passlib]\nschemes")

    sample_config_1pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "md5_crypt",
        # NOTE: not maintaining backwards compat for rendering to "10%"
        all__vary_rounds = 0.1,
        bsdi_crypt__max_rounds = 30000,
        bsdi_crypt__default_rounds = 25000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds = 40000,
    )

    sample_config_1pid = {
        "schemes": "des_crypt, md5_crypt, bsdi_crypt, sha512_crypt",
        "default": "md5_crypt",
        # NOTE: not maintaining backwards compat for rendering to "10%"
        "all.vary_rounds": 0.1,
        "bsdi_crypt.max_rounds": 30000,
        "bsdi_crypt.default_rounds": 25000,
        "sha512_crypt.max_rounds": 50000,
        "sha512_crypt.min_rounds": 40000,
    }

    sample_config_1prd = dict(
        schemes = [ hash.des_crypt, hash.md5_crypt, hash.bsdi_crypt, hash.sha512_crypt],
        default = "md5_crypt", # NOTE: passlib <= 1.5 was handler obj.
        # NOTE: not maintaining backwards compat for rendering to "10%"
        all__vary_rounds = 0.1,
        bsdi_crypt__max_rounds = 30000,
        bsdi_crypt__default_rounds = 25000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds = 40000,
    )

    #---------------------------------------------------------------
    # sample 2 - partial policy & result of overlay on sample 1
    #---------------------------------------------------------------
    sample_config_2s = """\
[passlib]
bsdi_crypt.min_rounds = 29000
bsdi_crypt.max_rounds = 35000
bsdi_crypt.default_rounds = 31000
sha512_crypt.min_rounds = 45000
"""

    sample_config_2pd = dict(
        # using this to test full replacement of existing options
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        # using this to test partial replacement of existing options
        sha512_crypt__min_rounds=45000,
    )

    sample_config_12pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "md5_crypt",
        # NOTE: not maintaining backwards compat for rendering to "10%"
        all__vary_rounds = 0.1,
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds=45000,
    )

    #---------------------------------------------------------------
    # sample 3 - just changing default
    #---------------------------------------------------------------
    sample_config_3pd = dict(
        default="sha512_crypt",
    )

    sample_config_123pd = dict(
        schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
        default = "sha512_crypt",
        # NOTE: not maintaining backwards compat for rendering to "10%"
        all__vary_rounds = 0.1,
        bsdi_crypt__min_rounds = 29000,
        bsdi_crypt__max_rounds = 35000,
        bsdi_crypt__default_rounds = 31000,
        sha512_crypt__max_rounds = 50000,
        sha512_crypt__min_rounds=45000,
    )

    #---------------------------------------------------------------
    # sample 4 - category specific
    #---------------------------------------------------------------
    sample_config_4s = """
[passlib]
schemes = sha512_crypt
all.vary_rounds = 10%%
default.sha512_crypt.max_rounds = 20000
admin.all.vary_rounds = 5%%
admin.sha512_crypt.max_rounds = 40000
"""

    sample_config_4pd = dict(
        schemes = [ "sha512_crypt" ],
        # NOTE: not maintaining backwards compat for rendering to "10%"
        all__vary_rounds = 0.1,
        sha512_crypt__max_rounds = 20000,
        # NOTE: not maintaining backwards compat for rendering to "5%"
        admin__all__vary_rounds = 0.05,
        admin__sha512_crypt__max_rounds = 40000,
        )

    #---------------------------------------------------------------
    # sample 5 - to_string & deprecation testing
    #---------------------------------------------------------------
    sample_config_5s = sample_config_1s + """\
deprecated = des_crypt
admin__context__deprecated = des_crypt, bsdi_crypt
"""

    sample_config_5pd = sample_config_1pd.copy()
    sample_config_5pd.update(
        deprecated = [ "des_crypt" ],
        admin__context__deprecated = [ "des_crypt", "bsdi_crypt" ],
    )

    sample_config_5pid = sample_config_1pid.copy()
    sample_config_5pid.update({
        "deprecated": "des_crypt",
        "admin.context.deprecated": "des_crypt, bsdi_crypt",
    })

    sample_config_5prd = sample_config_1prd.copy()
    sample_config_5prd.update({
        # XXX: should deprecated return the actual handlers in this case?
        #      would have to modify how policy stores info, for one.
        "deprecated": ["des_crypt"],
        "admin__context__deprecated": ["des_crypt", "bsdi_crypt"],
    })

    #===================================================================
    # constructors
    #===================================================================
    def setUp(self):
        TestCase.setUp(self)
        warnings.filterwarnings("ignore",
                                r"The CryptPolicy class has been deprecated")
        warnings.filterwarnings("ignore",
                                r"the method.*hash_needs_update.*is deprecated")
        warnings.filterwarnings("ignore", "The 'all' scheme is deprecated.*")
        warnings.filterwarnings("ignore", "bsdi_crypt rounds should be odd")

    def test_00_constructor(self):
        """test CryptPolicy() constructor"""
        policy = CryptPolicy(**self.sample_config_1pd)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        policy = CryptPolicy(self.sample_config_1pd)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        self.assertRaises(TypeError, CryptPolicy, {}, {})
        self.assertRaises(TypeError, CryptPolicy, {}, dummy=1)

        # check key with too many separators is rejected
        self.assertRaises(TypeError, CryptPolicy,
            schemes = [ "des_crypt", "md5_crypt", "bsdi_crypt", "sha512_crypt"],
            bad__key__bsdi_crypt__max_rounds = 30000,
            )

        # check nameless handler rejected
        class nameless(uh.StaticHandler):
            name = None
        self.assertRaises(ValueError, CryptPolicy, schemes=[nameless])

        # check scheme must be name or crypt handler
        self.assertRaises(TypeError, CryptPolicy, schemes=[uh.StaticHandler])

        # check name conflicts are rejected
        class dummy_1(uh.StaticHandler):
            name = 'dummy_1'
        self.assertRaises(KeyError, CryptPolicy, schemes=[dummy_1, dummy_1])

        # with unknown deprecated value
        self.assertRaises(KeyError, CryptPolicy,
                          schemes=['des_crypt'],
                          deprecated=['md5_crypt'])

        # with unknown default value
        self.assertRaises(KeyError, CryptPolicy,
                          schemes=['des_crypt'],
                          default='md5_crypt')

    def test_01_from_path_simple(self):
        """test CryptPolicy.from_path() constructor"""
        # NOTE: this is separate so it can also run under GAE

        # test preset stored in existing file
        path = self.sample_config_1s_path
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test if path missing
        self.assertRaises(EnvironmentError, CryptPolicy.from_path, path + 'xxx')

    def test_01_from_path(self):
        """test CryptPolicy.from_path() constructor with encodings"""
        path = self.mktemp()

        # test "\n" linesep
        set_file(path, self.sample_config_1s)
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test "\r\n" linesep
        set_file(path, self.sample_config_1s.replace("\n","\r\n"))
        policy = CryptPolicy.from_path(path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test with custom encoding
        uc2 = to_bytes(self.sample_config_1s, "utf-16", source_encoding="utf-8")
        set_file(path, uc2)
        policy = CryptPolicy.from_path(path, encoding="utf-16")
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

    def test_02_from_string(self):
        """test CryptPolicy.from_string() constructor"""
        # test "\n" linesep
        policy = CryptPolicy.from_string(self.sample_config_1s)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test "\r\n" linesep
        policy = CryptPolicy.from_string(
            self.sample_config_1s.replace("\n","\r\n"))
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test with unicode
        data = to_unicode(self.sample_config_1s)
        policy = CryptPolicy.from_string(data)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test with non-ascii-compatible encoding
        uc2 = to_bytes(self.sample_config_1s, "utf-16", source_encoding="utf-8")
        policy = CryptPolicy.from_string(uc2, encoding="utf-16")
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # test category specific options
        policy = CryptPolicy.from_string(self.sample_config_4s)
        self.assertEqual(policy.to_dict(), self.sample_config_4pd)

    def test_03_from_source(self):
        """test CryptPolicy.from_source() constructor"""
        # pass it a path
        policy = CryptPolicy.from_source(self.sample_config_1s_path)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # pass it a string
        policy = CryptPolicy.from_source(self.sample_config_1s)
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # pass it a dict (NOTE: make a copy to detect in-place modifications)
        policy = CryptPolicy.from_source(self.sample_config_1pd.copy())
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # pass it existing policy
        p2 = CryptPolicy.from_source(policy)
        self.assertIs(policy, p2)

        # pass it something wrong
        self.assertRaises(TypeError, CryptPolicy.from_source, 1)
        self.assertRaises(TypeError, CryptPolicy.from_source, [])

    def test_04_from_sources(self):
        """test CryptPolicy.from_sources() constructor"""

        # pass it empty list
        self.assertRaises(ValueError, CryptPolicy.from_sources, [])

        # pass it one-element list
        policy = CryptPolicy.from_sources([self.sample_config_1s])
        self.assertEqual(policy.to_dict(), self.sample_config_1pd)

        # pass multiple sources
        policy = CryptPolicy.from_sources(
            [
            self.sample_config_1s_path,
            self.sample_config_2s,
            self.sample_config_3pd,
            ])
        self.assertEqual(policy.to_dict(), self.sample_config_123pd)

    def test_05_replace(self):
        """test CryptPolicy.replace() constructor"""

        p1 = CryptPolicy(**self.sample_config_1pd)

        # check overlaying sample 2
        p2 = p1.replace(**self.sample_config_2pd)
        self.assertEqual(p2.to_dict(), self.sample_config_12pd)

        # check repeating overlay makes no change
        p2b = p2.replace(**self.sample_config_2pd)
        self.assertEqual(p2b.to_dict(), self.sample_config_12pd)

        # check overlaying sample 3
        p3 = p2.replace(self.sample_config_3pd)
        self.assertEqual(p3.to_dict(), self.sample_config_123pd)

    def test_06_forbidden(self):
        """test CryptPolicy() forbidden kwds"""

        # salt not allowed to be set
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            des_crypt__salt="xx",
        )
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            all__salt="xx",
        )

        # schemes not allowed for category
        self.assertRaises(KeyError, CryptPolicy,
            schemes=["des_crypt"],
            user__context__schemes=["md5_crypt"],
        )

    #===================================================================
    # reading
    #===================================================================
    def test_10_has_schemes(self):
        """test has_schemes() method"""

        p1 = CryptPolicy(**self.sample_config_1pd)
        self.assertTrue(p1.has_schemes())

        p3 = CryptPolicy(**self.sample_config_3pd)
        self.assertTrue(not p3.has_schemes())

    def test_11_iter_handlers(self):
        """test iter_handlers() method"""

        p1 = CryptPolicy(**self.sample_config_1pd)
        s = self.sample_config_1prd['schemes']
        self.assertEqual(list(p1.iter_handlers()), s)

        p3 = CryptPolicy(**self.sample_config_3pd)
        self.assertEqual(list(p3.iter_handlers()), [])

    def test_12_get_handler(self):
        """test get_handler() method"""

        p1 = CryptPolicy(**self.sample_config_1pd)

        # check by name
        self.assertIs(p1.get_handler("bsdi_crypt"), hash.bsdi_crypt)

        # check by missing name
        self.assertIs(p1.get_handler("sha256_crypt"), None)
        self.assertRaises(KeyError, p1.get_handler, "sha256_crypt", required=True)

        # check default
        self.assertIs(p1.get_handler(), hash.md5_crypt)

    def test_13_get_options(self):
        """test get_options() method"""

        p12 = CryptPolicy(**self.sample_config_12pd)

        self.assertEqual(p12.get_options("bsdi_crypt"),dict(
            # NOTE: not maintaining backwards compat for rendering to "10%"
            vary_rounds = 0.1,
            min_rounds = 29000,
            max_rounds = 35000,
            default_rounds = 31000,
        ))

        self.assertEqual(p12.get_options("sha512_crypt"),dict(
            # NOTE: not maintaining backwards compat for rendering to "10%"
            vary_rounds = 0.1,
            min_rounds = 45000,
            max_rounds = 50000,
        ))

        p4 = CryptPolicy.from_string(self.sample_config_4s)
        self.assertEqual(p4.get_options("sha512_crypt"), dict(
            # NOTE: not maintaining backwards compat for rendering to "10%"
            vary_rounds=0.1,
            max_rounds=20000,
        ))

        self.assertEqual(p4.get_options("sha512_crypt", "user"), dict(
            # NOTE: not maintaining backwards compat for rendering to "10%"
            vary_rounds=0.1,
            max_rounds=20000,
        ))

        self.assertEqual(p4.get_options("sha512_crypt", "admin"), dict(
            # NOTE: not maintaining backwards compat for rendering to "5%"
            vary_rounds=0.05,
            max_rounds=40000,
        ))

    def test_14_handler_is_deprecated(self):
        """test handler_is_deprecated() method"""
        pa = CryptPolicy(**self.sample_config_1pd)
        pb = CryptPolicy(**self.sample_config_5pd)

        self.assertFalse(pa.handler_is_deprecated("des_crypt"))
        self.assertFalse(pa.handler_is_deprecated(hash.bsdi_crypt))
        self.assertFalse(pa.handler_is_deprecated("sha512_crypt"))

        self.assertTrue(pb.handler_is_deprecated("des_crypt"))
        self.assertFalse(pb.handler_is_deprecated(hash.bsdi_crypt))
        self.assertFalse(pb.handler_is_deprecated("sha512_crypt"))

        # check categories as well
        self.assertTrue(pb.handler_is_deprecated("des_crypt", "user"))
        self.assertFalse(pb.handler_is_deprecated("bsdi_crypt", "user"))
        self.assertTrue(pb.handler_is_deprecated("des_crypt", "admin"))
        self.assertTrue(pb.handler_is_deprecated("bsdi_crypt", "admin"))

        # check deprecation is overridden per category
        pc = CryptPolicy(
            schemes=["md5_crypt", "des_crypt"],
            deprecated=["md5_crypt"],
            user__context__deprecated=["des_crypt"],
        )
        self.assertTrue(pc.handler_is_deprecated("md5_crypt"))
        self.assertFalse(pc.handler_is_deprecated("des_crypt"))
        self.assertFalse(pc.handler_is_deprecated("md5_crypt", "user"))
        self.assertTrue(pc.handler_is_deprecated("des_crypt", "user"))

    def test_15_min_verify_time(self):
        """test get_min_verify_time() method"""
        # silence deprecation warnings for min verify time
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        pa = CryptPolicy()
        self.assertEqual(pa.get_min_verify_time(), 0)
        self.assertEqual(pa.get_min_verify_time('admin'), 0)

        pb = pa.replace(min_verify_time=.1)
        self.assertEqual(pb.get_min_verify_time(), 0)
        self.assertEqual(pb.get_min_verify_time('admin'), 0)

    #===================================================================
    # serialization
    #===================================================================
    def test_20_iter_config(self):
        """test iter_config() method"""
        p5 = CryptPolicy(**self.sample_config_5pd)
        self.assertEqual(dict(p5.iter_config()), self.sample_config_5pd)
        self.assertEqual(dict(p5.iter_config(resolve=True)), self.sample_config_5prd)
        self.assertEqual(dict(p5.iter_config(ini=True)), self.sample_config_5pid)

    def test_21_to_dict(self):
        """test to_dict() method"""
        p5 = CryptPolicy(**self.sample_config_5pd)
        self.assertEqual(p5.to_dict(), self.sample_config_5pd)
        self.assertEqual(p5.to_dict(resolve=True), self.sample_config_5prd)

    def test_22_to_string(self):
        """test to_string() method"""
        pa = CryptPolicy(**self.sample_config_5pd)
        s = pa.to_string() # NOTE: can't compare string directly, ordering etc may not match
        pb = CryptPolicy.from_string(s)
        self.assertEqual(pb.to_dict(), self.sample_config_5pd)

        s = pa.to_string(encoding="latin-1")
        self.assertIsInstance(s, bytes)

    #===================================================================
    #
    #===================================================================

#=============================================================================
# CryptContext
#=============================================================================
class CryptContextTest(TestCase):
    """test CryptContext class"""
    descriptionPrefix = "CryptContext"

    def setUp(self):
        TestCase.setUp(self)
        warnings.filterwarnings("ignore",
                                r"CryptContext\(\)\.replace\(\) has been deprecated.*")
        warnings.filterwarnings("ignore",
                                r"The CryptContext ``policy`` keyword has been deprecated.*")
        warnings.filterwarnings("ignore", ".*(CryptPolicy|context\.policy).*(has|have) been deprecated.*")
        warnings.filterwarnings("ignore",
                                r"the method.*hash_needs_update.*is deprecated")

    #===================================================================
    # constructor
    #===================================================================
    def test_00_constructor(self):
        """test constructor"""
        # create crypt context using handlers
        cc = CryptContext([hash.md5_crypt, hash.bsdi_crypt, hash.des_crypt])
        c,b,a = cc.policy.iter_handlers()
        self.assertIs(a, hash.des_crypt)
        self.assertIs(b, hash.bsdi_crypt)
        self.assertIs(c, hash.md5_crypt)

        # create context using names
        cc = CryptContext(["md5_crypt", "bsdi_crypt", "des_crypt"])
        c,b,a = cc.policy.iter_handlers()
        self.assertIs(a, hash.des_crypt)
        self.assertIs(b, hash.bsdi_crypt)
        self.assertIs(c, hash.md5_crypt)

        # policy kwd
        policy = cc.policy
        cc = CryptContext(policy=policy)
        self.assertEqual(cc.to_dict(), policy.to_dict())

        cc = CryptContext(policy=policy, default="bsdi_crypt")
        self.assertNotEqual(cc.to_dict(), policy.to_dict())
        self.assertEqual(cc.to_dict(), dict(schemes=["md5_crypt","bsdi_crypt","des_crypt"],
                                            default="bsdi_crypt"))

        self.assertRaises(TypeError, setattr, cc, 'policy', None)
        self.assertRaises(TypeError, CryptContext, policy='x')

    def test_01_replace(self):
        """test replace()"""

        cc = CryptContext(["md5_crypt", "bsdi_crypt", "des_crypt"])
        self.assertIs(cc.policy.get_handler(), hash.md5_crypt)

        cc2 = cc.replace()
        self.assertIsNot(cc2, cc)
        # NOTE: was not able to maintain backward compatibility with this...
        ##self.assertIs(cc2.policy, cc.policy)

        cc3 = cc.replace(default="bsdi_crypt")
        self.assertIsNot(cc3, cc)
        # NOTE: was not able to maintain backward compatibility with this...
        ##self.assertIs(cc3.policy, cc.policy)
        self.assertIs(cc3.policy.get_handler(), hash.bsdi_crypt)

    def test_02_no_handlers(self):
        """test no handlers"""

        # check constructor...
        cc = CryptContext()
        self.assertRaises(KeyError, cc.identify, 'hash', required=True)
        self.assertRaises(KeyError, cc.hash, 'secret')
        self.assertRaises(KeyError, cc.verify, 'secret', 'hash')

        # check updating policy after the fact...
        cc = CryptContext(['md5_crypt'])
        p = CryptPolicy(schemes=[])
        cc.policy = p

        self.assertRaises(KeyError, cc.identify, 'hash', required=True)
        self.assertRaises(KeyError, cc.hash, 'secret')
        self.assertRaises(KeyError, cc.verify, 'secret', 'hash')

    #===================================================================
    # policy adaptation
    #===================================================================
    sample_policy_1 = dict(
            schemes = [ "des_crypt", "md5_crypt", "phpass", "bsdi_crypt",
                       "sha256_crypt"],
            deprecated = [ "des_crypt", ],
            default = "sha256_crypt",
            bsdi_crypt__max_rounds = 30,
            bsdi_crypt__default_rounds = 25,
            bsdi_crypt__vary_rounds = 0,
            sha256_crypt__max_rounds = 3000,
            sha256_crypt__min_rounds = 2000,
            sha256_crypt__default_rounds = 3000,
            phpass__ident = "H",
            phpass__default_rounds = 7,
    )

    def test_12_hash_needs_update(self):
        """test hash_needs_update() method"""
        cc = CryptContext(**self.sample_policy_1)

        # check deprecated scheme
        self.assertTrue(cc.hash_needs_update('9XXD4trGYeGJA'))
        self.assertFalse(cc.hash_needs_update('$1$J8HC2RCr$HcmM.7NxB2weSvlw2FgzU0'))

        # check min rounds
        self.assertTrue(cc.hash_needs_update('$5$rounds=1999$jD81UCoo.zI.UETs$Y7qSTQ6mTiU9qZB4fRr43wRgQq4V.5AAf7F97Pzxey/'))
        self.assertFalse(cc.hash_needs_update('$5$rounds=2000$228SSRje04cnNCaQ$YGV4RYu.5sNiBvorQDlO0WWQjyJVGKBcJXz3OtyQ2u8'))

        # check max rounds
        self.assertFalse(cc.hash_needs_update('$5$rounds=3000$fS9iazEwTKi7QPW4$VasgBC8FqlOvD7x2HhABaMXCTh9jwHclPA9j5YQdns.'))
        self.assertTrue(cc.hash_needs_update('$5$rounds=3001$QlFHHifXvpFX4PLs$/0ekt7lSs/lOikSerQ0M/1porEHxYq7W/2hdFpxA3fA'))

    #===================================================================
    # border cases
    #===================================================================
    def test_30_nonstring_hash(self):
        """test non-string hash values cause error"""
        warnings.filterwarnings("ignore", ".*needs_update.*'scheme' keyword is deprecated.*")

        #
        # test hash=None or some other non-string causes TypeError
        # and that explicit-scheme code path behaves the same.
        #
        cc = CryptContext(["des_crypt"])
        for hash, kwds in [
                (None, {}),
                # NOTE: 'scheme' kwd is deprecated...
                (None, {"scheme": "des_crypt"}),
                (1, {}),
                ((), {}),
                ]:

            self.assertRaises(TypeError, cc.hash_needs_update, hash, **kwds)

        cc2 = CryptContext(["mysql323"])
        self.assertRaises(TypeError, cc2.hash_needs_update, None)

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# LazyCryptContext
#=============================================================================
class dummy_2(uh.StaticHandler):
    name = "dummy_2"

class LazyCryptContextTest(TestCase):
    descriptionPrefix = "LazyCryptContext"

    def setUp(self):
        TestCase.setUp(self)

        # make sure this isn't registered before OR after
        unload_handler_name("dummy_2")
        self.addCleanup(unload_handler_name, "dummy_2")

        # silence some warnings
        warnings.filterwarnings("ignore",
                                r"CryptContext\(\)\.replace\(\) has been deprecated")
        warnings.filterwarnings("ignore", ".*(CryptPolicy|context\.policy).*(has|have) been deprecated.*")

    def test_kwd_constructor(self):
        """test plain kwds"""
        self.assertFalse(has_crypt_handler("dummy_2"))
        register_crypt_handler_path("dummy_2", "passlib.tests.test_context")

        cc = LazyCryptContext(iter(["dummy_2", "des_crypt"]), deprecated=["des_crypt"])

        self.assertFalse(has_crypt_handler("dummy_2", True))

        self.assertTrue(cc.policy.handler_is_deprecated("des_crypt"))
        self.assertEqual(cc.policy.schemes(), ["dummy_2", "des_crypt"])

        self.assertTrue(has_crypt_handler("dummy_2", True))

    def test_callable_constructor(self):
        """test create_policy() hook, returning CryptPolicy"""
        self.assertFalse(has_crypt_handler("dummy_2"))
        register_crypt_handler_path("dummy_2", "passlib.tests.test_context")

        def create_policy(flag=False):
            self.assertTrue(flag)
            return CryptPolicy(schemes=iter(["dummy_2", "des_crypt"]), deprecated=["des_crypt"])

        cc = LazyCryptContext(create_policy=create_policy, flag=True)

        self.assertFalse(has_crypt_handler("dummy_2", True))

        self.assertTrue(cc.policy.handler_is_deprecated("des_crypt"))
        self.assertEqual(cc.policy.schemes(), ["dummy_2", "des_crypt"])

        self.assertTrue(has_crypt_handler("dummy_2", True))

#=============================================================================
# eof
#=============================================================================
