"""tests for passlib.apache -- (c) Assurance Technologies 2008-2011"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement
# core
from logging import getLogger
import os
import subprocess
# site
# pkg
from passlib import apache, registry
from lib.passlib.exc import MissingBackendError
from lib.passlib.utils.compat import irange
from lib.passlib.tests.backports import unittest
from lib.passlib.tests.utils import TestCase, get_file, set_file, ensure_mtime_changed
from lib.passlib.utils.compat import u
from lib.passlib.utils import to_bytes
from lib.passlib.utils.handlers import to_unicode_for_identify
# module
log = getLogger(__name__)

#=============================================================================
# helpers
#=============================================================================

def backdate_file_mtime(path, offset=10):
    """backdate file's mtime by specified amount"""
    # NOTE: this is used so we can test code which detects mtime changes,
    #       without having to actually *pause* for that long.
    atime = os.path.getatime(path)
    mtime = os.path.getmtime(path)-offset
    os.utime(path, (atime, mtime))

#=============================================================================
# detect external HTPASSWD tool
#=============================================================================


htpasswd_path = os.environ.get("PASSLIB_TEST_HTPASSWD_PATH") or "htpasswd"


def _call_htpasswd(args, stdin=None):
    """
    helper to run htpasswd cmd
    """
    if stdin is not None:
        stdin = stdin.encode("utf-8")
    proc = subprocess.Popen([htpasswd_path] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, stdin=subprocess.PIPE if stdin else None)
    out, err = proc.communicate(stdin)
    rc = proc.wait()
    out = to_unicode_for_identify(out or "")
    return out, rc


def _call_htpasswd_verify(path, user, password):
    """
    wrapper for htpasswd verify
    """
    out, rc = _call_htpasswd(["-vi", path, user], password)
    return not rc


def _detect_htpasswd():
    """
    helper to check if htpasswd is present
    """
    try:
        out, rc = _call_htpasswd([])
    except OSError:
        # TODO: under py3, could trap the more specific FileNotFoundError
        # cmd not found
        return False, False
    # when called w/o args, it should print usage to stderr & return rc=2
    if not rc:
        log.warning("htpasswd test returned with rc=0")
    have_bcrypt = " -B " in out
    return True, have_bcrypt


HAVE_HTPASSWD, HAVE_HTPASSWD_BCRYPT = _detect_htpasswd()

requires_htpasswd_cmd = unittest.skipUnless(HAVE_HTPASSWD, "requires `htpasswd` cmdline tool")


#=============================================================================
# htpasswd
#=============================================================================
class HtpasswdFileTest(TestCase):
    """test HtpasswdFile class"""
    descriptionPrefix = "HtpasswdFile"

    # sample with 4 users
    sample_01 = (b'user2:2CHkkwa2AtqGs\n'
                 b'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n'
                 b'user4:pass4\n'
                 b'user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n')

    # sample 1 with user 1, 2 deleted; 4 changed
    sample_02 = b'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\nuser4:pass4\n'

    # sample 1 with user2 updated, user 1 first entry removed, and user 5 added
    sample_03 = (b'user2:pass2x\n'
                 b'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n'
                 b'user4:pass4\n'
                 b'user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n'
                 b'user5:pass5\n')

    # standalone sample with 8-bit username
    sample_04_utf8 = b'user\xc3\xa6:2CHkkwa2AtqGs\n'
    sample_04_latin1 = b'user\xe6:2CHkkwa2AtqGs\n'

    sample_dup = b'user1:pass1\nuser1:pass2\n'

    # sample with bcrypt & sha256_crypt hashes
    sample_05 = (b'user2:2CHkkwa2AtqGs\n'
                 b'user3:{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=\n'
                 b'user4:pass4\n'
                 b'user1:$apr1$t4tc7jTh$GPIWVUo8sQKJlUdV8V5vu0\n'
                 b'user5:$2a$12$yktDxraxijBZ360orOyCOePFGhuis/umyPNJoL5EbsLk.s6SWdrRO\n'
                 b'user6:$5$rounds=110000$cCRp/xUUGVgwR4aP$'
                     b'p0.QKFS5qLNRqw1/47lXYiAcgIjJK.WjCO8nrEKuUK.\n')

    def test_00_constructor_autoload(self):
        """test constructor autoload"""
        # check with existing file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)
        self.assertEqual(ht.path, path)
        self.assertTrue(ht.mtime)

        # check changing path
        ht.path = path + "x"
        self.assertEqual(ht.path, path + "x")
        self.assertFalse(ht.mtime)

        # check new=True
        ht = apache.HtpasswdFile(path, new=True)
        self.assertEqual(ht.to_string(), b"")
        self.assertEqual(ht.path, path)
        self.assertFalse(ht.mtime)

        # check autoload=False (deprecated alias for new=True)
        with self.assertWarningList("``autoload=False`` is deprecated"):
            ht = apache.HtpasswdFile(path, autoload=False)
        self.assertEqual(ht.to_string(), b"")
        self.assertEqual(ht.path, path)
        self.assertFalse(ht.mtime)

        # check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtpasswdFile, path)

        # NOTE: "default_scheme" option checked via set_password() test, among others

    def test_00_from_path(self):
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile.from_path(path)
        self.assertEqual(ht.to_string(), self.sample_01)
        self.assertEqual(ht.path, None)
        self.assertFalse(ht.mtime)

    def test_01_delete(self):
        """test delete()"""
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertTrue(ht.delete("user1")) # should delete both entries
        self.assertTrue(ht.delete("user2"))
        self.assertFalse(ht.delete("user5")) # user not present
        self.assertEqual(ht.to_string(), self.sample_02)

        # invalid user
        self.assertRaises(ValueError, ht.delete, "user:")

    def test_01_delete_autosave(self):
        path = self.mktemp()
        sample = b'user1:pass1\nuser2:pass2\n'
        set_file(path, sample)

        ht = apache.HtpasswdFile(path)
        ht.delete("user1")
        self.assertEqual(get_file(path), sample)

        ht = apache.HtpasswdFile(path, autosave=True)
        ht.delete("user1")
        self.assertEqual(get_file(path), b"user2:pass2\n")

    def test_02_set_password(self):
        """test set_password()"""
        ht = apache.HtpasswdFile.from_string(
            self.sample_01, default_scheme="plaintext")
        self.assertTrue(ht.set_password("user2", "pass2x"))
        self.assertFalse(ht.set_password("user5", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        # test legacy default kwd
        with self.assertWarningList("``default`` is deprecated"):
            ht = apache.HtpasswdFile.from_string(self.sample_01, default="plaintext")
        self.assertTrue(ht.set_password("user2", "pass2x"))
        self.assertFalse(ht.set_password("user5", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        # invalid user
        self.assertRaises(ValueError, ht.set_password, "user:", "pass")

        # test that legacy update() still works
        with self.assertWarningList("update\(\) is deprecated"):
            ht.update("user2", "test")
        self.assertTrue(ht.check_password("user2", "test"))

    def test_02_set_password_autosave(self):
        path = self.mktemp()
        sample = b'user1:pass1\n'
        set_file(path, sample)

        ht = apache.HtpasswdFile(path)
        ht.set_password("user1", "pass2")
        self.assertEqual(get_file(path), sample)

        ht = apache.HtpasswdFile(path, default_scheme="plaintext", autosave=True)
        ht.set_password("user1", "pass2")
        self.assertEqual(get_file(path), b"user1:pass2\n")

    def test_02_set_password_default_scheme(self):
        """test set_password() -- default_scheme"""

        def check(scheme):
            ht = apache.HtpasswdFile(default_scheme=scheme)
            ht.set_password("user1", "pass1")
            return ht.context.identify(ht.get_hash("user1"))

        # explicit scheme
        self.assertEqual(check("sha256_crypt"), "sha256_crypt")
        self.assertEqual(check("des_crypt"), "des_crypt")

        # unknown scheme
        self.assertRaises(KeyError, check, "xxx")

        # alias resolution
        self.assertEqual(check("portable"), apache.htpasswd_defaults["portable"])
        self.assertEqual(check("portable_apache_22"), apache.htpasswd_defaults["portable_apache_22"])
        self.assertEqual(check("host_apache_22"), apache.htpasswd_defaults["host_apache_22"])

        # default
        self.assertEqual(check(None), apache.htpasswd_defaults["portable_apache_22"])

    def test_03_users(self):
        """test users()"""
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        ht.set_password("user5", "pass5")
        ht.delete("user3")
        ht.set_password("user3", "pass3")
        self.assertEqual(sorted(ht.users()), ["user1", "user2", "user3", "user4", "user5"])

    def test_04_check_password(self):
        """test check_password()"""
        ht = apache.HtpasswdFile.from_string(self.sample_05)
        self.assertRaises(TypeError, ht.check_password, 1, 'pass9')
        self.assertTrue(ht.check_password("user9","pass9") is None)

        # users 1..6 of sample_01 run through all the main hash formats,
        # to make sure they're recognized.
        for i in irange(1, 7):
            i = str(i)
            try:
                self.assertTrue(ht.check_password("user"+i, "pass"+i))
                self.assertTrue(ht.check_password("user"+i, "pass9") is False)
            except MissingBackendError:
                if i == "5":
                    # user5 uses bcrypt, which is apparently not available right now
                    continue
                raise

        self.assertRaises(ValueError, ht.check_password, "user:", "pass")

        # test that legacy verify() still works
        with self.assertWarningList(["verify\(\) is deprecated"]*2):
            self.assertTrue(ht.verify("user1", "pass1"))
            self.assertFalse(ht.verify("user1", "pass2"))

    def test_05_load(self):
        """test load()"""
        # setup empty file
        path = self.mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtpasswdFile(path, default_scheme="plaintext")
        self.assertEqual(ha.to_string(), b"")

        # make changes, check load_if_changed() does nothing
        ha.set_password("user1", "pass1")
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), b"user1:pass1\n")

        # change file
        set_file(path, self.sample_01)
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), self.sample_01)

        # make changes, check load() overwrites them
        ha.set_password("user5", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        # test load w/ no path
        hb = apache.HtpasswdFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load_if_changed)

        # test load w/ dups and explicit path
        set_file(path, self.sample_dup)
        hc = apache.HtpasswdFile()
        hc.load(path)
        self.assertTrue(hc.check_password('user1','pass1'))

    # NOTE: load_string() tested via from_string(), which is used all over this file

    def test_06_save(self):
        """test save()"""
        # load from file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtpasswdFile(path)

        # make changes, check they saved
        ht.delete("user1")
        ht.delete("user2")
        ht.save()
        self.assertEqual(get_file(path), self.sample_02)

        # test save w/ no path
        hb = apache.HtpasswdFile(default_scheme="plaintext")
        hb.set_password("user1", "pass1")
        self.assertRaises(RuntimeError, hb.save)

        # test save w/ explicit path
        hb.save(path)
        self.assertEqual(get_file(path), b"user1:pass1\n")

    def test_07_encodings(self):
        """test 'encoding' kwd"""
        # test bad encodings cause failure in constructor
        self.assertRaises(ValueError, apache.HtpasswdFile, encoding="utf-16")

        # check sample utf-8
        ht = apache.HtpasswdFile.from_string(self.sample_04_utf8, encoding="utf-8",
                                             return_unicode=True)
        self.assertEqual(ht.users(), [ u("user\u00e6") ])

        # test deprecated encoding=None
        with self.assertWarningList("``encoding=None`` is deprecated"):
            ht = apache.HtpasswdFile.from_string(self.sample_04_utf8, encoding=None)
        self.assertEqual(ht.users(), [ b'user\xc3\xa6' ])

        # check sample latin-1
        ht = apache.HtpasswdFile.from_string(self.sample_04_latin1,
                                              encoding="latin-1", return_unicode=True)
        self.assertEqual(ht.users(), [ u("user\u00e6") ])

    def test_08_get_hash(self):
        """test get_hash()"""
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertEqual(ht.get_hash("user3"), b"{SHA}3ipNV1GrBtxPmHFC21fCbVCSXIo=")
        self.assertEqual(ht.get_hash("user4"), b"pass4")
        self.assertEqual(ht.get_hash("user5"), None)

        with self.assertWarningList("find\(\) is deprecated"):
            self.assertEqual(ht.find("user4"), b"pass4")

    def test_09_to_string(self):
        """test to_string"""

        # check with known sample
        ht = apache.HtpasswdFile.from_string(self.sample_01)
        self.assertEqual(ht.to_string(), self.sample_01)

        # test blank
        ht = apache.HtpasswdFile()
        self.assertEqual(ht.to_string(), b"")

    def test_10_repr(self):
        ht = apache.HtpasswdFile("fakepath", autosave=True, new=True, encoding="latin-1")
        repr(ht)

    def test_11_malformed(self):
        self.assertRaises(ValueError, apache.HtpasswdFile.from_string,
            b'realm:user1:pass1\n')
        self.assertRaises(ValueError, apache.HtpasswdFile.from_string,
            b'pass1\n')

    def test_12_from_string(self):
        # forbid path kwd
        self.assertRaises(TypeError, apache.HtpasswdFile.from_string,
                          b'', path=None)

    def test_13_whitespace(self):
        """whitespace & comment handling"""

        # per htpasswd source (https://github.com/apache/httpd/blob/trunk/support/htpasswd.c),
        # lines that match "^\s*(#.*)?$" should be ignored
        source = to_bytes(
            '\n'
            'user2:pass2\n'
            'user4:pass4\n'
            'user7:pass7\r\n'
            ' \t \n'
            'user1:pass1\n'
            ' # legacy users\n'
            '#user6:pass6\n'
            'user5:pass5\n\n'
        )

        # loading should see all users (except user6, who was commented out)
        ht = apache.HtpasswdFile.from_string(source)
        self.assertEqual(sorted(ht.users()), ["user1", "user2", "user4", "user5", "user7"])

        # update existing user
        ht.set_hash("user4", "althash4")
        self.assertEqual(sorted(ht.users()), ["user1", "user2", "user4", "user5", "user7"])

        # add a new user
        ht.set_hash("user6", "althash6")
        self.assertEqual(sorted(ht.users()), ["user1", "user2", "user4", "user5", "user6", "user7"])

        # delete existing user
        ht.delete("user7")
        self.assertEqual(sorted(ht.users()), ["user1", "user2", "user4", "user5", "user6"])

        # re-serialization should preserve whitespace
        target = to_bytes(
            '\n'
            'user2:pass2\n'
            'user4:althash4\n'
            ' \t \n'
            'user1:pass1\n'
            ' # legacy users\n'
            '#user6:pass6\n'
            'user5:pass5\n'
            'user6:althash6\n'
        )
        self.assertEqual(ht.to_string(), target)

    @requires_htpasswd_cmd
    def test_htpasswd_cmd_verify(self):
        """
        verify "htpasswd" command can read output
        """
        path = self.mktemp()
        ht = apache.HtpasswdFile(path=path, new=True)

        def hash_scheme(pwd, scheme):
            return ht.context.handler(scheme).hash(pwd)

        # base scheme
        ht.set_hash("user1", hash_scheme("password","apr_md5_crypt"))

        # 2.2-compat scheme
        host_no_bcrypt = apache.htpasswd_defaults["host_apache_22"]
        ht.set_hash("user2", hash_scheme("password", host_no_bcrypt))

        # 2.4-compat scheme
        host_best = apache.htpasswd_defaults["host"]
        ht.set_hash("user3", hash_scheme("password", host_best))

        # unsupported scheme -- should always fail to verify
        ht.set_hash("user4", "$xxx$foo$bar$baz")

        # make sure htpasswd properly recognizes hashes
        ht.save()

        self.assertFalse(_call_htpasswd_verify(path, "user1", "wrong"))
        self.assertFalse(_call_htpasswd_verify(path, "user2", "wrong"))
        self.assertFalse(_call_htpasswd_verify(path, "user3", "wrong"))
        self.assertFalse(_call_htpasswd_verify(path, "user4", "wrong"))

        self.assertTrue(_call_htpasswd_verify(path, "user1", "password"))
        self.assertTrue(_call_htpasswd_verify(path, "user2", "password"))
        self.assertTrue(_call_htpasswd_verify(path, "user3", "password"))

    @requires_htpasswd_cmd
    @unittest.skipUnless(registry.has_backend("bcrypt"), "bcrypt support required")
    def test_htpasswd_cmd_verify_bcrypt(self):
        """
        verify "htpasswd" command can read bcrypt format

        this tests for regression of issue 95, where we output "$2b$" instead of "$2y$";
        fixed in v1.7.2.
        """
        path = self.mktemp()
        ht = apache.HtpasswdFile(path=path, new=True)
        def hash_scheme(pwd, scheme):
            return ht.context.handler(scheme).hash(pwd)
        ht.set_hash("user1", hash_scheme("password", "bcrypt"))
        ht.save()
        self.assertFalse(_call_htpasswd_verify(path, "user1", "wrong"))
        if HAVE_HTPASSWD_BCRYPT:
            self.assertTrue(_call_htpasswd_verify(path, "user1", "password"))
        else:
            # apache2.2 should fail, acting like it's an unknown hash format
            self.assertFalse(_call_htpasswd_verify(path, "user1", "password"))

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# htdigest
#=============================================================================
class HtdigestFileTest(TestCase):
    """test HtdigestFile class"""
    descriptionPrefix = "HtdigestFile"

    # sample with 4 users
    sample_01 = (b'user2:realm:549d2a5f4659ab39a80dac99e159ab19\n'
                 b'user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                 b'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n'
                 b'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n')

    # sample 1 with user 1, 2 deleted; 4 changed
    sample_02 = (b'user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                 b'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n')

    # sample 1 with user2 updated, user 1 first entry removed, and user 5 added
    sample_03 = (b'user2:realm:5ba6d8328943c23c64b50f8b29566059\n'
                 b'user3:realm:a500bb8c02f6a9170ae46af10c898744\n'
                 b'user4:realm:ab7b5d5f28ccc7666315f508c7358519\n'
                 b'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n'
                 b'user5:realm:03c55fdc6bf71552356ad401bdb9af19\n')

    # standalone sample with 8-bit username & realm
    sample_04_utf8 = b'user\xc3\xa6:realm\xc3\xa6:549d2a5f4659ab39a80dac99e159ab19\n'
    sample_04_latin1 = b'user\xe6:realm\xe6:549d2a5f4659ab39a80dac99e159ab19\n'

    def test_00_constructor_autoload(self):
        """test constructor autoload"""
        # check with existing file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)
        self.assertEqual(ht.to_string(), self.sample_01)

        # check without autoload
        ht = apache.HtdigestFile(path, new=True)
        self.assertEqual(ht.to_string(), b"")

        # check missing file
        os.remove(path)
        self.assertRaises(IOError, apache.HtdigestFile, path)

        # NOTE: default_realm option checked via other tests.

    def test_01_delete(self):
        """test delete()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertTrue(ht.delete("user1", "realm"))
        self.assertTrue(ht.delete("user2", "realm"))
        self.assertFalse(ht.delete("user5", "realm"))
        self.assertFalse(ht.delete("user3", "realm5"))
        self.assertEqual(ht.to_string(), self.sample_02)

        # invalid user
        self.assertRaises(ValueError, ht.delete, "user:", "realm")

        # invalid realm
        self.assertRaises(ValueError, ht.delete, "user", "realm:")

    def test_01_delete_autosave(self):
        path = self.mktemp()
        set_file(path, self.sample_01)

        ht = apache.HtdigestFile(path)
        self.assertTrue(ht.delete("user1", "realm"))
        self.assertFalse(ht.delete("user3", "realm5"))
        self.assertFalse(ht.delete("user5", "realm"))
        self.assertEqual(get_file(path), self.sample_01)

        ht.autosave = True
        self.assertTrue(ht.delete("user2", "realm"))
        self.assertEqual(get_file(path), self.sample_02)

    def test_02_set_password(self):
        """test update()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertTrue(ht.set_password("user2", "realm", "pass2x"))
        self.assertFalse(ht.set_password("user5", "realm", "pass5"))
        self.assertEqual(ht.to_string(), self.sample_03)

        # default realm
        self.assertRaises(TypeError, ht.set_password, "user2", "pass3")
        ht.default_realm = "realm2"
        ht.set_password("user2", "pass3")
        ht.check_password("user2", "realm2", "pass3")

        # invalid user
        self.assertRaises(ValueError, ht.set_password, "user:", "realm", "pass")
        self.assertRaises(ValueError, ht.set_password, "u"*256, "realm", "pass")

        # invalid realm
        self.assertRaises(ValueError, ht.set_password, "user", "realm:", "pass")
        self.assertRaises(ValueError, ht.set_password, "user", "r"*256, "pass")

        # test that legacy update() still works
        with self.assertWarningList("update\(\) is deprecated"):
            ht.update("user2", "realm2", "test")
        self.assertTrue(ht.check_password("user2", "test"))

    # TODO: test set_password autosave

    def test_03_users(self):
        """test users()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        ht.set_password("user5", "realm", "pass5")
        ht.delete("user3", "realm")
        ht.set_password("user3", "realm", "pass3")
        self.assertEqual(sorted(ht.users("realm")), ["user1", "user2", "user3", "user4", "user5"])

        self.assertRaises(TypeError, ht.users, 1)

    def test_04_check_password(self):
        """test check_password()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertRaises(TypeError, ht.check_password, 1, 'realm', 'pass5')
        self.assertRaises(TypeError, ht.check_password, 'user', 1, 'pass5')
        self.assertIs(ht.check_password("user5", "realm","pass5"), None)
        for i in irange(1,5):
            i = str(i)
            self.assertTrue(ht.check_password("user"+i, "realm", "pass"+i))
            self.assertIs(ht.check_password("user"+i, "realm", "pass5"), False)

        # default realm
        self.assertRaises(TypeError, ht.check_password, "user5", "pass5")
        ht.default_realm = "realm"
        self.assertTrue(ht.check_password("user1", "pass1"))
        self.assertIs(ht.check_password("user5", "pass5"), None)

        # test that legacy verify() still works
        with self.assertWarningList(["verify\(\) is deprecated"]*2):
            self.assertTrue(ht.verify("user1", "realm", "pass1"))
            self.assertFalse(ht.verify("user1", "realm", "pass2"))

        # invalid user
        self.assertRaises(ValueError, ht.check_password, "user:", "realm", "pass")

    def test_05_load(self):
        """test load()"""
        # setup empty file
        path = self.mktemp()
        set_file(path, "")
        backdate_file_mtime(path, 5)
        ha = apache.HtdigestFile(path)
        self.assertEqual(ha.to_string(), b"")

        # make changes, check load_if_changed() does nothing
        ha.set_password("user1", "realm", "pass1")
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), b'user1:realm:2a6cf53e7d8f8cf39d946dc880b14128\n')

        # change file
        set_file(path, self.sample_01)
        ha.load_if_changed()
        self.assertEqual(ha.to_string(), self.sample_01)

        # make changes, check load_if_changed overwrites them
        ha.set_password("user5", "realm", "pass5")
        ha.load()
        self.assertEqual(ha.to_string(), self.sample_01)

        # test load w/ no path
        hb = apache.HtdigestFile()
        self.assertRaises(RuntimeError, hb.load)
        self.assertRaises(RuntimeError, hb.load_if_changed)

        # test load w/ explicit path
        hc = apache.HtdigestFile()
        hc.load(path)
        self.assertEqual(hc.to_string(), self.sample_01)

        # change file, test deprecated force=False kwd
        ensure_mtime_changed(path)
        set_file(path, "")
        with self.assertWarningList(r"load\(force=False\) is deprecated"):
            ha.load(force=False)
        self.assertEqual(ha.to_string(), b"")

    def test_06_save(self):
        """test save()"""
        # load from file
        path = self.mktemp()
        set_file(path, self.sample_01)
        ht = apache.HtdigestFile(path)

        # make changes, check they saved
        ht.delete("user1", "realm")
        ht.delete("user2", "realm")
        ht.save()
        self.assertEqual(get_file(path), self.sample_02)

        # test save w/ no path
        hb = apache.HtdigestFile()
        hb.set_password("user1", "realm", "pass1")
        self.assertRaises(RuntimeError, hb.save)

        # test save w/ explicit path
        hb.save(path)
        self.assertEqual(get_file(path), hb.to_string())

    def test_07_realms(self):
        """test realms() & delete_realm()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)

        self.assertEqual(ht.delete_realm("x"), 0)
        self.assertEqual(ht.realms(), ['realm'])

        self.assertEqual(ht.delete_realm("realm"), 4)
        self.assertEqual(ht.realms(), [])
        self.assertEqual(ht.to_string(), b"")

    def test_08_get_hash(self):
        """test get_hash()"""
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertEqual(ht.get_hash("user3", "realm"), "a500bb8c02f6a9170ae46af10c898744")
        self.assertEqual(ht.get_hash("user4", "realm"), "ab7b5d5f28ccc7666315f508c7358519")
        self.assertEqual(ht.get_hash("user5", "realm"), None)

        with self.assertWarningList("find\(\) is deprecated"):
            self.assertEqual(ht.find("user4", "realm"), "ab7b5d5f28ccc7666315f508c7358519")

    def test_09_encodings(self):
        """test encoding parameter"""
        # test bad encodings cause failure in constructor
        self.assertRaises(ValueError, apache.HtdigestFile, encoding="utf-16")

        # check sample utf-8
        ht = apache.HtdigestFile.from_string(self.sample_04_utf8, encoding="utf-8", return_unicode=True)
        self.assertEqual(ht.realms(), [ u("realm\u00e6") ])
        self.assertEqual(ht.users(u("realm\u00e6")), [ u("user\u00e6") ])

        # check sample latin-1
        ht = apache.HtdigestFile.from_string(self.sample_04_latin1, encoding="latin-1", return_unicode=True)
        self.assertEqual(ht.realms(), [ u("realm\u00e6") ])
        self.assertEqual(ht.users(u("realm\u00e6")), [ u("user\u00e6") ])

    def test_10_to_string(self):
        """test to_string()"""

        # check sample
        ht = apache.HtdigestFile.from_string(self.sample_01)
        self.assertEqual(ht.to_string(), self.sample_01)

        # check blank
        ht = apache.HtdigestFile()
        self.assertEqual(ht.to_string(), b"")

    def test_11_malformed(self):
        self.assertRaises(ValueError, apache.HtdigestFile.from_string,
            b'realm:user1:pass1:other\n')
        self.assertRaises(ValueError, apache.HtdigestFile.from_string,
            b'user1:pass1\n')

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
