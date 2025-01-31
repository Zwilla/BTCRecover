"""tests for passlib.hash -- (c) Assurance Technologies 2003-2009"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement
# core
from logging import getLogger
import warnings
import sys
# site
# pkg
from passlib import hash, registry, exc
from lib.passlib.registry import register_crypt_handler, register_crypt_handler_path, \
    get_crypt_handler, list_crypt_handlers, _unload_handler_name as unload_handler_name
import passlib.utils.handlers as uh
from lib.passlib.tests.utils import TestCase
# module
log = getLogger(__name__)

#=============================================================================
# dummy handlers
#
# NOTE: these are defined outside of test case
#       since they're used by test_register_crypt_handler_path(),
#       which needs them to be available as module globals.
#=============================================================================
class dummy_0(uh.StaticHandler):
    name = "dummy_0"

class alt_dummy_0(uh.StaticHandler):
    name = "dummy_0"

dummy_x = 1

#=============================================================================
# test registry
#=============================================================================
class RegistryTest(TestCase):

    descriptionPrefix = "passlib.registry"

    def setUp(self):
        super(RegistryTest, self).setUp()

        # backup registry state & restore it after test.
        locations = dict(registry._locations)
        handlers = dict(registry._handlers)
        def restore():
            registry._locations.clear()
            registry._locations.update(locations)
            registry._handlers.clear()
            registry._handlers.update(handlers)
        self.addCleanup(restore)

    def test_hash_proxy(self):
        """test passlib.hash proxy object"""
        # check dir works
        dir(hash)

        # check repr works
        repr(hash)

        # check non-existent attrs raise error
        self.assertRaises(AttributeError, getattr, hash, 'fooey')

        # GAE tries to set __loader__,
        # make sure that doesn't call register_crypt_handler.
        old = getattr(hash, "__loader__", None)
        test = object()
        hash.__loader__ = test
        self.assertIs(hash.__loader__, test)
        if old is None:
            del hash.__loader__
            self.assertFalse(hasattr(hash, "__loader__"))
        else:
            hash.__loader__ = old
            self.assertIs(hash.__loader__, old)

        # check storing attr calls register_crypt_handler
        class dummy_1(uh.StaticHandler):
            name = "dummy_1"
        hash.dummy_1 = dummy_1
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        # check storing under wrong name results in error
        self.assertRaises(ValueError, setattr, hash, "dummy_1x", dummy_1)

    def test_register_crypt_handler_path(self):
        """test register_crypt_handler_path()"""
        # NOTE: this messes w/ internals of registry, shouldn't be used publically.
        paths = registry._locations

        # check namespace is clear
        self.assertTrue('dummy_0' not in paths)
        self.assertFalse(hasattr(hash, 'dummy_0'))

        # check invalid names are rejected
        self.assertRaises(ValueError, register_crypt_handler_path,
                          "dummy_0", ".test_registry")
        self.assertRaises(ValueError, register_crypt_handler_path,
                          "dummy_0", __name__ + ":dummy_0:xxx")
        self.assertRaises(ValueError, register_crypt_handler_path,
                          "dummy_0", __name__ + ":dummy_0.xxx")

        # try lazy load
        register_crypt_handler_path('dummy_0', __name__)
        self.assertTrue('dummy_0' in list_crypt_handlers())
        self.assertTrue('dummy_0' not in list_crypt_handlers(loaded_only=True))
        self.assertIs(hash.dummy_0, dummy_0)
        self.assertTrue('dummy_0' in list_crypt_handlers(loaded_only=True))
        unload_handler_name('dummy_0')

        # try lazy load w/ alt
        register_crypt_handler_path('dummy_0', __name__ + ':alt_dummy_0')
        self.assertIs(hash.dummy_0, alt_dummy_0)
        unload_handler_name('dummy_0')

        # check lazy load w/ wrong type fails
        register_crypt_handler_path('dummy_x', __name__)
        self.assertRaises(TypeError, get_crypt_handler, 'dummy_x')

        # check lazy load w/ wrong name fails
        register_crypt_handler_path('alt_dummy_0', __name__)
        self.assertRaises(ValueError, get_crypt_handler, "alt_dummy_0")
        unload_handler_name("alt_dummy_0")

        # TODO: check lazy load which calls register_crypt_handler (warning should be issued)
        sys.modules.pop("passlib.tests._test_bad_register", None)
        register_crypt_handler_path("dummy_bad", "passlib.tests._test_bad_register")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", "xxxxxxxxxx", DeprecationWarning)
            h = get_crypt_handler("dummy_bad")
        from lib.passlib.tests import _test_bad_register as tbr
        self.assertIs(h, tbr.alt_dummy_bad)

    def test_register_crypt_handler(self):
        """test register_crypt_handler()"""

        self.assertRaises(TypeError, register_crypt_handler, {})

        self.assertRaises(ValueError, register_crypt_handler, type('x', (uh.StaticHandler,), dict(name=None)))
        self.assertRaises(ValueError, register_crypt_handler, type('x', (uh.StaticHandler,), dict(name="AB_CD")))
        self.assertRaises(ValueError, register_crypt_handler, type('x', (uh.StaticHandler,), dict(name="ab-cd")))
        self.assertRaises(ValueError, register_crypt_handler, type('x', (uh.StaticHandler,), dict(name="ab__cd")))
        self.assertRaises(ValueError, register_crypt_handler, type('x', (uh.StaticHandler,), dict(name="default")))

        class dummy_1(uh.StaticHandler):
            name = "dummy_1"

        class dummy_1b(uh.StaticHandler):
            name = "dummy_1"

        self.assertTrue('dummy_1' not in list_crypt_handlers())

        register_crypt_handler(dummy_1)
        register_crypt_handler(dummy_1)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        self.assertRaises(KeyError, register_crypt_handler, dummy_1b)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        register_crypt_handler(dummy_1b, force=True)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1b)

        self.assertTrue('dummy_1' in list_crypt_handlers())

    def test_get_crypt_handler(self):
        """test get_crypt_handler()"""

        class dummy_1(uh.StaticHandler):
            name = "dummy_1"

        # without available handler
        self.assertRaises(KeyError, get_crypt_handler, "dummy_1")
        self.assertIs(get_crypt_handler("dummy_1", None), None)

        # already loaded handler
        register_crypt_handler(dummy_1)
        self.assertIs(get_crypt_handler("dummy_1"), dummy_1)

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", "handler names should be lower-case, and use underscores instead of hyphens:.*", UserWarning)

            # already loaded handler, using incorrect name
            self.assertIs(get_crypt_handler("DUMMY-1"), dummy_1)

            # lazy load of unloaded handler, using incorrect name
            register_crypt_handler_path('dummy_0', __name__)
            self.assertIs(get_crypt_handler("DUMMY-0"), dummy_0)

        # check system & private names aren't returned
        from passlib import hash
        hash.__dict__["_fake"] = "dummy"
        for name in ["_fake", "__package__"]:
            self.assertRaises(KeyError, get_crypt_handler, name)
            self.assertIs(get_crypt_handler(name, None), None)

    def test_list_crypt_handlers(self):
        """test list_crypt_handlers()"""
        from lib.passlib.registry import list_crypt_handlers

        # check system & private names aren't returned
        hash.__dict__["_fake"] = "dummy"
        for name in list_crypt_handlers():
            self.assertFalse(name.startswith("_"), "%r: " % name)
        unload_handler_name("_fake")

    def test_handlers(self):
        """verify we have tests for all builtin handlers"""
        from lib.passlib.registry import list_crypt_handlers
        from lib.passlib.tests.test_handlers import get_handler_case, conditionally_available_hashes
        for name in list_crypt_handlers():
            # skip some wrappers that don't need independant testing
            if name.startswith("ldap_") and name[5:] in list_crypt_handlers():
                continue
            if name in ["roundup_plaintext"]:
                continue
            # check the remaining ones all have a handler
            try:
                self.assertTrue(get_handler_case(name))
            except exc.MissingBackendError:
                if name in conditionally_available_hashes: # expected to fail on some setups
                    continue
                raise

#=============================================================================
# eof
#=============================================================================
