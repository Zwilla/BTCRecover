"""backports of needed unittest2 features"""
#=============================================================================
# imports
#=============================================================================
from __future__ import with_statement
# core
import logging; log = logging.getLogger(__name__)
import re
import sys
##from warnings import warn
# site
# pkg
from lib.passlib.utils.compat import PY26
# local
__all__ = [
    "TestCase",
    "unittest",
    # TODO: deprecate these exports in favor of "unittest.XXX"
    "skip", "skipIf", "skipUnless",
]

#=============================================================================
# import latest unittest module available
#=============================================================================
try:
    import unittest2 as unittest
except ImportError:
    if PY26:
        raise ImportError("Passlib's tests require 'unittest2' under Python 2.6 (as of Passlib 1.7)")
    # python 2.7 and python 3.2 both have unittest2 features (at least, the ones we use)
    import unittest

#=============================================================================
# unittest aliases
#=============================================================================
skip = unittest.skip
skipIf = unittest.skipIf
skipUnless = unittest.skipUnless
SkipTest = unittest.SkipTest

#=============================================================================
# custom test harness
#=============================================================================
class TestCase(unittest.TestCase):
    """backports a number of unittest2 features in TestCase"""

    #===================================================================
    # backport some unittest2 names
    #===================================================================

    #---------------------------------------------------------------
    # backport assertRegex() alias from 3.2 to 2.7
    # was present in 2.7 under an alternate name
    #---------------------------------------------------------------
    if not hasattr(unittest.TestCase, "assertRegex"):
        assertRegex = unittest.TestCase.assertRegexpMatches

    if not hasattr(unittest.TestCase, "assertRaisesRegex"):
        assertRaisesRegex = unittest.TestCase.assertRaisesRegexp

    #===================================================================
    # eoc
    #===================================================================

#=============================================================================
# eof
#=============================================================================
