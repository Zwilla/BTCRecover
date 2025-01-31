"""passlib.tests -- tests for passlib.pwd"""
#=============================================================================
# imports
#=============================================================================
# core
import itertools
import logging; log = logging.getLogger(__name__)
# site
# pkg
from lib.passlib.tests.utils import TestCase
# local
__all__ = [
    "UtilsTest",
    "GenerateTest",
    "StrengthTest",
]

#=============================================================================
#
#=============================================================================
class UtilsTest(TestCase):
    """test internal utilities"""
    descriptionPrefix = "passlib.pwd"

    def test_self_info_rate(self):
        """_self_info_rate()"""
        from lib.passlib.pwd import _self_info_rate

        self.assertEqual(_self_info_rate(""), 0)

        self.assertEqual(_self_info_rate("a" * 8), 0)

        self.assertEqual(_self_info_rate("ab"), 1)
        self.assertEqual(_self_info_rate("ab" * 8), 1)

        self.assertEqual(_self_info_rate("abcd"), 2)
        self.assertEqual(_self_info_rate("abcd" * 8), 2)
        self.assertAlmostEqual(_self_info_rate("abcdaaaa"), 1.5488, places=4)

    # def test_total_self_info(self):
    #     """_total_self_info()"""
    #     from lib.passlib.pwd import _total_self_info
    #
    #     self.assertEqual(_total_self_info(""), 0)
    #
    #     self.assertEqual(_total_self_info("a" * 8), 0)
    #
    #     self.assertEqual(_total_self_info("ab"), 2)
    #     self.assertEqual(_total_self_info("ab" * 8), 16)
    #
    #     self.assertEqual(_total_self_info("abcd"), 8)
    #     self.assertEqual(_total_self_info("abcd" * 8), 64)
    #     self.assertAlmostEqual(_total_self_info("abcdaaaa"), 12.3904, places=4)

#=============================================================================
# word generation
#=============================================================================

# import subject
from lib.passlib.pwd import genword, default_charsets
ascii_62 = default_charsets['ascii_62']
hex = default_charsets['hex']

class WordGeneratorTest(TestCase):
    """test generation routines"""
    descriptionPrefix = "passlib.pwd.genword()"

    def setUp(self):
        super(WordGeneratorTest, self).setUp()

        # patch some RNG references so they're reproducible.
        from lib.passlib.pwd import SequenceGenerator
        self.patchAttr(SequenceGenerator, "rng",
                       self.getRandom("pwd generator"))

    def assertResultContents(self, results, count, chars, unique=True):
        """check result list matches expected count & charset"""
        self.assertEqual(len(results), count)
        if unique:
            if unique is True:
                unique = count
            self.assertEqual(len(set(results)), unique)
        self.assertEqual(set("".join(results)), set(chars))

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genword()
        self.assertEqual(len(result), 9)

        # malformed keyword should have useful error.
        self.assertRaisesRegex(TypeError, "(?i)unexpected keyword.*badkwd", genword, badkwd=True)

    def test_returns(self):
        """'returns' keyword"""
        # returns=int option
        results = genword(returns=5000)
        self.assertResultContents(results, 5000, ascii_62)

        # returns=iter option
        gen = genword(returns=iter)
        results = [next(gen) for _ in range(5000)]
        self.assertResultContents(results, 5000, ascii_62)

        # invalid returns option
        self.assertRaises(TypeError, genword, returns='invalid-type')

    def test_charset(self):
        """'charset' & 'chars' options"""
        # charset option
        results = genword(charset="hex", returns=5000)
        self.assertResultContents(results, 5000, hex)

        # chars option
        # there are 3**3=27 possible combinations
        results = genword(length=3, chars="abc", returns=5000)
        self.assertResultContents(results, 5000, "abc", unique=27)

        # chars + charset
        self.assertRaises(TypeError, genword, chars='abc', charset='hex')

    # TODO: test rng option

#=============================================================================
# phrase generation
#=============================================================================

# import subject
from lib.passlib.pwd import genphrase
simple_words = ["alpha", "beta", "gamma"]

class PhraseGeneratorTest(TestCase):
    """test generation routines"""
    descriptionPrefix = "passlib.pwd.genphrase()"

    def assertResultContents(self, results, count, words, unique=True, sep=" "):
        """check result list matches expected count & charset"""
        self.assertEqual(len(results), count)
        if unique:
            if unique is True:
                unique = count
            self.assertEqual(len(set(results)), unique)
        out = set(itertools.chain.from_iterable(elem.split(sep) for elem in results))
        self.assertEqual(out, set(words))

    def test_general(self):
        """general behavior"""

        # basic usage
        result = genphrase()
        self.assertEqual(len(result.split(" ")), 4)  # 48 / log(7776, 2) ~= 3.7 -> 4

        # malformed keyword should have useful error.
        self.assertRaisesRegex(TypeError, "(?i)unexpected keyword.*badkwd", genphrase, badkwd=True)

    def test_entropy(self):
        """'length' & 'entropy' keywords"""

        # custom entropy
        result = genphrase(entropy=70)
        self.assertEqual(len(result.split(" ")), 6)  # 70 / log(7776, 2) ~= 5.4 -> 6

        # custom length
        result = genphrase(length=3)
        self.assertEqual(len(result.split(" ")), 3)

        # custom length < entropy
        result = genphrase(length=3, entropy=48)
        self.assertEqual(len(result.split(" ")), 4)

        # custom length > entropy
        result = genphrase(length=4, entropy=12)
        self.assertEqual(len(result.split(" ")), 4)

    def test_returns(self):
        """'returns' keyword"""
        # returns=int option
        results = genphrase(returns=1000, words=simple_words)
        self.assertResultContents(results, 1000, simple_words)

        # returns=iter option
        gen = genphrase(returns=iter, words=simple_words)
        results = [next(gen) for _ in range(1000)]
        self.assertResultContents(results, 1000, simple_words)

        # invalid returns option
        self.assertRaises(TypeError, genphrase, returns='invalid-type')

    def test_wordset(self):
        """'wordset' & 'words' options"""
        # wordset option
        results = genphrase(words=simple_words, returns=5000)
        self.assertResultContents(results, 5000, simple_words)

        # words option
        results = genphrase(length=3, words=simple_words, returns=5000)
        self.assertResultContents(results, 5000, simple_words, unique=3**3)

        # words + wordset
        self.assertRaises(TypeError, genphrase, words=simple_words, wordset='bip39')

#=============================================================================
# eof
#=============================================================================
