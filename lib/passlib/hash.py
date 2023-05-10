"""
passlib.hash - proxy object mapping hash scheme names -> handlers

==================
***** NOTICE *****
==================

This module does not actually contain any hashes. This file
is a stub that replaces itself with a proxy object.

This proxy object (passlib.registry._PasslibRegistryProxy)
handles lazy-loading hashes as they are requested.

The actual implementation of the various hashes is store elsewhere,
mainly in the submodules of the ``passlib.handlers`` subpackage.
"""

#=============================================================================
# import proxy object and replace this module
#=============================================================================

# XXX: if any platform has problem w/ lazy modules, could support 'non-lazy'
#      version which just imports all schemes known to list_crypt_handlers()

from lib.passlib.registry import _proxy
import sys
sys.modules[__name__] = _proxy

#=============================================================================
# HACK: the following bit of code is unreachable, but it's presence seems to
#       help make autocomplete work for certain IDEs such as PyCharm.
#       this list is automatically regenerated using $SOURCE/admin/regen.py
#=============================================================================

#----------------------------------------------------
# begin autocomplete hack (autogenerated 2016-11-10)
#----------------------------------------------------
if False:
    from lib.passlib.handlers.argon2 import argon2
    from lib.passlib.handlers.bcrypt import bcrypt, bcrypt_sha256
    from lib.passlib.handlers.cisco import cisco_asa, cisco_pix, cisco_type7
    from lib.passlib.handlers.des_crypt import bigcrypt, bsdi_crypt, crypt16, des_crypt
    from lib.passlib.handlers.digests import hex_md4, hex_md5, hex_sha1, hex_sha256, hex_sha512, htdigest
    from lib.passlib.handlers.django import django_bcrypt, django_bcrypt_sha256, django_des_crypt, django_disabled, django_pbkdf2_sha1, django_pbkdf2_sha256, django_salted_md5, django_salted_sha1
    from lib.passlib.handlers.fshp import fshp
    from lib.passlib.handlers.ldap_digests import ldap_bcrypt, ldap_bsdi_crypt, ldap_des_crypt, ldap_md5, ldap_md5_crypt, ldap_plaintext, ldap_salted_md5, ldap_salted_sha1, ldap_salted_sha256, ldap_salted_sha512, ldap_sha1, ldap_sha1_crypt, ldap_sha256_crypt, ldap_sha512_crypt
    from lib.passlib.handlers.md5_crypt import apr_md5_crypt, md5_crypt
    from lib.passlib.handlers.misc import plaintext, unix_disabled, unix_fallback
    from lib.passlib.handlers.mssql import mssql2000, mssql2005
    from lib.passlib.handlers.mysql import mysql323, mysql41
    from lib.passlib.handlers.oracle import oracle10, oracle11
    from lib.passlib.handlers.pbkdf2 import atlassian_pbkdf2_sha1, cta_pbkdf2_sha1, dlitz_pbkdf2_sha1, grub_pbkdf2_sha512, ldap_pbkdf2_sha1, ldap_pbkdf2_sha256, ldap_pbkdf2_sha512, pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512
    from lib.passlib.handlers.phpass import phpass
    from lib.passlib.handlers.postgres import postgres_md5
    from lib.passlib.handlers.roundup import ldap_hex_md5, ldap_hex_sha1, roundup_plaintext
    from lib.passlib.handlers.scram import scram
    from lib.passlib.handlers.scrypt import scrypt
    from lib.passlib.handlers.sha1_crypt import sha1_crypt
    from lib.passlib.handlers.sha2_crypt import sha256_crypt, sha512_crypt
    from lib.passlib.handlers.sun_md5_crypt import sun_md5_crypt
    from lib.passlib.handlers.windows import bsd_nthash, lmhash, msdcc, msdcc2, nthash
#----------------------------------------------------
# end autocomplete hack
#----------------------------------------------------

#=============================================================================
# eoc
#=============================================================================
