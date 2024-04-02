import ldap
from django.test import TestCase
from unittest.mock import Mock
from unittest.mock import sentinel

from baya.backend import NestedLDAPGroupsBackend
from baya.backend import ReconnectingLDAP


class TestReconnectingLDAP(TestCase):

    def test_getattr_not_initialize(self):
        ldap = Mock()
        reconnecting_ldap = ReconnectingLDAP(ldap)
        assert reconnecting_ldap.not_initialize is ldap.not_initialize

    def test_initialize(self):
        ldap = Mock()
        reconnecting_ldap = ReconnectingLDAP(ldap)
        reconnecting_ldap.initialize(sentinel.uri)
        ldap.ldapobject.ReconnectLDAPObject.assert_called_once_with(
            sentinel.uri, retry_max=6)


class TestReconnectingLDAPBackend(TestCase):

    class TestBackend(NestedLDAPGroupsBackend):
        use_reconnecting_client = True

    def test_reconnecting_backend(self):
        backend = self.TestBackend()
        ldap_module = backend.ldap
        assert isinstance(ldap_module, ReconnectingLDAP)
        assert ldap_module.SERVER_DOWN is ldap.SERVER_DOWN


class TestNonReconnectingLDAPBackend(TestCase):

    class TestBackend(NestedLDAPGroupsBackend):
        use_reconnecting_client = False

    def test_non_reconnecting_backend(self):
        backend = self.TestBackend()
        ldap_module = backend.ldap
        assert not isinstance(ldap_module, ReconnectingLDAP)
        assert ldap_module.SERVER_DOWN is ldap.SERVER_DOWN
