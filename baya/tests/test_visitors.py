from unittest.mock import MagicMock
import pytest

from ..dynamic_roles import DjangoRequestGroupFormatter
from ..membership import DynamicRolesNode as dg
from ..membership import RolesNode as g
from ..membership import ValueNode
from ..visitors import ExpressionWriter
from ..visitors import PermissionChecker


@pytest.mark.django_db
class TestPermissionChecker():
    def setup_method(self):
        self.a = g('A')
        self.b = g('B')
        self.c = g('C')
        self.s_admin = dg(DjangoRequestGroupFormatter('%s_admin', 'group'))

    def mock_request(self, request_group):
        """Build a mock request (for self.s_admin).

        Args:
            request_group: The group that the user is requesting access to.
        """
        request = MagicMock()
        request.resolver_match.kwargs = {}
        request.GET = {}
        request.GET['group'] = request_group
        return request

    def _has_permissions(self, node, roles, **kwargs):
        return PermissionChecker(roles).visit(node, **kwargs)

    def test_set_membership_single(self):
        assert self._has_permissions(self.a, ['A'])
        assert not self._has_permissions(self.a, ['B'])

    def test_and(self):
        and_node = self.a & self.b
        assert self._has_permissions(and_node, ['A', 'B'])
        assert not self._has_permissions(and_node, ['A'])
        assert not self._has_permissions(and_node, ['B'])

    def test_and_dynamic(self):
        """Ensure the group permissions are using the requested group."""
        and_node = self.a & self.s_admin
        assert self._has_permissions(
            and_node, ['A', 'a_admin'], request=self.mock_request('A'))
        assert not self._has_permissions(
            and_node, ['A', 'a_admin'], request=self.mock_request('B'))

    def test_or(self):
        or_node = self.a | self.b
        assert self._has_permissions(or_node, ['A', 'B'])
        assert self._has_permissions(or_node, ['A'])
        assert self._has_permissions(or_node, ['B'])
        assert self._has_permissions(or_node, ['A', 'B', 'C'])

    def test_xor(self):
        xor_node = self.a ^ self.b
        assert not self._has_permissions(xor_node, ['A', 'B'])
        assert self._has_permissions(xor_node, ['A'])
        assert self._has_permissions(xor_node, ['B'])

    def test_not(self):
        not_node = ~self.a
        assert not self._has_permissions(not_node, ['A', 'B'])
        assert not self._has_permissions(not_node, ['A'])
        assert self._has_permissions(not_node, ['B'])
        assert not self._has_permissions(not_node, ['A', 'B', 'C'])
        assert self._has_permissions(not_node, ['B', 'C'])

    def test_and_or_and(self):
        node = (self.a & self.b) | (self.c & self.s_admin)
        req = self.mock_request('a')
        assert not self._has_permissions(node, ['A'], request=req)
        assert not self._has_permissions(node, ['B'], request=req)
        assert not self._has_permissions(node, ['C'], request=req)
        assert not self._has_permissions(node, ['a_admin'], request=req)
        assert self._has_permissions(node, ['A', 'B'], request=req)
        assert self._has_permissions(node, ['a_admin', 'C'], request=req)
        assert not self._has_permissions(node, ['A', 'C'], request=req)
        assert not self._has_permissions(node, ['B', 'a_admin'], request=req)

    def test_and_xor_not_and(self):
        """What a ridiculous membership requirement."""
        node = (self.a & self.b) ^ ~(self.c | self.s_admin)
        req = self.mock_request('A')
        assert self._has_permissions(node, ['A'], request=req)
        assert self._has_permissions(node, ['B'], request=req)
        assert not self._has_permissions(node, ['C'], request=req)
        assert not self._has_permissions(node, ['a_admin'], request=req)
        assert not self._has_permissions(node, ['A', 'B'], request=req)
        assert not self._has_permissions(node, ['a_admin', 'C'], request=req)
        assert not self._has_permissions(node, ['A', 'C'], request=req)
        assert not self._has_permissions(node, ['B', 'a_admin'], request=req)
        assert self._has_permissions(node, ['A', 'B', 'a_admin'], request=req)
        assert self._has_permissions(node, ['A', 'B', 'C'], request=req)
        assert self._has_permissions(node, ['A', 'B', 'C', 'a_admin'], request=req)

    def test_value_node(self):
        node1 = ValueNode(True)
        node2 = ~ValueNode(False)
        assert self._has_permissions(node1, ['A'])
        assert self._has_permissions(node2, ['A'])
        assert self._has_permissions(node1, [''])
        assert self._has_permissions(node2, [''])
        assert self._has_permissions(node1, ['A', 'F'])
        assert self._has_permissions(node2, ['A', 'F'])
        node1 = ValueNode(False)
        node2 = ~ValueNode(True)
        assert not self._has_permissions(node1, ['A'])
        assert not self._has_permissions(node2, ['A'])
        assert not self._has_permissions(node1, [''])
        assert not self._has_permissions(node2, [''])
        assert not self._has_permissions(node1, ['A', 'F'])
        assert not self._has_permissions(node2, ['A', 'F'])

    def test_member_and_value_node(self):
        node = ValueNode(True) | g('A')
        assert self._has_permissions(node, ['A'])
        assert self._has_permissions(node, [''])
        assert self._has_permissions(node, ['A', 'F'])
        node = ValueNode(True) & g('A')
        assert self._has_permissions(node, ['A'])
        assert not self._has_permissions(node, [''])
        assert self._has_permissions(node, ['A', 'F'])
        node = ValueNode(False) | g('A')
        assert self._has_permissions(node, ['A'])
        assert not self._has_permissions(node, [''])
        assert self._has_permissions(node, ['A', 'F'])
        node = ValueNode(False) & g('A')
        assert not self._has_permissions(node, ['A'])
        assert not self._has_permissions(node, [''])
        assert not self._has_permissions(node, ['A', 'F'])


@pytest.mark.django_db
class TestExpressionWriter():
    def setup_method(self):
        self.writer = ExpressionWriter()

    def test_operator_precedence(self):
        node = g('A') ^ g('B') | g('C') ^ g('D')
        assert '{a} ^ {b} | {c} ^ {d}', self.writer.visit(node) == repr(node)
        node = ~(g('A') & g('B')) ^ (g('C') | g('D') & g('E'))
        assert '~{a, b} ^ ({c} | {d, e})', self.writer.visit(node) == repr(node)

    def test_unary(self):
        node = ~~g('A')
        assert '~~{a}', self.writer.visit(node) == repr(node)
        node = ~(g('A') ^ g('B'))
        assert '~({a} ^ {b})', self.writer.visit(node) == repr(node)

    def test_value_node(self):
        node = ~ValueNode(True)
        assert '~True' == self.writer.visit(node)
        node = g('A') & ValueNode(False)
        assert '{a} & False' == self.writer.visit(node)
        node = ~node
        assert '~({a} & False)' == self.writer.visit(node)
