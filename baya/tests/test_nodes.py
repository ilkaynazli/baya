from unittest.mock import Mock

from operator import and_
from operator import or_
from operator import xor
import pytest
from unittest import TestCase

from ..membership import AndNode
from ..membership import DynamicRolesNode as dg
from ..membership import RolesNode as g


class TestNodes(TestCase):
    def test_equality(self):
        a = g('A')
        b = g('B')
        c = g('C')
        assert not a == b
        assert a & b == a & b
        assert not (a & b == a | b)
        assert (a & b) | c == (a & b | c)
        assert not (a & b == a | b)
        assert not (a & b == a & b & c)

    def test_or_raises(self):
        """The or keyword is going to screw people up."""
        with pytest.raises(TypeError):
            g('A') or g('B')

    def test_and_raises(self):
        """The and keyword is going to screw people up."""
        with pytest.raises(TypeError):
            g('A') and g('B')

    def test_coercion(self):
        """Throw a TypeError when trying to combine nodes with non-nodes."""
        for op in [and_, or_, xor]:
            with pytest.raises(TypeError):
                op(g('A'), 'b')
            with pytest.raises(TypeError):
                op('b', g('A'))
            with pytest.raises(TypeError):
                op(g('A'), 1234)
            with pytest.raises(TypeError):
                op(1234, g('A'))


class TestDynamicRolesNode(TestCase):
    def test_get_roles_set(self):
        roles_callable1 = Mock(return_value=set())
        node = dg(roles_callable1)
        kwargs = {'a': 123}
        node.get_roles_set(**kwargs)
        assert roles_callable1.called_with(**kwargs)

    def test_get_roles_set_multiple_callables(self):
        roles_callable1 = Mock(return_value=set())
        roles_callable2 = Mock(return_value=set())
        node = dg(roles_callable1, roles_callable2)
        kwargs = {'b': 123}
        node.get_roles_set(**kwargs)
        assert roles_callable1.called_with(**kwargs)
        assert roles_callable2.called_with(**kwargs)

    def test_get_roles_set_or(self):
        c1 = lambda: {True}
        c2 = lambda: {True}
        c3 = lambda: {False}
        node = dg(c1, c2, c3)
        assert node.get_roles_set() == {True, False}

    def test_invalid_callable_return(self):
        c1 = lambda x: x
        node = dg(c1)
        with pytest.raises(RuntimeError):
            node.get_roles_set(x='abc')

    def test_combine_roles(self):
        """Combining roles into a simpler node when AND-ing."""
        role1 = dg(lambda x: x)
        role2 = dg(lambda y: y)
        combined = role1 & role2
        assert isinstance(combined, dg)
        assert role1._roles_set < combined._roles_set
        assert role2._roles_set < combined._roles_set
        assert role1._roles_set | role2._roles_set == combined._roles_set

    def test_combine_regular_role(self):
        """Combining with a regular node should just give an AndNode."""
        role1 = g('abc')
        role2 = dg(lambda y: y)
        combined = role1 & role2
        assert isinstance(combined, AndNode)
