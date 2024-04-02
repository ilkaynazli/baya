from unittest.mock import MagicMock
from unittest.mock import patch

from unittest import TestCase

from ..dynamic_roles import DjangoRequestGroupFormatter


class TestDjangoRequestGroupFormatter(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestDjangoRequestGroupFormatter, self).__init__(*args, **kwargs)
        self.formatter = DjangoRequestGroupFormatter("%s_admin", "group")

    def build_mock_request(self, request_group):
        """Build a mock request.

        Args:
            request_group: The group that the user is requesting access to.
        """
        request = MagicMock()
        request.resolver_match.kwargs = {}
        request.GET = {}
        request.GET['group'] = request_group
        return request

    def test_returns_set(self):
        """The formatter should return a set of groups."""
        roles = self.formatter(self.build_mock_request('mygroup'))
        assert type(roles) == set
        assert len(roles) == 1
        assert roles.pop() == "mygroup_admin"

    def test_query_param(self):
        request = self.build_mock_request('mygroup')
        roles = self.formatter(request)
        assert roles == {'mygroup_admin'}

    def test_reverse_kwarg(self):
        request = self.build_mock_request('mygroup')
        request.GET = {}
        request.resolver_match.kwargs = {'group': 'mygroup'}
        roles = self.formatter(request)
        assert roles == {'mygroup_admin'}

    def test_query_param_collision(self):
        """The URL kwarg should take precedence over the query parameter."""
        request = self.build_mock_request('mygroup')
        request.resolver_match.kwargs = {'group': 'kwarg_group'}
        with patch('baya.dynamic_roles.logger') as mock_logger:
            roles = self.formatter(request)
            assert mock_logger.warning.call_count == 1
        assert roles == {'kwarg_group_admin'}

    def test_str(self):
        st = str(self.formatter)
        assert "%s_admin" in st
        assert "group" in st

    def test_repr(self):
        re = repr(self.formatter)
        assert self.formatter.__class__.__name__ in re
