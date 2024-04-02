import pytest
from django.template import Context
from django.template import Template
from .test_base import LDAPGroupAuthTestBase
from django.contrib.auth.models import AnonymousUser


@pytest.mark.django_db
class CanUserPerformActionTagTest(LDAPGroupAuthTestBase):

    BASIC_TEMPLATE = Template(
        "{%  load baya_tags  %}"
        "{%  can_user_perform_action action as can_perform_action %}"
        "{%  if can_perform_action %}"
        "True"
        "{%  else %}"
        "False"
        "{%  endif %}"
    )

    def test_anonymous_user_has_permission_false(self):
        context = Context({
            'action': 'index',
            'user': AnonymousUser(),
        })
        rendered = self.BASIC_TEMPLATE.render(context)
        assert 'False' in rendered

    def test_has_permission_false(self):
        context = Context({
            'action': 'index',
            'user': self.login('has_nothing'),
        })
        rendered = self.BASIC_TEMPLATE.render(context)
        assert 'False' == rendered

    def test_has_permission_true(self):
        context = Context({
            'action': 'index',
            'user': self.login('has_all'),
        })
        rendered = self.BASIC_TEMPLATE.render(context)
        assert 'True' in rendered
