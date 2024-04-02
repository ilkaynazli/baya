from django.contrib.admin.options import InlineModelAdmin
import pytest

from baya import RolesNode as g
from baya.admin.sites import NestedGroupsAdminSite
from baya.permissions import requires
from baya.permissions import ALLOW_ALL
from baya.tests.admin import BlagEntryInline
from baya.tests.admin import ProtectedPhotoBlagEntryInline
from baya.tests.admin import site
from baya.tests.models import Blag
from baya.tests.models import BlagEntry
from baya.tests.submod.models import Comment
from baya.tests.test_base import LDAPGroupAuthTestBase
from unittest import mock
from unittest.mock import MagicMock


@pytest.mark.django_db
class TestAdminSite(LDAPGroupAuthTestBase):
    def test_module_perms(self):
        app_label = Blag._meta.app_label
        for user in ['has_all', 'has_a', 'has_aa', 'has_aaa']:
            request = self.mock_get_request(self.login(user))
            assert request.user.has_module_perms(app_label)

        request = self.mock_get_request(self.login('has_b'))
        assert not request.user.has_module_perms(app_label)

    def test_required_baya_groups(self):
        # The required groups for an admin site is the `or`-union of all
        # different required groups
        required_groups = site._get_required_baya_groups()
        exp = ((g('AAA') & ALLOW_ALL) |
               (g('AA') & ALLOW_ALL) |
               (g('AA') | g('B')))
        assert required_groups == exp

    def test_required_baya_groups_repeats(self):
        """Repeated roles should only be shown once."""
        admins = []
        role = g('A')
        # Mock model admins, each with the same required role
        for i in range(5):
            model = MagicMock(_meta=MagicMock(app_label='%s' % i))
            model_opts = MagicMock(_gate=MagicMock(
                _gate=MagicMock()))
            model_opts._gate.get_requires = role
            admins.append((model, model_opts))
        with mock.patch.object(
                NestedGroupsAdminSite,
                '_get_admins_with_gate',
                return_value=admins):
            site = NestedGroupsAdminSite()
            required_groups = site._get_required_baya_groups()
            exp = g('A')
            assert required_groups == exp

    def test_index(self):
        """Only display those apps which the user can access."""
        request = self.mock_get_request(self.login('has_all'))
        index = site.index(request)
        app_list = index.context_data['app_list']
        assert len(app_list) == 2
        for app in app_list:
            models = {str(model['name']) for model in app['models']}
            if len(models) == 2:
                assert {"Blags", "Entries"} == models
                for model in app['models']:
                    for permission in ['add', 'change', 'delete']:
                        assert model['perms'][permission]
            else:
                assert {"Comments"} == models
                model = app['models'][0]
                assert model['perms']['add']
                assert model['perms']['change']
                assert not model['perms']['delete']

    def test_read_only(self):
        # has_aaa can only access the read-only Blag changelist
        request = self.mock_get_request(self.login('has_aaa'))
        index = site.index(request)
        app_list = index.context_data['app_list']
        assert len(app_list) == 1
        app_list = app_list[0]
        assert {"Blags"} == {str(model['name']) for model in app_list['models']}
        perms = app_list['models'][0]['perms']
        assert not perms['add']
        assert perms['change']
        assert not perms['delete']


@pytest.mark.django_db
class TestOptions(LDAPGroupAuthTestBase):
    def _get_options(self):
        return site._registry[Blag]

    def test_add_permissions(self):
        options = self._get_options()
        assert (
            options.has_add_permission(
                self.mock_get_request(self.login('has_all'))))
        assert (
            options.has_add_permission(
                self.mock_get_request(self.login('has_a'))))
        assert not (
            options.has_add_permission(
                self.mock_get_request(self.login('has_aaa'))))

    def test_change_view_permission(self):
        options = self._get_options()
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_all'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_a'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_aaa'))))

    def test_delete_permission(self):
        options = self._get_options()
        assert (
            options.has_delete_permission(
                self.mock_post_request(self.login('has_all'))))
        assert (
            options.has_delete_permission(
                self.mock_post_request(self.login('has_a'))))
        assert not (
            options.has_delete_permission(
                self.mock_post_request(self.login('has_aaa'))))


class TestCRUDOptions(LDAPGroupAuthTestBase):
    def _get_options(self):
        return site._registry[Comment]

    def test_create_permissions(self):
        options = self._get_options()
        assert (
            options.has_add_permission(
                self.mock_get_request(self.login('has_all'))))
        assert (
            options.has_add_permission(
                self.mock_get_request(self.login('has_a'))))
        assert not (
            options.has_add_permission(
                self.mock_get_request(self.login('has_aa'))))
        assert not (
            options.has_add_permission(
                self.mock_get_request(self.login('has_aaa'))))
        assert not (
            options.has_add_permission(
                self.mock_get_request(self.login('has_b'))))

    def test_read_permissions(self):
        options = self._get_options()
        # Note - django admin doesn't distinguish between read and update, so
        # baya blocks read-only access from writing, but it still looks to
        # the admin like they have change permissions.
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_all'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_a'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_aa'))))
        assert not (
            options.has_change_permission(
                self.mock_get_request(self.login('has_aaa'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_b'))))

    def test_update_permissions(self):
        options = self._get_options()
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_all'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_a'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_aa'))))
        assert not (
            options.has_change_permission(
                self.mock_get_request(self.login('has_aaa'))))
        assert (
            options.has_change_permission(
                self.mock_get_request(self.login('has_b'))))

    def test_delete_permissions(self):
        options = self._get_options()
        assert not (
            options.has_delete_permission(
                self.mock_get_request(self.login('has_all'))))
        assert not (
            options.has_delete_permission(
                self.mock_get_request(self.login('has_a'))))
        assert not (
            options.has_delete_permission(
                self.mock_get_request(self.login('has_aa'))))
        assert not (
            options.has_delete_permission(
                self.mock_get_request(self.login('has_aaa'))))
        assert not (
            options.has_delete_permission(
                self.mock_get_request(self.login('has_b'))))


@pytest.mark.django_db
class TestInlines(LDAPGroupAuthTestBase):
    def setup_method(self):
        super().setup_method()
        Blag.objects.all().delete()
        self.blag = Blag.objects.create(name="My Blag")
        self.entries = [
            BlagEntry.objects.create(blag=self.blag, title="entry 1"),
            BlagEntry.objects.create(blag=self.blag, title="entry 2"),
        ]

    def _get_inlines(self):
        request = self.mock_get_request(
            self.login('has_all'), get={'blag_id': self.blag.id})
        blag_options = site._registry[Blag]
        blag_details = blag_options.change_view(request, '%s' % self.blag.id)
        return blag_details.context_data['inline_admin_formsets']

    def test_entries_displayed(self):
        inline_formsets = self._get_inlines()
        assert len(inline_formsets) == 2
        # The UnprotectedPhotoBlagEntryInline should not be here
        inline_opts = {type(inf.opts) for inf in inline_formsets}
        assert inline_opts == {BlagEntryInline, ProtectedPhotoBlagEntryInline}

    def test_perms_correct(self):
        def _check(inline, request, add, change, delete):
            assert inline.opts.has_add_permission(request, obj=None) == add
            assert inline.opts.has_change_permission(request) == change
            assert inline.opts.has_delete_permission(request) == delete

        inline_formsets = self._get_inlines()
        while inline_formsets:
            inline = inline_formsets.pop()
            if isinstance(inline.opts, BlagEntryInline):
                request = self.mock_post_request(self.login('has_a'))
                _check(inline, request, True, True, True)
                request = self.mock_post_request(self.login('has_b'))
                _check(inline, request, False, False, False)
            elif isinstance(inline.opts, ProtectedPhotoBlagEntryInline):
                request = self.mock_post_request(self.login('has_a'))
                _check(inline, request, True, True, True)
                request = self.mock_post_request(self.login('has_b'))
                _check(inline, request, True, False, False)

    def test_inline_decoration(self):
        # This should fail because inlines don't have any {add,change,delete}
        # views to protect.
        with pytest.raises(TypeError):
            @requires(g('A'))
            class MyInline(InlineModelAdmin):
                pass
