from django.conf.urls import include, url

from . import admin


app_name = 'submod2'

urlpatterns = [
    url(r'^admin/', admin.site.urls, name='submod2_admin'),
]
