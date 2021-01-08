from django.urls import path
from django.contrib import admin

from . import views

admin.autodiscover()
admin.site.enable_nav_sidebar = False

urlpatterns = [
    # path('', views.mainHTML, name='main'),
    path('', views.get, name='main'),
    path('get/', views.searchGet, name='get'),
    path('ipdomain/<str:searchValue>/', views.searchIp, name='searchipdomain'),
    path('files/<str:searchValue>/', views.searchFile, name='searchfilehash')
]