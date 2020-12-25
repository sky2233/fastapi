from django.urls import path

from . import views

urlpatterns = [
    # path('', views.mainHTML, name='main'),
    path('search/', views.get, name='main'),
    path('search/get/', views.searchGet, name='get'),
    path('search/ipdomain/<str:searchValue>/', views.searchIp, name='searchipdomain'),
    path('search/files/<str:searchValue>/', views.searchFile, name='searchfilehash')
]