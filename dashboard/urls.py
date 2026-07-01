from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/', views.scan, name='scan'),
    path('api/scan/', views.api_scan, name='api_scan'),
    path('ip-intelligence/', views.ip_intelligence, name='ip_intelligence'),
    path('api/ip-details/', views.api_ip_details, name='api_ip_details'),
]