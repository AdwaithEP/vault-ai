from django.urls import path
from . import views

urlpatterns = [
    path('', views.packet_tracer, name='packet_tracer'),
    path('analyze/', views.analyze_packets, name='analyze_packets'),
]