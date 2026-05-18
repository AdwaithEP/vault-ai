from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add/', views.add_password, name='add_password'),
    path('delete/<int:id>/', views.delete_password, name='delete_password'),
    path('reveal/', views.reveal_password, name='reveal_password'),
]