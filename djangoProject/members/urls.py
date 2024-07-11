from django.urls import path
from . import views

app_name = 'members'

urlpatterns = [
    path('', views.members_views, name='members_views'),
    path('signup/', views.signup_views, name='signup_views'),
    path('password/', views.user_password, name='user_password'),
    path('check-password/', views.password_check, name='password_check'),
]