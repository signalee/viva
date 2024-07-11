from django.urls import path, include

urlpatterns = [
    path('api/v1/user/login/', include('login.urls')),
    path('api/v1/user/logout/', include('logout.urls')),
    path('api/v1/user/', include('members.urls')),
    path('api/v1/board/', include('board.urls')),
]