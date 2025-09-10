from django.urls import path
from .import views 

urlpatterns=[
    path('login/', views.pin_login_view, name='user_pin_login'),
    path('register/',views.initial_register, name='initial_register'),
    path('logout/', views.logout_view, name='logout'),
]   