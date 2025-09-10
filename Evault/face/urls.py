from django.urls import path
from .import views
from .views import serve_user_file
urlpatterns =[
    path('',views.home,name='home'),
    path('register-face/', views.register_face_page, name='register_face_page'),
    path('register-face/api/', views.register_face_api, name='register_face_api'),
    path('login_page',views.login_page,name='login_page'),# vault
    path('pin_login', views.pin_login, name='pin_login'),
    path('verify-login/', views.verify_login, name='verify_login'),
    path('upload/',views.upload_file_view,name='upload_file'),
    path('myfiles/<str:folder>/<str:filename>/', serve_user_file, name='serve_user_file'),
   
]