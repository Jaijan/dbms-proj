from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    path('', views.signin, name='signin'),
    path('home/', login_required(views.home), name='home'),
    path('signout/', views.signout, name='signout'),
    path('get_credentials/', login_required(views.get_credentials), name='get_credentials'),
]
