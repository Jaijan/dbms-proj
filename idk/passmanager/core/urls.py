from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    path('', views.signin, name='signin'),
    path('home/', login_required(views.home), name='home'),
    path('signout/', views.signout, name='signout'),
    path('get_credentials/', login_required(views.get_credentials), name='get_credentials'),
    path('delete-password/', views.delete_password, name='delete_password'),
    path('setup-otp/', views.setup_otp, name='setup_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('upload-document/', views.upload_document, name='upload_document'),
    path('documents/', views.get_documents, name='get_documents'),
    path('documents/<int:document_id>/delete/', views.delete_document, name='delete_document'),
    path('verify-document-otp/', views.verify_document_otp, name='verify_document_otp'),
    path('view-document/<int:document_id>/', views.view_document, name='view_document'),
    path('download-document/<int:document_id>/', views.download_document, name='download_document'),
]
