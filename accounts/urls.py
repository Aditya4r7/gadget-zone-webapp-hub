from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('forgotPassword/', views.forgot_password, name='forgot_password'),

    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('reset_passwordValidation/<uidb64>/<token>/', views.reset_passwordValidation, name='reset_passwordValidation'),
    path('resetPassword/', views.reset_password, name='reset_password'),

    path('my_orders/', views.my_orders, name='my_orders'),
    path('order_detail/<int:order_id>/', views.order_detail, name='order_detail'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
]
