from django.urls import path
from .views import CurrentUserView, UserChangePasswordView, UserLoginView, UserPasswordResetView, UserProfileView, UserRegistrationView, SendPasswordResetEmailView,UserSerializer

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('current/user/', CurrentUserView.as_view(), name='user'),


]
