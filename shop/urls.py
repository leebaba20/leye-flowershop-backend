from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    SignupView,
    CustomTokenObtainPairView,
    LogoutView,
    CurrentUserView,
    get_csrf_token,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    CreatePaymentView,
    VerifyPaymentView,
    ShippingView,
    OrderView,
    NewsletterView,
    ContactView,
)

urlpatterns = [
    path("csrf-token/", get_csrf_token, name="csrf_token"),
    path("signup/", SignupView.as_view(), name="signup"),
    path("login/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("me/", CurrentUserView.as_view(), name="current_user"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # ✅ Fix these to match frontend
    path("reset-password/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("reset-password-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    path("paystack/init/", CreatePaymentView.as_view(), name="create_payment"),
    path("payment/verify/", VerifyPaymentView.as_view(), name="verify_payment"),

    path("shipping/", ShippingView.as_view(), name="shipping"),
    path("orders/", OrderView.as_view(), name="orders"),

    path("newsletter/", NewsletterView.as_view(), name="newsletter"),
    path("contact/", ContactView.as_view(), name="contact"),
]
