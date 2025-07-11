import os
import logging
import requests

from django.conf import settings
from django.core.mail import send_mail
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator

from rest_framework import status, permissions, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .serializers import (
    SignupSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    CreatePaymentSerializer,
    VerifyPaymentSerializer,
    ShippingSerializer,
    UserSerializer,
    OrderSerializer,
    CustomTokenObtainPairSerializer,
    NewsletterSubscriptionSerializer,
    ContactMessageSerializer,
)
from .models import ShippingInfo, Order, NewsletterSubscription, ContactMessage

logger = logging.getLogger(__name__)
User = get_user_model()


# === AUTH & USER ===
class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = True
            user.save()
            logger.info(f"New user created: {user.email}")
            return Response({
                "message": "User created successfully",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            }, status=status.HTTP_201_CREATED)
        logger.warning("Signup failed", extra={'errors': serializer.errors})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User {request.user.email} logged out")
            return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            logger.warning("Logout failed: invalid token", exc_info=True)
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


@ensure_csrf_cookie
def get_csrf_token(request):
    return JsonResponse({'detail': 'CSRF cookie set'})


# === PASSWORD RESET ===
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = f"{settings.FRONTEND_BASE_URL}/reset-password/{uid}/{token}/"

            send_mail(
                "Password Reset Request",
                f"Click the link to reset your password: {reset_url}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )
            logger.info(f"Password reset email sent to: {email}")
            return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            logger.warning(f"Password reset requested for non-existent email: {email}")
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uidb64 = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if not default_token_generator.check_token(user, token):
                return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            logger.info(f"Password reset successfully for user {user.email}")
            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error("Unexpected error during password reset", exc_info=True)
            return Response({"detail": "Something went wrong. Please try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# === PAYMENT ===
class CreatePaymentView(APIView):
    def post(self, request):
        serializer = CreatePaymentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        amount_kobo = int(float(data["amount"]) * 100)

        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        pay_data = {
            "email": data["email"],
            "amount": amount_kobo,
            "metadata": data.get("metadata", {}),
        }

        response = requests.post("https://api.paystack.co/transaction/initialize", json=pay_data, headers=headers)
        res_data = response.json()

        if response.status_code != 200 or not res_data.get("status"):
            return Response({'detail': res_data.get('message', 'Payment initialization failed')}, status=status.HTTP_400_BAD_REQUEST)

        return Response(res_data.get("data", {}), status=status.HTTP_200_OK)


class VerifyPaymentView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = VerifyPaymentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        reference = serializer.validated_data['reference']
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
        url = f"https://api.paystack.co/transaction/verify/{reference}"

        try:
            response = requests.get(url, headers=headers)
            res_data = response.json()

            if response.status_code == 200 and res_data.get("status"):
                logger.info(f"✅ Payment verified: {reference}")
                metadata = res_data["data"].get("metadata", {})
                shipping = metadata.get("shipping")
                cart = metadata.get("cart")

                amount_kobo = res_data["data"].get("amount", 0)
                amount_naira = round(amount_kobo / 100, 2)

                user = request.user if request.user.is_authenticated else None

                if user and shipping:
                    ShippingInfo.objects.update_or_create(
                        user=user,
                        defaults={**shipping}
                    )
                    logger.info(f"Shipping info saved for user {user.email}")

                if user and cart:
                    Order.objects.update_or_create(
                        reference=reference,
                        defaults={
                            "user": user,
                            "items": cart,
                            "total_amount": amount_naira,
                        }
                    )
                    logger.info(f"Order saved for user {user.email}, ref: {reference}")
                else:
                    logger.warning("User not authenticated or cart empty — order not saved.")

                return Response(res_data["data"], status=status.HTTP_200_OK)

            return Response({'error': res_data.get("message", "Payment verification failed")}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error("❌ Payment verification failed", exc_info=True)
            return Response({'error': f'Invalid request: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


# === SHIPPING ===
class ShippingView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        shipping = ShippingInfo.objects.filter(user=request.user).first()
        serializer = ShippingSerializer(instance=shipping, data=request.data, context={'user': request.user})

        if serializer.is_valid():
            serializer.save()
            logger.info(f"Shipping info {'updated' if shipping else 'created'} for user {request.user.email}")
            return Response({"message": "Shipping info saved", "data": serializer.data}, status=status.HTTP_200_OK)

        logger.warning("Shipping info failed to save", extra={'errors': serializer.errors})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        return self.post(request)


# === ORDERS ===
class OrderView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OrderSerializer

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# === NEWSLETTER ===
class NewsletterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = NewsletterSubscriptionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"detail": serializer.errors.get("email", ["Invalid input"])[0]},
                status=status.HTTP_400_BAD_REQUEST
            )

        subscription = serializer.save()
        email = subscription.email

        try:
            send_mail(
                subject="Thanks for Subscribing to Leye Flower Shop 🌸",
                message="You've successfully subscribed to our newsletter!",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )
            logger.info("Newsletter subscription saved and email sent to %s", email)
        except Exception as e:
            logger.error("Failed to send subscription email", exc_info=True)

        return Response({"message": "Subscribed successfully."}, status=status.HTTP_201_CREATED)


# === CONTACT ===
class ContactView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ContactMessageSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"detail": serializer.errors.get("email", ["Invalid input"])[0]},
                status=status.HTTP_400_BAD_REQUEST
            )

        contact = serializer.save()

        try:
            send_mail(
                subject=f"New Contact Message from {contact.name}",
                message=f"{contact.name} <{contact.email}> wrote:\n\n{contact.message}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=["princeleeoye@gmail.com"],
            )
        except Exception as e:
            logger.error("Failed to send contact email", exc_info=True)

        return Response({"message": "Message received successfully."}, status=status.HTTP_200_OK)
