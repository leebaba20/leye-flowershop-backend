from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils.translation import gettext_lazy as _
from .models import (
    ShippingInfo,
    NewsletterSubscription,
    ContactMessage,
    Order,
    Product,  # Make sure Product model is imported
)

User = get_user_model()


# === USER SERIALIZER ===
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')


# === LOGIN SERIALIZER ===
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'username'

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if not username or not password:
            raise serializers.ValidationError(_("Must include both username and password."))

        user = authenticate(request=self.context.get('request'), username=username, password=password)

        if not user:
            raise serializers.ValidationError(_("Invalid username or password."))

        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }


# === SIGNUP SERIALIZER ===
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=6,
        required=True,
        style={'input_type': 'password'},
        error_messages={
            'min_length': 'Password must be at least 6 characters long.',
            'required': 'Password is required.',
        }
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already taken.")
        return value

    def validate_email(self, value):
        value = value.lower()
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )


# === PASSWORD RESET REQUEST SERIALIZER ===
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value


# === PASSWORD RESET CONFIRM SERIALIZER ===
class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        min_length=6,
        write_only=True,
        style={'input_type': 'password'},
        error_messages={
            'min_length': 'Password must be at least 6 characters long.',
            'required': 'New password is required.',
        }
    )

    def validate_new_password(self, value):
        validate_password(value)
        return value


# === CREATE PAYMENT SERIALIZER ===
class CreatePaymentSerializer(serializers.Serializer):
    email = serializers.EmailField()
    amount = serializers.IntegerField()
    metadata = serializers.DictField(required=False)

    def validate_amount(self, value):
        if value < 100:
            raise serializers.ValidationError("Minimum transaction amount is ₦100.")
        return value


# === VERIFY PAYMENT SERIALIZER ===
class VerifyPaymentSerializer(serializers.Serializer):
    reference = serializers.CharField()


# === SHIPPING SERIALIZER ===
class ShippingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingInfo
        fields = [
            'full_name',
            'address',
            'city',
            'state',
            'postal_code',
            'country',
            'phone_number',
        ]

    def create(self, validated_data):
        return ShippingInfo.objects.create(user=self.context['user'], **validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


# === ORDER SERIALIZER ===
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['reference', 'items', 'total_amount']

    def validate_total_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Total amount must be positive.")
        return value


# === NEWSLETTER SUBSCRIPTION SERIALIZER ===
class NewsletterSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsletterSubscription
        fields = ['email']

    def validate_email(self, value):
        if NewsletterSubscription.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("You are already subscribed with this email.")
        return value


# === CONTACT MESSAGE SERIALIZER ===
class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'message']


# === SEARCH PRODUCT SERIALIZER ===
class SearchProductSerializer(serializers.ModelSerializer):
    img = serializers.SerializerMethodField()
    new_price = serializers.DecimalField(source='price', max_digits=10, decimal_places=2)
    old_price = serializers.SerializerMethodField()  # Optional

    class Meta:
        model = Product
        fields = ['id', 'name', 'img', 'new_price', 'old_price', 'description']

    def get_img(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url)
        return None
