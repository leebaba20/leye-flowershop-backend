from django.db import models
from django.contrib.auth.models import AbstractUser

# ===============================
# ✅ Custom User Model
# ===============================
class CustomUser(AbstractUser):
    email_confirmed = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return self.username


# ===============================
# 🚚 Shipping Info Model
# ===============================
class ShippingInfo(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="shipping_infos")
    full_name = models.CharField(max_length=255)
    address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} ({getattr(self.user, 'username', 'Unknown')})"

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Shipping Info"
        verbose_name_plural = "Shipping Infos"


# ===============================
# 🧾 Order Model
# ===============================
class Order(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="orders")
    reference = models.CharField(max_length=100, unique=True)
    items = models.JSONField()  # Store cart items as JSON
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order {self.reference} by {getattr(self.user, 'username', 'Unknown')}"

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Order"
        verbose_name_plural = "Orders"


# ===============================
# 📬 Newsletter Subscription
# ===============================
class NewsletterSubscription(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    class Meta:
        ordering = ['-subscribed_at']
        verbose_name = "Newsletter Subscriber"
        verbose_name_plural = "Newsletter Subscribers"


# ===============================
# 📩 Contact Message Model
# ===============================
class ContactMessage(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Contact Message"
        verbose_name_plural = "Contact Messages"
