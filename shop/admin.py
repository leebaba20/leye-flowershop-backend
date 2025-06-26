from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    CustomUser,
    ShippingInfo,
    Order,
    NewsletterSubscription,
    ContactMessage
)

# Register CustomUser with default UserAdmin
admin.site.register(CustomUser, UserAdmin)

# Customize ShippingInfo admin
@admin.register(ShippingInfo)
class ShippingInfoAdmin(admin.ModelAdmin):
    list_display = ("full_name", "user", "phone_number", "city", "state", "created_at")
    search_fields = ("full_name", "user__username", "phone_number", "city", "state")
    list_filter = ("state", "created_at")
    ordering = ("-created_at",)

# Customize Order admin
@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("reference", "user", "total_amount", "created_at")
    search_fields = ("reference", "user__username", "user__email")
    list_filter = ("created_at",)
    ordering = ("-created_at",)

# Customize Newsletter admin
@admin.register(NewsletterSubscription)
class NewsletterSubscriptionAdmin(admin.ModelAdmin):
    list_display = ("email", "subscribed_at")
    search_fields = ("email",)
    ordering = ("-subscribed_at",)

# Customize Contact Message admin
@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "created_at")
    search_fields = ("name", "email", "message")
    ordering = ("-created_at",)
