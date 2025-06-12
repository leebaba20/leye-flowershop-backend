# shop/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, ShippingInfo

admin.site.register(CustomUser, UserAdmin)

@admin.register(ShippingInfo)
class ShippingInfoAdmin(admin.ModelAdmin):
    list_display = ("full_name", "user", "phone_number", "city", "state", "created_at")
    search_fields = ("full_name", "user__username", "phone_number", "city", "state")
    list_filter = ("state", "created_at")
