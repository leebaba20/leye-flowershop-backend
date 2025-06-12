from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

# Inline home view for root URL
def home_view(request):
    return HttpResponse("Welcome to the Leye Flower Shop API!")

urlpatterns = [
    path('', home_view, name='root'),                    # Root welcome page
    path('admin/', admin.site.urls),                     # Django admin
    path('api/auth/', include('shop.urls')),             # All app API routes
]
