from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.views.decorators.http import require_POST

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='core/login.html'), name='login'),
    path('logout/', require_POST(auth_views.LogoutView.as_view()), name='logout'),
    path('', include('core.urls')),
]
