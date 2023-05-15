from django.urls import path, re_path
from django.conf import settings
from django.conf.urls.static import static

from api.views import Index, Login, Register, Passwords, Leave

urlpatterns = [
    path('', Index.as_view(), name='index'),
    path('api/login', Login.as_view(), name='login'),
    path('api/register', Register.as_view(), name='register'),
    path('api/leave/<str:username>', Leave.as_view(), name='leave'),
    re_path(r'^api/(?P<username>.*)$', Passwords.as_view(), name='passwords'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
