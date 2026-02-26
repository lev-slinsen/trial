from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include
from django.urls import path
from django.views import defaults as default_views
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView
from drf_spectacular.views import SpectacularSwaggerView
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
from rest_framework.permissions import AllowAny

schema_view = SpectacularAPIView.as_view(
    permission_classes=[AllowAny] if settings.DEBUG else []
)

swagger_view = SpectacularSwaggerView.as_view(
    url_name="api-schema",
    permission_classes=[AllowAny] if settings.DEBUG else []
)

urlpatterns = [
    # Django Admin
    path(settings.ADMIN_URL, admin.site.urls),
    # API service urls
    path("api/schema/", schema_view, name="api-schema"),
    path("api/swagger/", swagger_view, name="api-docs"),
    # API for Users
    path("api/users/", include("trial.users.urls", namespace="users")),
    # Media files
    *static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT),
]

# # API URLS
# urlpatterns += [
#     # DRF auth token
#     path("api/auth-token/", obtain_auth_token, name="obtain_auth_token"),
# ]

if settings.DEBUG:
    # This allows the error pages to be debugged during development, just visit
    # these url in browser to see how these error pages look like.
    urlpatterns += [
        path(
            "400/",
            default_views.bad_request,
            kwargs={"exception": Exception("Bad Request!")},
        ),
        path(
            "403/",
            default_views.permission_denied,
            kwargs={"exception": Exception("Permission Denied")},
        ),
        path(
            "404/",
            default_views.page_not_found,
            kwargs={"exception": Exception("Page not Found")},
        ),
        path("500/", default_views.server_error),
    ]
    if "debug_toolbar" in settings.INSTALLED_APPS:
        import debug_toolbar

        urlpatterns = [
            path("__debug__/", include(debug_toolbar.urls)),
            *urlpatterns,
        ]
