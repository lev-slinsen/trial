from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from trial.users.views import LoginView, TOTPView

app_name = "users"
urlpatterns = [
    path("login", LoginView.as_view(), name="login"),
    path("jwt/verify", TokenVerifyView.as_view(), name="jwt_verify"),   # POST
    path("jwt/refresh", TokenRefreshView.as_view(), name="jwt_refresh"),  # POST
    path("totp", TOTPView.as_view(), name="totp"),  # GET, POST
    # path("~redirect/", view=user_redirect_view, name="redirect"),
    # path("~update/", view=user_update_view, name="update"),
    # path("<str:username>/", view=user_detail_view, name="detail"),
]
