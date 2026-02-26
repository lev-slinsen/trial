import pyotp
from django.contrib.auth import authenticate, get_user_model, login
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiRequest
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from trial.users.serializers import UserSerializer
from trial.users.tokens import create_jwt_pair_for_user

User = get_user_model()


class LoginView(APIView):
    permission_classes = []

    def get(self, request: Request):
        if not request.user.is_authenticated:
            return Response(data={"error": "You are not authenticated"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = UserSerializer(request.user)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    @extend_schema(
        request=OpenApiRequest(
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                },
                "required": ["username", "password"],
            }
        ),
        responses={200: OpenApiTypes.OBJECT},
    )
    def post(self, request: Request):
        # Validating username and password
        user = authenticate(
            username=request.data.get("username"),
            password=request.data.get("password")
        )
        if not user:
            return Response({"message": "Invalid credentials"}, status=400)

        # If 2fa is required, user is not authenticated yet
        if user.tfa_required:
            request.session["pre_2fa_user_id"] = user.pk
            return Response({"tfa_required": True, "methods": ["totp", "sms"]}, status=200)

        # Authentication and session token generation
        login(request, user)
        if "pre_2fa_user_id" in request.session:
            request.session.pop("pre_2fa_user_id", None)
        tokens = create_jwt_pair_for_user(user)
        return Response({"message": "Login successful", "tokens": tokens})


class TOTPView(APIView):
    permission_classes = []

    def get(self, request):
        # Chek if user exists and requires 2fa
        if "pre_2fa_user_id" not in request.session:
            return Response({"message": "No pre-2FA session found"}, status=400)
        try:
            user = User.objects.get(pk=request.session.get("pre_2fa_user_id"))
            if not user.tfa_required:
                return Response({"message": "2FA not required"}, status=400)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=404)

        # Generate TOTP URI for authenticator apps
        secret = pyotp.TOTP(user.totp_secret)
        totp_uri = secret.provisioning_uri(
            name=user.username,     # account name shown in app
            issuer_name="Trial"     # app/organization name
        )

        return Response({"totp_uri": totp_uri})

    def post(self, request):
        # Request validation
        if "code" not in request.data:
            return Response({"message": "Code required"}, status=400)
        code = request.data.get("code")
        user_id = request.session.get("pre_2fa_user_id")
        if not user_id:
            return Response({"message": "No pre-2FA session found"}, status=400)

        # Code verification
        user = User.objects.get(pk=user_id)
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code, valid_window=1):
            return Response({"message": "Invalid code"}, status=400)

        # Updating user status
        User.objects.filter(pk=user.pk).update(tfa_verified=True)
        tokens = create_jwt_pair_for_user(user)
        request.session.pop("pre_2fa_user_id", None)

        return Response({"message": "Verification successful", "tokens": tokens})
