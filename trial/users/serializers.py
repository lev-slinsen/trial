from copy import copy

from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import (
    ModelSerializer,
    SerializerMethodField,
    ValidationError,
)

User = get_user_model()


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = [
            "username",
            "phone",
            "tfa_enabled",
            "tfa_verified",
        ]
        read_only_fields = ["tfa_enabled", "tfa_verified"]
