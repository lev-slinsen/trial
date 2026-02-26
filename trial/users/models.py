import pyotp
from django.contrib.auth.models import AbstractUser
from django.core.cache import cache
from django.db import models
from django.db.models import CharField
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from phone_field import PhoneField


class User(AbstractUser):
    """
    Default custom user model for Trial.
    If adding fields that need to be filled at user signup,
    check forms.SignupForm and forms.SocialSignupForms accordingly.
    """

    # First and last name do not cover name patterns around the globe
    name = CharField(_("Name of User"), blank=True, max_length=255)
    first_name = None  # type: ignore[assignment]
    last_name = None  # type: ignore[assignment]
    phone = PhoneField(blank=True, verbose_name=_("Phone number"), help_text=_("+[country code][number]x[extension]"))
    tfa_enabled = models.BooleanField(default=True, verbose_name=_("2FA enabled"))
    tfa_verified = models.BooleanField(default=False, verbose_name=_("2FA verified"))

    @property
    def tfa_required(self) -> bool:
        return self.tfa_enabled and not self.tfa_verified

    @property
    def totp_secret(self) -> str:
        cache_key = f"totp_{self.pk}"
        secret = cache.get(cache_key)
        if not secret:
            secret = pyotp.random_base32()
            cache.set(cache_key, secret, timeout=30 * 60)   # 30 minutes
        return secret

    def get_absolute_url(self) -> str:
        """Get URL for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"username": self.username})


@receiver(pre_save, sender=User)
def tfa_disable(sender, instance: User, **kwargs):
    if instance.is_staff or instance.is_superuser:
        # TODO: Reverse values if staff or superuser status are removed
        instance.tfa_enabled = False
        instance.tfa_verified = False
