import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
)
from rest_framework.test import APIClient, APITestCase

from trial.users.tests.factories import UserFactory

User = get_user_model()
client = APIClient()


class ApiTest(APITestCase):
    def setUp(self):
        # Objects
        self.user_1_pass = "1234qwerASDF!"
        self.user_1 = UserFactory(password=self.user_1_pass, phone="+1234567890")
        # # URLs
        self.url_login = reverse("users:login")
        self.url_jwt_refresh = reverse("users:jwt_refresh")
        self.url_jwt_verify = reverse("users:jwt_verify")
        self.url_totp = reverse("users:totp")

    def test_codes_unauthorized(self):
        """
        Test if all endpoints exist and return 400/401 errors when accessed unauthorized
        """
        client.logout()

        # login
        path = self.url_login
        self.assertEqual(path, "/api/users/login")
        res = client.get(path=path)
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)
        res = client.post(path=path, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)

        # jwt_refresh
        path = self.url_jwt_refresh
        self.assertEqual(path, "/api/users/jwt/refresh")
        res = client.post(path=path, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)

        # jwt_verify
        path = self.url_jwt_verify
        self.assertEqual(path, "/api/users/jwt/verify")
        res = client.post(path=path, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)

        # totp
        path = self.url_totp
        self.assertEqual(path, "/api/users/totp")
        res = client.get(path=path)
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)
        res = client.post(path=path, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)

    def test_authenticate(self):
        """
        Login
        """
        user = self.user_1
        # POST
        # Exception: wrong password
        data = {"username": user.username, "password": self.user_1_pass + "error"}
        res = client.post(path=self.url_login, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)

        # 2fa required
        data = {"username": user.username, "password": self.user_1_pass}
        res = client.post(path=self.url_login, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertIn("pre_2fa_user_id", client.session)
        self.assertNotIn("_auth_user_id", client.session)
        self.assertNotIn("tokens", res.data)
        self.assertEqual(res.data["tfa_required"], True)
        self.assertEqual(res.data["methods"], ["totp", "sms"])

        # 2fa not required
        User.objects.filter(pk=user.pk).update(tfa_verified=True)
        user.refresh_from_db()
        res = client.post(path=self.url_login, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertNotIn("pre_2fa_user_id", client.session)
        self.assertEqual(int(client.session["_auth_user_id"]), user.pk)
        self.assertGreater(len(res.data["tokens"]["access"]), 0)
        self.assertGreater(len(res.data["tokens"]["refresh"]), 0)
        access_token = res.data["tokens"]["access"]
        refresh_token = res.data["tokens"]["refresh"]

        # GET
        res = client.get(path=self.url_login, HTTP_AUTHORIZATION=f"Bearer {access_token}")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertEqual(res.data["username"], user.username)
        self.assertEqual(res.data["phone"], user.phone)
        self.assertTrue(res.data["tfa_enabled"] == user.tfa_enabled == True)
        self.assertTrue(res.data["tfa_verified"] == user.tfa_verified == True)

        """
        JWT verify
        """
        # POST
        # Exception: wrong token
        res = client.post(path=self.url_jwt_verify, data={"token": "wrong token"}, format="json")
        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)
        # Correct request
        res = client.post(path=self.url_jwt_verify, data={"token": access_token}, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertEqual(res.data, {})

        """
        JWT refresh
        """
        # Exception: wrong token
        res = client.post(path=self.url_jwt_refresh, data={"refresh": "wrong token"}, format="json")
        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)
        # POST
        res = client.post(path=self.url_jwt_refresh, data={"refresh": refresh_token}, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertNotEqual(res.data["access"], access_token)

    def test_totp(self):
        """
        Login
        """
        user = self.user_1
        # POST
        # 2fa required
        data = {"username": user.username, "password": self.user_1_pass}
        res = client.post(path=self.url_login, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertIn("pre_2fa_user_id", client.session)
        self.assertNotIn("_auth_user_id", client.session)
        self.assertNotIn("tokens", res.data)
        self.assertEqual(res.data["tfa_required"], True)
        self.assertEqual(res.data["methods"], ["totp", "sms"])

        """
        TOTP verification
        """
        # GET
        data = {"totp": user.totp_secret}
        res = client.get(path=self.url_totp, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertIn(user.totp_secret, res.data["totp_uri"])
        self.assertIn(cache.get(f"totp_{user.pk}"), res.data["totp_uri"])

        # POST
        valid_code = pyotp.TOTP(user.totp_secret).now()
        # Exception: wrong code
        data = {"code": int(valid_code) + 1}
        res = client.post(path=self.url_totp, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)
        # Correct request
        data = {"code": valid_code}
        res = client.post(path=self.url_totp, data=data, format="json")
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertGreater(len(res.data["tokens"]["access"]), 0)
        self.assertGreater(len(res.data["tokens"]["refresh"]), 0)
