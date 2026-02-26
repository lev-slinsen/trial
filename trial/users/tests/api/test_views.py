# import pytest
# from rest_framework.test import APIRequestFactory
#
# from trial.users.api.views import UserViewSet
# from django.contrib.auth import get_user_model
#
# User = get_user_model()
#
# class TestUserViewSet:
#     @pytest.fixture
#     def api_rf(self) -> APIRequestFactory:
#         return APIRequestFactory()
#
#     def test_get_queryset(self, user: User, api_rf: APIRequestFactory):
#         view = UserViewSet()
#         request = api_rf.get("/fake-url/")
#         request.user = user
#
#         view.request = request
#
#         assert user in view.get_queryset()
#
#     def test_me(self, user: User, api_rf: APIRequestFactory):
#         view = UserViewSet()
#         request = api_rf.get("/fake-url/")
#         request.user = user
#
#         view.request = request
#
#         response = view.me(request)  # type: ignore[call-arg, arg-type, misc]
#
#         assert response.data == {
#             "username": user.username,
#             "url": f"http://testserver/api/users/{user.username}/",
#             "name": user.name,
#         }
