from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, JsonResponse
from django.urls import include, path


def password_login(request):
    user = authenticate(
        request, username=request.POST.get("username"), password=request.POST.get("password")
    )
    if not user:
        return JsonResponse({"success": False}, status=400)
    login(request, user)
    response = JsonResponse({"success": True, "redirect_url": "/dashboard"})
    response.set_cookie("edx-jwt-cookie-header-payload", "first-factor-token")
    return response


def sign_out(request):
    logout(request)
    return HttpResponse("logged out")


urlpatterns = [
    path("favicon.ico", lambda request: HttpResponse("icon", content_type="image/x-icon")),
    path("", include("openedx_two_factor.plugin_urls")),
    path("login_ajax", password_login),
    path("logout", sign_out),
    path("dashboard", lambda request: HttpResponse("protected")),
    path("api/protected/", lambda request: HttpResponse("protected")),
    path("oauth2/access_token", lambda request: HttpResponse("token")),
    path("admin/", lambda request: HttpResponse("admin")),
]
