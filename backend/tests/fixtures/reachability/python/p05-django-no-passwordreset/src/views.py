"""Django app that uses auth but NOT password reset.  PasswordResetForm
is never imported, so the CVE-2019-19844 path is unreachable."""
from django.contrib.auth import authenticate, login
from django.http import HttpResponse


def login_view(request):
    user = authenticate(
        request,
        username=request.POST.get("username"),
        password=request.POST.get("password"),
    )
    if user is None:
        return HttpResponse("bad credentials", status=401)
    login(request, user)
    return HttpResponse("ok")
