"""Reachable use of the vulnerable PasswordResetForm path."""
from django.contrib.auth.forms import PasswordResetForm
from django.http import HttpResponse


def password_reset(request):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            # PasswordResetForm.save() internally calls get_users() — this
            # is the actual fix path for CVE-2019-19844.
            form.save(
                request=request,
                use_https=True,
                email_template_name="registration/password_reset_email.html",
            )
            return HttpResponse("reset email sent")
    return HttpResponse("provide email", status=400)
