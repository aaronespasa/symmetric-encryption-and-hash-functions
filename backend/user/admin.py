from django.contrib import admin
from .models import User, Password, Prescription

admin.site.register(User)
admin.site.register(Password)
admin.site.register(Prescription)
