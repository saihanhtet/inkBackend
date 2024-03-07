from django.contrib import admin
from .models import *

admin.site.register(CustomUser)
admin.site.register(Course)
admin.site.register(Subject)
admin.site.register(Chapter)
admin.site.register(Cohort)
admin.site.register(SecretKey)
admin.site.register(AdminProfile)
admin.site.register(TeacherProfile)
admin.site.register(StudentProfile)
