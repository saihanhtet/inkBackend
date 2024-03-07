from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.db.models.signals import post_save
import secrets
from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser, PermissionsMixin, Permission, Group
from django.contrib.contenttypes.models import ContentType
# Create your models here.


class School(models.Model):
    school_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Course(models.Model):
    id = models.AutoField(primary_key=True)
    course_name = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.course_name


class Subject(models.Model):
    id = models.AutoField(primary_key=True)
    subject_name = models.CharField(max_length=255)
    book_name = models.CharField(max_length=255)
    price = models.IntegerField(default=0)

    course = models.ForeignKey(
        Course, on_delete=models.DO_NOTHING, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.subject_name

    def get_chapter(self):
        return self.chapter_set.count()

    def get_course_name(self):
        return self.course.course_name

    def get_price(self):
        return self.price


class Chapter(models.Model):
    id = models.AutoField(primary_key=True)
    chapter_name = models.CharField(max_length=255, blank=True, default='')
    chapter_number = models.PositiveIntegerField()
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.chapter_name

    def get_subject(self):
        return self.subject.subj_name


class Cohort(models.Model):
    id = models.AutoField(primary_key=True)
    cohort_name = models.CharField(max_length=255)

    course = models.ForeignKey(
        Course, on_delete=models.CASCADE, related_name='branches')

    session_start_date = models.DateField(null=True, blank=True)
    session_end_date = models.DateField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.cohort_name} - {self.course.course_name}"


class SecretKey(models.Model):
    TEACHER = 'teacher'
    ADMIN = 'admin'

    ROLE_CHOICES = [
        (TEACHER, 'Teacher'),
        (ADMIN, 'Admin'),
    ]
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=36, unique=True, null=True, blank=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.key} - {self.role}"

    def generate_random_key(self, length=15) -> str:
        ''' return random generated secret key based on the length'''
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"
        random_key = ''.join(secrets.choice(characters)
                             for _ in range(length))
        return random_key

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_random_key()
        super().save(*args, **kwargs)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """ Create and return a regular user with an email and password. """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        self.check_user(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_staff(self, email, password=None, **extra_fields):
        """ Create and return a staff user based on the provided secret key. """
        secret_key = extra_fields.get('secret_key')

        try:
            secret_key_obj = SecretKey.objects.get(
                key=secret_key, is_used=False)
        except SecretKey.DoesNotExist:
            raise ValueError('Invalid or used secret key.')

        role = secret_key_obj.role
        extra_fields.setdefault('is_staff', True)

        if role == SecretKey.TEACHER:
            extra_fields.setdefault('user_type', CustomUser.ADMIN)

        if role == SecretKey.ADMIN:
            extra_fields.setdefault('user_type', CustomUser.ADMIN)
            extra_fields.setdefault('is_superuser', True)

        secret_key_obj.is_used = True
        return self.create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('user_type', CustomUser.ADMIN)
        return self.create_user(email, password, **extra_fields)

    def check_user(self, email):
        user = not CustomUser.objects.filter(email=email).exists()
        return user


class CustomUser(AbstractUser, PermissionsMixin):
    STUDENT = 'student'
    TEACHER = 'teacher'
    ADMIN = 'admin'

    USER_TYPES = [
        (STUDENT, 'Student'),
        (TEACHER, 'Teacher'),
        (ADMIN, 'Admin'),
    ]

    id = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=50, unique=True)
    username = models.CharField(max_length=50)
    secret_key = models.CharField(null=True, blank=True, max_length=255)
    user_type = models.CharField(
        max_length=10, choices=USER_TYPES, default=STUDENT)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    objects = CustomUserManager()

    def __str__(self):
        return self.username


class AdminProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    school = models.ForeignKey(
        School, on_delete=models.CASCADE, null=True, blank=True, related_name='admin_profiles')

    def __str__(self):
        return f"{self.user.username}'s admin profile"


class TeacherProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    school = models.ForeignKey(
        School, on_delete=models.CASCADE, related_name='teacher_profiles', null=True, blank=True)

    def __str__(self):
        return f"{self.user.username}'s teacher profile"


class StudentProfile(models.Model):
    MALE = 'male'
    FEMALE = 'female'
    OTHER = 'other'
    SEX_TYPES = [
        (MALE, 'Male'),
        (FEMALE, 'Female'),
        (OTHER, 'Other')
    ]

    student_id = models.CharField(
        max_length=30, blank=True, default="", unique=True)
    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, primary_key=True)

    sex = models.CharField(max_length=10, choices=SEX_TYPES, default=OTHER)
    phone_number = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_pic = models.ImageField(
        upload_to='profile_pics/', null=True, blank=True)
    address = models.TextField(blank=True)

    guardian_name = models.CharField(max_length=255, blank=True)
    guardian_phone = models.CharField(max_length=30, blank=True)
    guardian_phone2 = models.CharField(max_length=30, blank=True)

    cohort = models.ForeignKey(
        Cohort, on_delete=models.DO_NOTHING, null=True, blank=True, related_name='students')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s student profile"

    def generate_student_id(self):
        last_student = StudentProfile.objects.filter().order_by('-student_id').first()

        if last_student:
            last_id = int(last_student.student_id.split('-')[-1])
        else:
            last_id = 0

        school_name = "lightecfa".upper()
        new_id = f'{school_name}-{last_id + 1:03d}'
        return new_id

    def save(self, *args, **kwargs):
        if not self.student_id:
            self.student_id = self.generate_student_id()
        super().save(*args, **kwargs)


def generate_permission() -> tuple:
    ''' return the permission of admin, teacher, student in order of tuple format '''
    all_permissions = Permission.objects.all()
    teacher_models = [Course, Subject, Chapter,
                      TeacherProfile]
    student_models = [StudentProfile]
    teacher_permissions = set()
    student_permissions = set()

    for model in teacher_models:
        content_type = ContentType.objects.get_for_model(model)
        permissions = Permission.objects.filter(content_type=content_type)
        teacher_permissions.update(permissions)

    for model in student_models:
        content_type = ContentType.objects.get_for_model(model)
        permissions = Permission.objects.filter(content_type=content_type)
        student_permissions.update(permissions)

    admin_group, _ = Group.objects.get_or_create(name='Admins')
    teacher_group, _ = Group.objects.get_or_create(name='Teachers')
    student_group, _ = Group.objects.get_or_create(name='Students')

    admin_group.permissions.set(all_permissions)
    teacher_group.permissions.set(teacher_permissions)
    student_group.permissions.set(student_permissions)

    return (all_permissions, teacher_permissions, student_permissions)


@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        generate_permission()
        if instance.user_type == CustomUser.ADMIN:
            AdminProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Admins'))
        elif instance.user_type == CustomUser.TEACHER:
            TeacherProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Teachers'))
        elif instance.user_type == CustomUser.STUDENT:
            StudentProfile.objects.create(user=instance)
            instance.groups.add(Group.objects.get(name='Students'))


@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    if instance.user_type == CustomUser.ADMIN:
        instance.adminprofile.save()
    if instance.user_type == CustomUser.TEACHER:
        instance.teacherprofile.save()
    if instance.user_type == CustomUser.STUDENT:
        instance.studentprofile.save()
