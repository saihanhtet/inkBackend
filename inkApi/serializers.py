from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate

from .models import Course, SecretKey, AdminProfile, Subject, TeacherProfile, StudentProfile

User = get_user_model()


class TeacherRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, clean_data):
        secret_key = clean_data['secret_key']

        if secret_key:
            user_obj = User.objects.create_staff(
                email=clean_data['email'],
                password=clean_data['password'],
                username=clean_data['username'],
                secret_key=secret_key
            )
            user_obj.save()
            return user_obj
        else:
            user_obj = User.objects.create_user(
                email=clean_data['email'],
                password=clean_data['password'],
                username=clean_data['username']
            )
        return user_obj


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def check_user(self, clean_data):
        email = clean_data['email']
        password = clean_data['password']
        user = authenticate(username=email, password=password)
        if not user:
            raise ValueError("User does not exist!")
        return user


class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminProfile
        fields = '__all__'


class TeacherProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeacherProfile
        fields = '__all__'


class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = '__all__'


class UserDetailSerializer(serializers.ModelSerializer):
    admin_profile = AdminProfileSerializer(
        source='adminprofile', read_only=True)
    teacher_profile = TeacherProfileSerializer(
        source='teacherprofile', read_only=True)
    student_profile = StudentProfileSerializer(
        source='studentprofile', read_only=True)

    class Meta:
        model = User
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        user_type = instance.user_type

        if user_type == User.ADMIN:
            data.pop('teacher_profile')
            data.pop('student_profile')
        elif user_type == User.TEACHER:
            data.pop('admin_profile')
            data.pop('student_profile')
        elif user_type == User.STUDENT:
            data.pop('admin_profile')
            data.pop('teacher_profile')

        return data


class SecretKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = SecretKey
        fields = ('__all__')


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ('id', 'course_name')

    def create(self, clean_data):
        course = Course.objects.create(
            course_name=clean_data['course_name']
        )
        return course

    def update(self, instance, validated_data):
        instance.course_name = validated_data.get(
            'course_name', instance.course_name)
        instance.save()
        return instance


class SubjectSerializer(serializers.ModelSerializer):
    course_name = serializers.SerializerMethodField()

    class Meta:
        model = Subject
        fields = ('id', 'subject_name', 'book_name', 'price', 'course_name')

    def create(self, validated_data):
        subject_name = validated_data['subject_name']
        book_name = validated_data['book_name']
        price = validated_data['price']
        course = Course.objects.get(id=validated_data['course'])
        subject = Subject.objects.create(
            subject_name=subject_name, book_name=book_name, price=price, course=course)
        return subject

    def get_course_name(self, obj):
        return obj.get_course_name()


class CohortSerializer(serializers.Serializer):
    cohort_name = serializers.CharField()
    course_name = serializers.CharField()
    student_count = serializers.IntegerField()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        extra_kwargs = {
            'email': {'validators': []},
        }

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class DashboardAnalysisSerializer(serializers.Serializer):
    total_students = serializers.IntegerField()
    total_users = serializers.IntegerField()
    total_courses = serializers.IntegerField()
    total_cohorts = serializers.IntegerField()
    cohorts_student_count = CohortSerializer(many=True)
    # current_user = UserSerializer()

    def create(self, validated_data):
        # This method is not needed for a serializer without a model
        pass

    def update(self, instance, validated_data):
        # This method is not needed for a serializer without a model
        pass
