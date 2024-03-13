from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate

from inkApi.models import Attendance, AttendanceReport, Course, FeedBackStudent, FeedBackTeacher, LeaveReportStudent, LeaveReportTeacher, NotificationStudent, NotificationTeacher, School, SecretKey, AdminProfile, Subject, TeacherProfile, StudentProfile

User = get_user_model()


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
                secret_key=secret_key,
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
        data.pop('password')
        if user_type == User.ADMIN:
            admin_profile_data = data.get('admin_profile', {})
            admin_profile_data.pop('user', None)
            data['profile'] = admin_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')
        elif user_type == User.TEACHER:
            teacher_profile_data = data.get('teacher_profile', {})
            teacher_profile_data.pop('user', None)
            data['profile'] = teacher_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')
        elif user_type == User.STUDENT:
            student_profile_data = data.get('student_profile', {})
            student_profile_data.pop('user', None)
            data['profile'] = student_profile_data
            data.pop('admin_profile')
            data.pop('teacher_profile')
            data.pop('student_profile')

        return data


class SecretKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = SecretKey
        fields = ('__all__')

    def create(self, validated_data):
        school_instance = self.get_first_school()
        validated_data['school'] = school_instance
        return super().create(validated_data)

    def get_first_school(self):
        """ Get the first school from database """
        school = School.objects.first()
        return school

    def get_school_from_user(self):
        """ Get the school from current request user """
        user = self.context['request'].user
        user_data = UserDetailSerializer(user)
        school_id = user_data.data['admin_profile']['school']
        school_instance = School.objects.get(school_id=school_id)
        return school_instance


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


class CourseWithStudentSerializer(serializers.Serializer):
    course = CourseSerializer(many=False, allow_null=True)
    students = serializers.JSONField()
    count = serializers.IntegerField()


class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = ('__all__')


class SubjectSerializer(serializers.ModelSerializer):

    class Meta:
        model = Subject
        fields = ('id', 'subject_name', 'book_name',
                  'price', 'course')

    def create(self, validated_data):
        subject_name = validated_data['subject_name']
        book_name = validated_data['book_name']
        price = validated_data['price']
        course = Course.objects.get(id=validated_data['course'])
        subject = Subject.objects.create(
            subject_name=subject_name, book_name=book_name, price=price, course=course)
        return subject


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


class SchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = School
        fields = ('__all__')

    def create(self, validated_data):
        all_schools = School.objects.all().count()
        if all_schools < 1:
            return super().create(validated_data)
        else:
            raise serializers.ValidationError(
                "Can't add another school. Only one school is allowed.")


class DashboardAnalysisSerializer(serializers.Serializer):
    total_students = serializers.IntegerField()
    total_users = serializers.IntegerField()
    total_courses = serializers.IntegerField()
    total_cohorts = serializers.IntegerField()
    cohorts_student_count = CohortSerializer(many=True, allow_null=True)
    school_data = SchoolSerializer(many=False, allow_null=True)
    course_data = CourseSerializer(many=True, allow_null=True)
    subject_data = SubjectSerializer(many=True, allow_null=True)
    course_student_pairs = CourseWithStudentSerializer(
        many=True, allow_null=True)
    # current_user = UserSerializer()


class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class AttendanceReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttendanceReport
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class LeaveReportStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveReportStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class LeaveReportTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaveReportTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class FeedBackStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBackStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class FeedBackTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeedBackTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class NotificationStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationStudent
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)


class NotificationTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationTeacher
        fields = ('__all__')

    def create(self, validated_data):
        return super().create(validated_data)
