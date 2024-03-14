from django.core.exceptions import ObjectDoesNotExist
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from django.db.models import Count
from django.contrib.auth import get_user_model, login, logout
from rest_framework.views import APIView
from rest_framework.response import Response
from inkApi.serializers import AttendanceSerializer, CohortSerializer, CourseSerializer, CourseWithStudentSerializer, DashboardAnalysisSerializer, SchoolSerializer, SecretKeySerializer, StudentProfileSerializer, SubjectSerializer, UserRegisterSerializer, UserLoginSerializer, UserDetailSerializer
from rest_framework import permissions, status
from inkApi.validations import custom_validation, validate_email, validate_password
from inkApi.models import Attendance, Cohort, School, SecretKey, Course, StudentProfile, Subject
from rest_framework_simplejwt.authentication import JWTAuthentication as BaseJWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

UserModel = get_user_model()


class JWTAuthentication(BaseJWTAuthentication):
    """
    Custom JWT authentication class.
    This class extends the base JWTAuthentication provided by rest_framework_simplejwt.
    It adds support for checking access tokens stored in cookies if not found in the Authorization header.
    """

    def authenticate(self, request):
        # Check the Authorization header first
        header = self.get_header(request)
        if header is not None:
            raw_token = self.get_raw_token(header)
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
            return user, validated_token

        # If no token in the Authorization header, check cookies
        else:
            raw_token = request.COOKIES.get('access_token')
            if raw_token is not None:
                validated_token = self.get_validated_token(raw_token)
                user = self.get_user(validated_token)
                return user, validated_token

        return None


def generate_tokens(user):
    """
    Generate access and refresh tokens for a given user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class check_token(APIView):
    """
    Check access token from a user
    """
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """Check the token from request"""
        return Response({'data': {}, 'message': 'token alive'}, status=status.HTTP_200_OK)


class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        """ Check if the user making the request is a superuser"""
        return request.user and request.user.is_superuser


class IsTeacher(permissions.BasePermission):
    def has_permission(self, request, view):
        """ Check if the user making the request is a staff member"""
        return request.user and request.user.is_staff


def ResponseFunction(data, message, status):
    """ Default reponse function layout """
    return Response({'data': data, 'message': str(message)}, status=status)


def addCookies(response: Response, tokens):
    """ 
    Adding the cookies to our response header
    """
    # domain : .ink-backend.vercel.app | 127.0.0.1
    response.set_cookie(
        key='refresh_token',
        value=tokens['refresh'],
        httponly=os.getenv('HTTPONLY'),
        secure=True,
        samesite='None',
        domain=os.getenv('DOMAIN'),
        path='/',
    )
    response.set_cookie(
        key='access_token',
        value=tokens['access'],
        httponly=os.getenv('HTTPONLY'),
        secure=True,
        samesite='None',
        domain=os.getenv('DOMAIN'),
        path='/',
    )
    return response


class UserRegister(APIView):
    """
    View for user register.
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        """ User Register post method """
        clean_data = custom_validation(request.data)
        serializer = UserRegisterSerializer(data=clean_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.create(clean_data)
            serializer = UserDetailSerializer(user)
            if user:
                return ResponseFunction(serializer.data, "Successfully Registered", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    """
    View for user login.
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        """ User Login post method """
        data = request.data
        assert validate_email(data)
        assert validate_password(data)
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.check_user(data)
            login(request, user)
            tokens = generate_tokens(user)
            serializer = UserDetailSerializer(user)
            response = ResponseFunction(
                serializer.data, "Successfully Login", status.HTTP_200_OK)

            response = addCookies(response, tokens)
            return response


class UserLogout(APIView):
    """
    View for user logout.
    """
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request):
        """ User Logout method """
        logout(request)
        response = ResponseFunction(
            {}, "Successfully Logout", status.HTTP_200_OK)
        response.delete_cookie('refresh_token')
        response.delete_cookie('access_token')
        return response


class SelfUserView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        """ User Details get method """
        instance = UserModel.objects.get(username=request.user)
        serializer = UserDetailSerializer(instance)
        message = "Successfully retrieved user details."
        return Response({"data": serializer.data, "message": message}, status=status.HTTP_200_OK)


class UserView(RetrieveUpdateDestroyAPIView):
    """
    View for getting user details.
    """
    queryset = UserModel.objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        """ User Details get method """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        message = "Successfully retrieved user details."
        return Response({"data": serializer.data, "message": message}, status=status.HTTP_200_OK)


class UserAllView(APIView):
    """
    View for all user details
    """
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ All User Details get method """
        users = UserModel.objects.all()
        serializer = UserDetailSerializer(users, many=True)
        return ResponseFunction(serializer.data, "Successfully Got the Users", status.HTTP_200_OK)


class QuoteGenerator(APIView):
    """
    View for quote generate.
    """
    permission_classes = (permissions.AllowAny, )
    authentication_classes = ()

    def get(self, request):
        """ Get the random qute from rapidapi method """
        import requests
        url = "https://quotes15.p.rapidapi.com/quotes/random/"

        headers = {
            "X-RapidAPI-Key": os.get_env('RAPIDAPI'),
            "X-RapidAPI-Host": "quotes15.p.rapidapi.com"
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            quote = response.json()['content']
            data = {'quote': quote}

            return ResponseFunction(data, "Successfully Got the quote", status.HTTP_200_OK)


class SecretKeyView(APIView):
    """
    View for secret key.
    """
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the secret key """
        secret_keys = SecretKey.objects.all()
        serializer = SecretKeySerializer(secret_keys, many=True)

        return Response({'data': serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        """ Create new secret key """
        data = request.data
        serializer = SecretKeySerializer(
            data=data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            key = serializer.create(data)
            if key:
                secret_key = SecretKey.objects.order_by('-id').first()
                serializer = SecretKeySerializer(secret_key)
                return ResponseFunction(serializer.data, "Successfully created Secret Key", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class CourseDetailView(RetrieveUpdateDestroyAPIView):
    """
    View for course details view
    """
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = (permissions.IsAuthenticated, IsSuperuser,)
    authentication_classes = [JWTAuthentication]


class SubjectDetailView(RetrieveUpdateDestroyAPIView):
    """
    View for course details view
    """
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer
    permission_classes = (permissions.IsAuthenticated, IsSuperuser,)
    authentication_classes = [JWTAuthentication]


class SchoolDetailView(RetrieveUpdateDestroyAPIView):
    """
    View for school details view
    """
    queryset = School.objects.all()
    serializer_class = SchoolSerializer
    permission_classes = (permissions.IsAuthenticated, IsSuperuser,)
    authentication_classes = [JWTAuthentication]


class CourseView(APIView):
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the courses """
        courses = Course.objects.all()
        serializer = CourseSerializer(courses, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Courses", status.HTTP_200_OK)

    def post(self, request):
        """ Add new course """
        data = request.data
        serializer = CourseSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.create(data)
            return ResponseFunction(serializer.data, "Successfully created Course", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class CohortView(APIView):
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the courses """
        cohort = Cohort.objects.all()
        serializer = CohortSerializer(cohort, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Cohort", status.HTTP_200_OK)

    def post(self, request):
        """ Add new course """
        data = request.data
        serializer = CohortSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.create(data)
            return ResponseFunction(serializer.data, "Successfully created Cohort", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class SubjectView(APIView):
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the subjects """
        subjects = Subject.objects.all()
        serializer = SubjectSerializer(subjects, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Subject", status.HTTP_200_OK)

    def post(self, request):
        """ Add new subject """
        data = request.data
        serializer = SubjectSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.create(data)
            return ResponseFunction(serializer.data, "Successfully created Subject", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class StudentView(APIView):
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the subjects """
        users = UserModel.objects.filter(user_type='student')
        serializer = UserDetailSerializer(users, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Students", status.HTTP_200_OK)

    def post(self, request):
        """ Add new subject """
        data = request.data
        serializer = StudentProfileSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.create(data)
            return ResponseFunction(serializer.data, "Successfully created Student", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class AttendanceView(APIView):
    permission_classes = (permissions.IsAuthenticated,
                          IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        """ Get all the Attendance data """
        attendance_data = Attendance.objects.all()
        serializer = AttendanceSerializer(attendance_data, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Attendance", status.HTTP_200_OK)

    def post(self, request):
        pass


class SchoolView(APIView):
    permission_classes = (permissions.AllowAny, )
    authentication_classes = ()

    def get(self, request):
        """ Get the school details """
        school = School.objects.all()
        serializer = SchoolSerializer(school, many=True)
        return ResponseFunction(serializer.data, "Successfully retrieved School", status.HTTP_200_OK)

    def post(self, request):
        """ Create a school for the first time """
        data = request.data
        serializer = SchoolSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.create(data)
            return ResponseFunction(serializer.data, "Successfully created School", status.HTTP_201_CREATED)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class DashboardAnalysis(APIView):
    permission_classes = (permissions.IsAuthenticated, IsSuperuser,)
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        students = StudentProfile.objects.all()
        users = UserModel.objects.all()
        courses = Course.objects.all()
        cohorts = Cohort.objects.all()
        school = School.objects.all()
        subjects = Subject.objects.all()

        # Initialize data variables
        course_data = []

        subject_data = [SubjectSerializer(
            subj).data for subj in subjects] if subjects.exists() else []

        cohort_data = [CohortSerializer(
            cohort).data for cohort in cohorts] if cohorts.exists() else []

        cohorts_student_count = []
        course_student_pairs = []

        for course in courses:
            try:
                students_obj = StudentProfile.objects.filter(
                    cohort__course=course)
                # Append serialized course data
                course_data.append(CourseSerializer(course).data)
                students_data = StudentProfileSerializer(
                    students_obj, many=True).data
                course_student_pairs.append({
                    'course': CourseSerializer(course).data,
                    'students': students_data,
                    'count': students.count()
                })
            except ObjectDoesNotExist:
                print("Students not found for course:", course)

        if school.exists():
            school_data = SchoolSerializer(school.first(), many=False).data

        if cohorts.exists():
            cohorts_with_student_count = Cohort.objects.annotate(
                student_count=Count('students')
            ).select_related('course')

            cohorts_student_count = [
                {
                    'cohort_name': cohort.cohort_name,
                    'course_name': cohort.course.course_name if cohort.course else "",
                    'student_count': cohort.student_count
                }
                for cohort in cohorts_with_student_count
            ]

        # Serialize data
        serializer = DashboardAnalysisSerializer(data={
            'total_students': students.count(),
            'total_users': users.count(),
            'total_courses': courses.count(),
            'total_cohorts': cohorts.count(),
            'cohorts_student_count': cohorts_student_count,
            'cohort_data': cohort_data,
            'school_data': school_data,
            'course_data': course_data,
            'subject_data': subject_data,
            'course_student_pairs': course_student_pairs
        }, allow_null=True)

        # Validate serializer and return response
        serializer.is_valid(raise_exception=True)
        return ResponseFunction(serializer.data, "Successfully retrieved Analysis data", status.HTTP_200_OK)
