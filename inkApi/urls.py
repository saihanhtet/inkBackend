from django.urls import path
from . import views

urlpatterns = [
    path('register', views.UserRegister.as_view(), name='register'),
    path('login', views.UserLogin.as_view(), name='login'),
    path('logout', views.UserLogout.as_view(), name='logout'),
    path('user/<int:pk>', views.UserView.as_view(), name='user'),
    path('user/me', views.SelfUserView.as_view(), name='self_user'),
    path('user', views.UserAllView.as_view(), name='users'),
    path('secretkey', views.SecretKeyView.as_view(), name='sercet_key'),
    path('check-token', views.check_token.as_view(), name='check_token'),
    # path('quote', views.QuoteGenerator.as_view(), name='quote_generator'),

    # school
    path('school', views.SchoolView.as_view(), name='school'),
    path('school/<int:pk>', views.SchoolDetailView.as_view(), name='school_detail'),

    # dashboard
    path('analysis', views.DashboardAnalysis.as_view(), name='analysis'),
    path('course', views.CourseView.as_view(), name='course'),
    path('course/<int:pk>', views.CourseDetailView.as_view(), name='course_detail'),
    path('subject', views.SubjectView.as_view(), name='subject'),
    path('subject/<int:pk>', views.SubjectDetailView.as_view(),
         name='subject_detail'),
]
