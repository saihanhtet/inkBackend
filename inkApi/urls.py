from django.urls import path
from . import views

urlpatterns = [
    path('register', views.UserRegister.as_view(), name='register'),
    path('login', views.UserLogin.as_view(), name='login'),
    path('logout', views.UserLogout.as_view(), name='logout'),
    path('user', views.UserView.as_view(), name='user'),
    path('secretkey', views.SecretKeyView.as_view(), name='sercet_key'),
    path('check-token', views.check_token.as_view(), name='check_token'),

    # dashboard
    path('analysis', views.DashboardAnalysis.as_view(), name='analysis'),
    path('course', views.CourseView.as_view(), name='course'),
    path('course/<int:pk>', views.CourseDetailView.as_view(), name='course-detail'),
    path('subject', views.SubjectView.as_view(), name='sibject'),
]
