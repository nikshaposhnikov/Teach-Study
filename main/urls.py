from django.urls import path
from .views import *

app_name = 'main'

urlpatterns = [
    # Users urls
    path('accounts/register/activate/<str:sign>/', user_activate, name='register_activate'),
    path('accounts/register/done/', RegisterDoneView.as_view(), name='register_done'),
    path('accounts/register/', RegisterUserView.as_view(), name='register'),
    path('accounts/logout/', BBLogoutView.as_view(), name='logout'),
    path('accounts/change_password/', BBPasswordChangeView.as_view(), name='password_change'),
    path('accounts/login', login_page, name='login'),
    path('accounts/change_comment/<int:group_pk>/<int:bb_pk>/<int:pk>/', comment_change, name='comment_change'),
    path('accounts/delete_comment/<int:group_pk>/<int:bb_pk>/<int:pk>/', comment_delete, name='comment_delete'),

    # Teacher functionality
    path('accounts/register/teacher/', RegisterTeacherView.as_view(), name='register_teacher'),
    path('accounts/profile/change/<int:pk>/', profile_bb_change, name='profile_bb_change'),
    path('accounts/profile/delete/<int:pk>/', profile_bb_delete, name='profile_bb_delete'),
    path('accounts/profile/add/', profile_bb_add, name='profile_bb_add'),
    path('accounts/profile/<int:pk>/', profile_bb_detail, name='profile_bb_detail'),
    path('accounts/profile/subject/<int:pk>/file/add/', profile_file_add, name='profile_file_add'),
    path('accounts/profile/subject/<int:pk>/', profile_sub_detail, name='profile_sub_detail'),

    path('accounts/profile/', profile, name='profile'),
    path('accounts/profile/subjects', teacher_subjects, name='teacher_subjects'),
    path('accounts/profile/change', ChangeUserInfoView.as_view(), name='profile_change'),
    path('accounts/profile/teacher_change', ChangeTeacherInfoView.as_view(), name='profile_teacher_change'),
    path('accounts/profile/delete', DeleteUserView.as_view(), name='profile_delete'),

    # General
    path('<int:group_pk>/<int:pk>/', detail, name='detail'),
    path('error_perm_teach/', error_perm_teach, name='error_perm_teach'),
    path('<int:pk>/', by_group, name='by_group'),
    path('<str:page>/', other_page, name='other'),
    path('', index, name='index'),


]