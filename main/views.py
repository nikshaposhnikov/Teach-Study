from django.core.paginator import Paginator
from django.db.models import Q
from django.core.signing import BadSignature
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.template import TemplateDoesNotExist
from django.template.loader import get_template
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.views import LoginView, LogoutView, PasswordResetView, PasswordChangeView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib import messages
from django.views.generic import UpdateView, CreateView, TemplateView, DeleteView
from django.contrib.messages.views import SuccessMessageMixin
from django.urls import reverse_lazy
from django.views.generic.edit import FormView
from django.utils.decorators import method_decorator
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
)
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_protect

from .utilities import signer
from .forms import *
from .decorators import user_required, teacher_required, user_is_entry_author, student_required, user_is_entry_to_group

'''
Details about the selected bb
'''


@user_required
def detail(request, group_pk, pk):
    bb = get_object_or_404(Bb, pk=pk)
    ais = bb.additionalimage_set.all()
    comments = Comment.objects.filter(bb=pk, is_active=True)
    initial = {'bb': bb.pk}
    if request.user.is_authenticated:
        initial['author'] = request.user.pk
        form_class = UserCommentForm
    form = form_class(initial=initial)
    if request.method == 'POST':
        c_form = form_class(request.POST)
        if c_form.is_valid():
            c_form.save()
            messages.add_message(request, messages.SUCCESS, 'Коментар додано')
            return redirect('main:detail', group_pk, pk)
        else:
            form = c_form
            messages.add_message(request, messages.WARNING, 'Комаентар не додано')
    context = {'bb': bb, 'ais': ais, 'comments': comments, 'form': form}
    return render(request, 'main/detail.html', context)


'''
Search bbs 
'''


@user_required
@teacher_required
def by_group(request, pk):
    group = get_object_or_404(SubGroup, pk=pk)
    bbs = Bb.objects.filter(is_active=True, group=pk)
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        q = Q(title__icontains=keyword) | Q(content__icontains=keyword) | Q(author__middle_name__icontains=keyword) | \
            Q(author__first_name__icontains=keyword) | \
            Q(author__last_name__icontains=keyword)
        bbs = bbs.filter(q)
    else:
        keyword = ''
    form = SearchForm(initial={'keyword': keyword})
    paginator = Paginator(bbs, 5)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'group': group, 'page': page, 'bbs': page.object_list, 'form': form}
    return render(request, 'main/by_group.html', context)


class DeleteUserView(LoginRequiredMixin, DeleteView):
    model = AdvUser
    template_name = 'main/delete_user.html'
    success_url = reverse_lazy('main:index')

    def dispatch(self, request, *args, **kwargs):
        comments = Comment.objects.filter(author=request.user.pk)
        comments.delete()
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Користувача видалено')
        return super().post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class DeleteTeacherView(LoginRequiredMixin, DeleteView):
    model = Teacher
    template_name = 'main/delete_teacher.html'
    success_url = reverse_lazy('main:index')

    def dispatch(self, request, *args, **kwargs):
        comments = Comment.objects.filter(author=request.user.pk)
        comments.delete()
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Користувача видалено')
        return super().post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


def user_activate(request, sign):
    try:
        email = signer.unsign(sign)
    except BadSignature:
        return render(request, 'main/bad_signature.html')
    user = get_object_or_404(AdvUser, email=email)
    if user.is_activated:
        template = 'main/user_is_activated.html'
    else:
        template = 'main/activation_done.html'
        user.is_active = True
        user.is_activated = True
        user.save()
    return render(request, template)


class RegisterDoneView(TemplateView):
    template_name = 'main/register_done.html'


class RegisterTeacherDoneView(TemplateView):
    template_name = 'main/register_teacher_done.html'


class RegisterUserView(CreateView):
    model = AdvUser
    template_name = 'main/register_user.html'
    form_class = RegisterUserForm
    success_url = reverse_lazy('main:register_done')


class RegisterTeacherView(CreateView):
    model = AdvUser
    template_name = 'main/teacher_register.html'
    form_class = RegisterTeacherForm
    success_url = reverse_lazy('main:register_teacher_done')


class BBPasswordResetView(PasswordResetView):
    template_name = 'main/password_reset.html'
    success_url = reverse_lazy('main:reset_password_done')
    success_message = 'Лист надіслано на пошту'


class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'title': self.title,
            **(self.extra_context or {})
        })
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('main:change_password_done')
    template_name = 'main/password_change.html'
    title = _('Password change')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class ChangeTeacherInfoView(SuccessMessageMixin, LoginRequiredMixin, UpdateView):
    model = Teacher
    template_name = 'main/change_user_info.html'
    form_class = ChangeTeacherInfoForm
    success_url = reverse_lazy('main:profile')
    success_message = 'Особисті дані змінені'

    def dispatch(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class ChangeUserInfoView(SuccessMessageMixin, LoginRequiredMixin, UpdateView):
    model = AdvUser
    template_name = 'main/change_user_info.html'
    form_class = ChangeUserInfoForm
    success_url = reverse_lazy('main:student_profile')
    success_message = 'Особисті дані змінені'

    def dispatch(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class BBLogoutView(LoginRequiredMixin, LogoutView):
    template_name = 'main/logout.html'


@user_required
@user_is_entry_author
def comment_delete(request, group_pk, bb_pk, pk):
    comment = get_object_or_404(Comment, pk=pk)
    if request.method == 'POST':
        comment.delete()
        messages.add_message(request, messages.SUCCESS, 'Коментар видалено')
        return redirect('main:detail', group_pk, bb_pk)
    else:
        context = {'comment': comment}
        return render(request, 'main/comment_delete.html', context)


@user_required
@user_is_entry_author
def comment_change(request, group_pk, bb_pk, pk):
    comment = get_object_or_404(Comment, pk=pk)
    if request.method == 'POST':
        form = UserCommentForm(request.POST, instance=comment)
        if form.is_valid():
            comment = form.save()
            messages.add_message(request, messages.SUCCESS, 'Коментар виправлено')
            return redirect('main:detail', group_pk, bb_pk)
    else:
        form = UserCommentForm(instance=comment)
    context = {'comment': comment, 'form': form}
    return render(request, 'main/comment_change.html', context)


@user_required
@teacher_required
def profile_bb_delete(request, pk):
    bb = get_object_or_404(Bb, pk=pk)
    if request.method == 'POST':
        bb.delete()
        messages.add_message(request, messages.SUCCESS, 'Оголошення видалено')
        return redirect('main:profile')
    else:
        context = {'bb': bb}
        return render(request, 'main/profile_bb_delete.html', context)


@user_required
@teacher_required
def profile_bb_change(request, pk):
    bb = get_object_or_404(Bb, pk=pk)
    if request.method == 'POST':
        form = BbForm(request.POST, request.FILES, instance=bb)
        if form.is_valid():
            bb = form.save()
            formset = AIFormSet(request.POST, request.FILES, instance=bb)
            if formset.is_valid():
                formset.save()
                messages.add_message(request, messages.SUCCESS, 'Оголошення виправлено')
                return redirect('main:profile')
    else:
        form = BbForm(instance=bb)
        formset = AIFormSet(instance=bb)
    context = {'bb': bb, 'form': form, 'formset': formset}
    return render(request, 'main/profile_bb_change.html', context)


@user_required
@teacher_required
def profile_bb_add(request):
    if request.method == 'POST':
        form = BbForm(request.POST, request.FILES)
        if form.is_valid():
            bb = form.save()
            formset = AIFormSet(request.POST, request.FILES, instance=bb)
            if formset.is_valid():
                formset.save()
                messages.add_message(request, messages.SUCCESS, 'Оголошення додано')
                return redirect('main:profile')
    else:
        form = BbForm(initial={'author': request.user.pk})
        formset = AIFormSet()
    context = {'form': form, 'formset': formset}
    return render(request, 'main/profile_bb_add.html', context)


@user_required
@teacher_required
def profile_file_add(request, pk):
    sub = get_object_or_404(Subject, pk=pk)
    if request.method == 'POST':
        formset = AIFormFileSet(request.POST, request.FILES, instance=sub)
        if formset.is_valid():
            formset.save()
            messages.add_message(request, messages.SUCCESS, 'Матеріал змінений')
            return redirect('main:profile_sub_detail', sub.pk)
    else:
        formset = AIFormFileSet(instance=sub)
    context = {'formset': formset, 'sub': sub}
    return render(request, 'main/profile_file_add.html', context)


@user_required
def profile_sub_detail(request, pk):
    sub = get_object_or_404(Subject, pk=pk)
    ais = sub.additionalfile_set.all()
    context = {'sub': sub, 'ais': ais}
    return render(request, 'main/profile_sub_detail.html', context)


@user_required
@student_required
def student_sub_detail(request, pk):
    sub = get_object_or_404(Subject, pk=pk)
    sh = get_object_or_404(Schedule, group=request.user.group.pk)
    shs = AdditionalSchedule.objects.filter(schedule=sh, subject=sub)
    name_for_teacher = []
    for sh in shs:
        if sh not in name_for_teacher:
            name_for_teacher.append(sh.teacher.full_name())
    length_name_for_teach = len(name_for_teacher)
    ais = sub.additionalfile_set.all()
    context = {'sub': sub, 'ais': ais, 'name_for_teacher': name_for_teacher,
               'length_name_for_teach': length_name_for_teach}
    return render(request, 'main/profile_sub_detail.html', context)


@user_required
@user_is_entry_to_group
def profile_bb_detail(request, pk):
    bb = get_object_or_404(Bb, pk=pk)
    ais = bb.additionalimage_set.all()
    comments = Comment.objects.filter(bb=pk, is_active=True)
    initial = {'bb': bb.pk}
    if request.user.is_authenticated:
        initial['author'] = request.user.pk
        form_class = UserCommentForm
    else:
        form_class = UserCommentForm
    form = form_class(initial=initial)
    if request.method == 'POST':
        c_form = form_class(request.POST)
        if c_form.is_valid():
            c_form.save()
            messages.add_message(request, messages.SUCCESS, 'Коментар добавлено')
            return redirect('main:profile_bb_detail', pk)
        else:
            form = c_form
            messages.add_message(request, messages.WARNING, 'Коментар не добавлено')
    context = {'bb': bb, 'ais': ais, 'comments': comments, 'form': form}
    return render(request, 'main/profile_bb_detail.html', context)


@user_required
@student_required
def student_profile(request):
    bbs = Bb.objects.filter(group=request.user.group.pk)
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        q = Q(title__icontains=keyword) | Q(content__icontains=keyword) | Q(author__middle_name__icontains=keyword) | \
            Q(author__first_name__icontains=keyword) | \
            Q(author__last_name__icontains=keyword)
        bbs = bbs.filter(q)
    else:
        keyword = ''
    form = SearchForm(initial={'keyword': keyword})
    paginator = Paginator(bbs, 8)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'page': page, 'bbs': page.object_list, 'form': form}
    return render(request, 'main/profile.html', context)


@user_required
@teacher_required
def profile(request):
    bbs = Bb.objects.filter(author=request.user.pk)
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        q = Q(title__icontains=keyword) | Q(content__icontains=keyword) | Q(author__middle_name__icontains=keyword) | \
            Q(author__first_name__icontains=keyword) | \
            Q(author__last_name__icontains=keyword)
        bbs = bbs.filter(q)
    else:
        keyword = ''
    form = SearchForm(initial={'keyword': keyword})
    paginator = Paginator(bbs, 5)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'page': page, 'bbs': page.object_list, 'form': form}
    return render(request, 'main/profile.html', context)


def list_schedule(request):
    shs = Schedule.objects.all()
    context = {'shs': shs, }
    return render(request, 'main/schedule.html', context)


def detail_schedule(request, pk):
    sh = get_object_or_404(Schedule, pk=pk)
    ais = sh.additionalschedule_set.all()
    sbs_monday = AdditionalSchedule.objects.filter(schedule=pk, day='0').order_by('day',
                                                                                  'start_time')
    sbs_tuesday = AdditionalSchedule.objects.filter(schedule=pk, day='1').order_by('day',
                                                                                   'start_time')
    sbs_wednesday = AdditionalSchedule.objects.filter(schedule=pk, day='2').order_by('day',
                                                                                     'start_time')
    sbs_thursday = AdditionalSchedule.objects.filter(schedule=pk, day='3').order_by('day',
                                                                                    'start_time')

    sbs_friday = AdditionalSchedule.objects.filter(schedule=pk, day='4').order_by('day',
                                                                                  'start_time')
    sbs_saturday = AdditionalSchedule.objects.filter(schedule=pk, day='5').order_by('day',
                                                                                    'start_time')

    '''
   ALL LESSONS IN MONDAY
    '''
    first_lessonM = []
    second_lessonM = []
    third_lessonM = []
    fourth_lessonM = []
    fifth_lessonM = []
    sixth_lessonM = []
    schedule_monday = []
    for sb in sbs_monday:
        if sb not in schedule_monday:
            schedule_monday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_monday:
        if items[0] == '08:30:00':
            first_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '10:25:00':
            second_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '12:35:00':
            third_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '14:30:00':
            fourth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '16:25:00':
            fifth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '18:10:00':
            sixth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

    '''
      ALL LESSONS IN TUESDAY
    '''
    first_lessonTU = []
    second_lessonTU = []
    third_lessonTU = []
    fourth_lessonTU = []
    fifth_lessonTU = []
    sixth_lessonTU = []
    schedule_tuesday = []
    for sb in sbs_tuesday:
        if sb not in schedule_tuesday:
            schedule_tuesday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_tuesday:
        if items[0] == '08:30:00':
            first_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '10:25:00':
            second_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '12:35:00':
            third_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '14:30:00':
            fourth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '16:25:00':
            fifth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '18:10:00':
            sixth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
          ALL LESSONS IN WEDNESDAY
        '''
    first_lessonW = []
    second_lessonW = []
    third_lessonW = []
    fourth_lessonW = []
    fifth_lessonW = []
    sixth_lessonW = []
    schedule_wednesday = []
    for sb in sbs_wednesday:
        if sb not in schedule_wednesday:
            schedule_wednesday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_wednesday:
        if items[0] == '08:30:00':
            first_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '10:25:00':
            second_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '12:35:00':
            third_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '14:30:00':
            fourth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '16:25:00':
            fifth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '18:10:00':
            sixth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
             ALL LESSONS IN THURSDAY
        '''
    first_lessonTH = []
    second_lessonTH = []
    third_lessonTH = []
    fourth_lessonTH = []
    fifth_lessonTH = []
    sixth_lessonTH = []
    schedule_thursday = []
    for sb in sbs_thursday:
        if sb not in schedule_thursday:
            schedule_thursday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_thursday:
        if items[0] == '08:30:00':
            first_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '10:25:00':
            second_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '12:35:00':
            third_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '14:30:00':
            fourth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '16:25:00':
            fifth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '18:10:00':
            sixth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
             ALL LESSONS IN FRIDAY
        '''
    first_lessonF = []
    second_lessonF = []
    third_lessonF = []
    fourth_lessonF = []
    fifth_lessonF = []
    sixth_lessonF = []
    schedule_friday = []
    for sb in sbs_friday:
        if sb not in schedule_friday:
            schedule_friday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_friday:
        if items[0] == '08:30:00':
            first_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '10:25:00':
            second_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '12:35:00':
            third_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '14:30:00':
            fourth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '16:25:00':
            fifth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '18:10:00':
            sixth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

            '''
                 ALL LESSONS IN SATURDAY
            '''
    first_lessonS = []
    second_lessonS = []
    third_lessonS = []
    fourth_lessonS = []
    fifth_lessonS = []
    sixth_lessonS = []
    schedule_saturday = []
    for sb in sbs_saturday:
        if sb not in schedule_saturday:
            schedule_saturday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_saturday:
        if items[0] == '08:30:00':
            first_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '10:25:00':
            second_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '12:35:00':
            third_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '14:30:00':
            fourth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '16:25:00':
            fifth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '18:10:00':
            sixth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

    context = {'sh': sh, 'ais': ais,
               'sbs_monday': sbs_monday, 'first_lesson': first_lessonM, 'second_lesson': second_lessonM,
               'third_lesson': third_lessonM, 'fourth_lesson': fourth_lessonM, 'fifth_lesson': fifth_lessonM,
               'sixth_lesson': sixth_lessonM,
               'sbs_tuesday': sbs_tuesday, 'first_lessonTU': first_lessonTU, 'second_lessonTU': second_lessonTU,
               'third_lessonTU': third_lessonTU, 'fourth_lessonTU': fourth_lessonTU, 'fifth_lessonTU': fifth_lessonTU,
               'sixth_lessonTU': sixth_lessonTU,
               'sbs_wednesday': sbs_wednesday, 'first_lessonW': first_lessonW, 'second_lessonW': second_lessonW,
               'third_lessonW': third_lessonW, 'fourth_lessonW': fourth_lessonW, 'fifth_lessonW': fifth_lessonW,
               'sixth_lessonW': sixth_lessonW,
               'sbs_thursday': sbs_thursday, 'first_lessonTH': first_lessonTH, 'second_lessonTH': second_lessonTH,
               'third_lessonTH': third_lessonTH, 'fourth_lessonTH': fourth_lessonTH, 'fifth_lessonTH': fifth_lessonTH,
               'sixth_lessonTH': sixth_lessonTH,
               'sbs_friday': sbs_friday, 'first_lessonF': first_lessonF, 'second_lessonF': second_lessonF,
               'third_lessonF': third_lessonF, 'fourth_lessonF': fourth_lessonF, 'fifth_lessonF': fifth_lessonF,
               'sixth_lessonF': sixth_lessonF,
               'sbs_saturday': sbs_saturday, 'first_lessonS': first_lessonS, 'second_lessonS': second_lessonS,
               'third_lessonS': third_lessonS, 'fourth_lessonS': fourth_lessonS, 'fifth_lessonS': fifth_lessonS,
               'sixth_lessonS': sixth_lessonS}
    return render(request, 'main/detail_schedule.html', context)


@user_required
@student_required
def student_schedule(request):
    sbs = AdditionalSchedule.objects.filter(schedule__group=request.user.group).order_by('day', 'start_time')

    sbs_monday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='0').order_by('day',
                                                                                                         'start_time')
    sbs_tuesday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='1').order_by('day',
                                                                                                          'start_time')
    sbs_wednesday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='2').order_by('day',
                                                                                                            'start_time')
    sbs_thursday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='3').order_by('day',
                                                                                                           'start_time')

    sbs_friday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='4').order_by('day',
                                                                                                         'start_time')
    sbs_saturday = AdditionalSchedule.objects.filter(schedule__group=request.user.group, day='5').order_by('day',
                                                                                                           'start_time')

    '''
       ALL LESSONS IN MONDAY
        '''
    first_lessonM = []
    second_lessonM = []
    third_lessonM = []
    fourth_lessonM = []
    fifth_lessonM = []
    sixth_lessonM = []
    schedule_monday = []
    for sb in sbs_monday:
        if sb not in schedule_monday:
            schedule_monday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_monday:
        if items[0] == '08:30:00':
            first_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '10:25:00':
            second_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '12:35:00':
            third_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '14:30:00':
            fourth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '16:25:00':
            fifth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_monday:
        if items[0] == '18:10:00':
            sixth_lessonM.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

    '''
      ALL LESSONS IN TUESDAY
    '''
    first_lessonTU = []
    second_lessonTU = []
    third_lessonTU = []
    fourth_lessonTU = []
    fifth_lessonTU = []
    sixth_lessonTU = []
    schedule_tuesday = []
    for sb in sbs_tuesday:
        if sb not in schedule_tuesday:
            schedule_tuesday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_tuesday:
        if items[0] == '08:30:00':
            first_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '10:25:00':
            second_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '12:35:00':
            third_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '14:30:00':
            fourth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '16:25:00':
            fifth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_tuesday:
        if items[0] == '18:10:00':
            sixth_lessonTU.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
          ALL LESSONS IN WEDNESDAY
        '''
    first_lessonW = []
    second_lessonW = []
    third_lessonW = []
    fourth_lessonW = []
    fifth_lessonW = []
    sixth_lessonW = []
    schedule_wednesday = []
    for sb in sbs_wednesday:
        if sb not in schedule_wednesday:
            schedule_wednesday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_wednesday:
        if items[0] == '08:30:00':
            first_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '10:25:00':
            second_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '12:35:00':
            third_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '14:30:00':
            fourth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '16:25:00':
            fifth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_wednesday:
        if items[0] == '18:10:00':
            sixth_lessonW.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
             ALL LESSONS IN THURSDAY
        '''
    first_lessonTH = []
    second_lessonTH = []
    third_lessonTH = []
    fourth_lessonTH = []
    fifth_lessonTH = []
    sixth_lessonTH = []
    schedule_thursday = []
    for sb in sbs_thursday:
        if sb not in schedule_thursday:
            schedule_thursday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_thursday:
        if items[0] == '08:30:00':
            first_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '10:25:00':
            second_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '12:35:00':
            third_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '14:30:00':
            fourth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '16:25:00':
            fifth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_thursday:
        if items[0] == '18:10:00':
            sixth_lessonTH.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

        '''
             ALL LESSONS IN FRIDAY
        '''
    first_lessonF = []
    second_lessonF = []
    third_lessonF = []
    fourth_lessonF = []
    fifth_lessonF = []
    sixth_lessonF = []
    schedule_friday = []
    for sb in sbs_friday:
        if sb not in schedule_friday:
            schedule_friday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_friday:
        if items[0] == '08:30:00':
            first_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '10:25:00':
            second_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '12:35:00':
            third_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '14:30:00':
            fourth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '16:25:00':
            fifth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_friday:
        if items[0] == '18:10:00':
            sixth_lessonF.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

            '''
                 ALL LESSONS IN SATURDAY
            '''
    first_lessonS = []
    second_lessonS = []
    third_lessonS = []
    fourth_lessonS = []
    fifth_lessonS = []
    sixth_lessonS = []
    schedule_saturday = []
    for sb in sbs_saturday:
        if sb not in schedule_saturday:
            schedule_saturday.append(
                [sb.start_time, sb.subject.name_of_subject, sb.teacher.last_name,
                 sb.teacher.first_name,
                 sb.teacher.middle_name, sb.structure.structure_name, sb.auditory.auditory_number])
    for items in schedule_saturday:
        if items[0] == '08:30:00':
            first_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '10:25:00':
            second_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '12:35:00':
            third_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '14:30:00':
            fourth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '16:25:00':
            fifth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])
    for items in schedule_saturday:
        if items[0] == '18:10:00':
            sixth_lessonS.append(
                [items[0], items[1], items[2],
                 items[3],
                 items[4], items[5], items[6]])

    context = {'sbs': sbs, 'sbs_monday': sbs_monday, 'first_lesson': first_lessonM, 'second_lesson': second_lessonM,
               'third_lesson': third_lessonM, 'fourth_lesson': fourth_lessonM, 'fifth_lesson': fifth_lessonM,
               'sixth_lesson': sixth_lessonM,
               'sbs_tuesday': sbs_tuesday, 'first_lessonTU': first_lessonTU, 'second_lessonTU': second_lessonTU,
               'third_lessonTU': third_lessonTU, 'fourth_lessonTU': fourth_lessonTU, 'fifth_lessonTU': fifth_lessonTU,
               'sixth_lessonTU': sixth_lessonTU,
               'sbs_wednesday': sbs_wednesday, 'first_lessonW': first_lessonW, 'second_lessonW': second_lessonW,
               'third_lessonW': third_lessonW, 'fourth_lessonW': fourth_lessonW, 'fifth_lessonW': fifth_lessonW,
               'sixth_lessonW': sixth_lessonW,
               'sbs_thursday': sbs_thursday, 'first_lessonTH': first_lessonTH, 'second_lessonTH': second_lessonTH,
               'third_lessonTH': third_lessonTH, 'fourth_lessonTH': fourth_lessonTH, 'fifth_lessonTH': fifth_lessonTH,
               'sixth_lessonTH': sixth_lessonTH,
               'sbs_friday': sbs_friday, 'first_lessonF': first_lessonF, 'second_lessonF': second_lessonF,
               'third_lessonF': third_lessonF, 'fourth_lessonF': fourth_lessonF, 'fifth_lessonF': fifth_lessonF,
               'sixth_lessonF': sixth_lessonF,
               'sbs_saturday': sbs_saturday, 'first_lessonS': first_lessonS, 'second_lessonS': second_lessonS,
               'third_lessonS': third_lessonS, 'fourth_lessonS': fourth_lessonS, 'fifth_lessonS': fifth_lessonS,
               'sixth_lessonS': sixth_lessonS}
    return render(request, 'main/schedule.html', context)


@user_required
@student_required
def student_subjects(request):
    sbs_only = []
    sbs = AdditionalSchedule.objects.filter(schedule__group=request.user.group)
    for sb in sbs:
        if sb not in sbs_only:
            sbs_only.append([sb.subject.name_of_subject, int(sb.subject.pk), ])
    sbs_unique = []
    for elem in sbs_only:
        if elem not in sbs_unique:
            sbs_unique.append(elem)
    sbs_only = sbs_unique
    paginator = Paginator(sbs_only, 8)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'page': page, 'sbs_only': page.object_list}
    return render(request, 'main/subjects.html', context)


@user_required
@teacher_required
def teacher_subjects(request):
    sbs_only = []
    sbs = AdditionalSchedule.objects.filter(teacher=request.user.pk).order_by('subject')
    for sb in sbs:
        if sb not in sbs_only:
            sbs_only.append([sb.subject.name_of_subject, int(sb.subject.pk)])
    sbs_unique = []
    for elem in sbs_only:
        if elem not in sbs_unique:
            sbs_unique.append(elem)
    sbs_only = sbs_unique

    paginator = Paginator(sbs_only, 8)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'page': page, 'sbs_only': page.object_list}
    return render(request, 'main/subjects.html', context)


def login_page(request):
    form = LoginForm
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None and user.is_teacher:
            login(request, user)
            return redirect('main:teacher_subjects')
        elif user is not None and user.is_superuser:
            login(request, user)
            return HttpResponseRedirect('../../admin/')
        elif user is not None:
            login(request, user)
            return redirect('main:student_profile')
        else:
            messages.info(request, 'Ви ввели невірний логін або пароль')

    context = {'form': form}
    return render(request, 'main/login.html', context)


def other_page(request, page):
    try:
        template = get_template('main/' + page + '.html')
    except TemplateDoesNotExist:
        raise Http404
    return HttpResponse(template.render(request=request))


def index(request):
    bbs = Bb.objects.filter(is_active=True, group__name__icontains='Загальні')
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        q = Q(title__icontains=keyword) | Q(content__icontains=keyword) | \
            Q(author__middle_name__icontains=keyword) | Q(author__first_name__icontains=keyword) | \
            Q(author__last_name__icontains=keyword)
        bbs = bbs.filter(q)
    else:
        keyword = ''
    form = SearchForm(initial={'keyword': keyword})
    paginator = Paginator(bbs, 5)
    if 'page' in request.GET:
        page_num = request.GET['page']
    else:
        page_num = 1
    page = paginator.get_page(page_num)
    context = {'page': page, 'bbs': page.object_list, 'form': form}
    return render(request, 'main/index.html', context)


def error_perm_teach(request):
    return render(request, 'main/teacher_error.html')


def reset_password_confirm(request):
    return render(request, 'registration/password_reset_confirm.html')


def reset_password_done(request):
    return render(request, 'registration/password_reset_done.html')


def change_password_done(request):
    return render(request, 'main/change_password_done.html')
