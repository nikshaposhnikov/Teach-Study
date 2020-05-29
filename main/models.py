import os

from django.core.signing import Signer
from learnDjango.settings import ALLOWED_HOSTS
from django.db.models import signals
from django.core.mail import send_mail, EmailMultiAlternatives
from django.dispatch import Signal
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
import datetime
from django.core.exceptions import ValidationError

from .utilities import (send_activation_notification, get_timestamp_path, get_namestamp_path,
                        send_new_comment_notification)

DAYS_OF_WEEK = (
    ("0", 'Понеділок'),
    ("1", 'Вівторок'),
    ("2", 'Середа'),
    ("3", 'Четвер'),
    ("4", "П'ятниця"),
    ("5", 'Субота'),
)

TIME_CHOICES = (
    ("08:30:00", '08:30:00'),
    ("10:25:00", '10:25:00'),
    ("12:35:00", '12:35:00'),
    ("14:30:00", '14:30:00'),
    ("16:25:00", '16:25:00'),
    ("18:10:00", '18:10:00'),
)


class Structure(models.Model):
    structure_name = models.CharField(max_length=15, verbose_name='Учбовий корпус')

    def __str__(self):
        return self.structure_name

    class Meta:
        verbose_name_plural = 'Учбові корпуса'
        verbose_name = 'Учбовий корпус'
        ordering = ['structure_name']


class Auditory(models.Model):
    auditory_number = models.CharField(max_length=5, verbose_name='Аудиторія')

    def __str__(self):
        return self.auditory_number

    class Meta:
        verbose_name_plural = 'Аудиторії'
        verbose_name = 'Аудиторія'
        ordering = ['auditory_number']


class Schedule(models.Model):
    group = models.ForeignKey('SubGroup', on_delete=models.CASCADE, verbose_name='Група')

    def __str__(self):
        return 'Рзклад групи --- ' + str(self.group)

    class Meta:
        verbose_name = 'Розклад'
        verbose_name_plural = 'Розклад'


class AdditionalSchedule(models.Model):
    schedule = models.ForeignKey('Schedule', on_delete=models.CASCADE, verbose_name='Розклад')
    subject = models.ForeignKey('Subject', on_delete=models.PROTECT, null=True, verbose_name='Дисципліна')
    teacher = models.ForeignKey('Teacher', on_delete=models.CASCADE, null=True, verbose_name='Викладач')
    structure = models.ForeignKey('Structure', on_delete=models.PROTECT, null=True, verbose_name='Учбовий корпус')
    auditory = models.ForeignKey('Auditory', on_delete=models.PROTECT, null=True, verbose_name='Аудиторія')
    start_time = models.CharField(max_length=10, choices=TIME_CHOICES, null=True, verbose_name='Початок заняття')
    day = models.CharField(max_length=1, choices=DAYS_OF_WEEK, null=True, verbose_name='День тижня')

    # def clean(self):
    #     try:
    #         AdditionalSchedule.objects.get(start_time=self.cleaned_data['start_time'],
    #                                        day=self.cleaned_data['day'])
    #         # if we get this far, we have an exact match for this form's data
    #         raise self.ValidationError("Exists already!")
    #     except AdditionalSchedule.DoesNotExist:
    #         # because we didn't get a match
    #         pass
    #
    #     return self.cleaned_data

    # def clean(self, *args, **kwargs):
    #
    #     sh = AdditionalSchedule.objects.filter(schedule=self.schedule, start_time=self.start_time,
    #                                            day=self.day)
    #     if (AdditionalSchedule.objects.filter(schedule=self.schedule, start_time=self.start_time,
    #                                            day=self.day).exists()):
    #         raise ValidationError('Нельзя назначить пару в одно и тоже время!')
    #     else:
    #         super(AdditionalSchedule, self).clean(*args, **kwargs)

    def __str__(self):
        return 'Додання занять'

    class Meta:
        verbose_name_plural = 'Продовження розклду'
        verbose_name = 'Продовження розкладу'


class Subject(models.Model):
    name_of_subject = models.CharField(max_length=220, verbose_name='Назва дисципліни')

    def __str__(self):
        return self.name_of_subject

    class Meta:
        verbose_name_plural = 'Дисципліни'
        verbose_name = 'Дисципліна'
        ordering = ['name_of_subject']


class AdditionalFile(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, verbose_name='Дисципліна')
    file = models.FileField(upload_to=get_namestamp_path, verbose_name='Матеріал')

    def __str__(self):
        return self.file.name

    class Meta:
        verbose_name_plural = 'Додаткові матеріали'
        verbose_name = 'Дотатковий матеріал'


class Comment(models.Model):
    bb = models.ForeignKey('Bb', on_delete=models.CASCADE, verbose_name="Оголошення")
    author = models.ForeignKey('AdvUser', on_delete=models.CASCADE, verbose_name='Автор')
    content = models.TextField(verbose_name='Зміст')
    is_active = models.BooleanField(default=True, db_index=True, verbose_name='Виводити на головній сторінці?')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Опублікован')

    def __str__(self):
        return self.content

    class Meta:
        verbose_name_plural = 'Коментарі'
        verbose_name = 'Коментарій'
        ordering = ['-created_at']


def post_save_dispatcher(sender, **kwargs):
    author = kwargs['instance'].bb.author
    if kwargs['created'] and author.send_messages:
        send_new_comment_notification(kwargs['instance'])


post_save.connect(post_save_dispatcher, sender=Comment)


class AdditionalImage(models.Model):
    bb = models.ForeignKey('Bb', on_delete=models.CASCADE, verbose_name="Оголошення")
    image = models.ImageField(upload_to=get_timestamp_path, verbose_name='Зображення')

    def __str__(self):
        return self.image.name

    class Meta:
        verbose_name_plural = 'Додаткові зображення'
        verbose_name = 'Додаткове зображення'


class Bb(models.Model):
    group = models.ForeignKey('SubGroup', on_delete=models.CASCADE, verbose_name='Група')
    title = models.CharField(max_length=40, verbose_name='Заголовок')
    content = models.TextField(verbose_name='Інформація')
    image = models.ImageField(blank=True, upload_to=get_timestamp_path, verbose_name='Зображення')
    author = models.ForeignKey('Teacher', on_delete=models.CASCADE,
                               verbose_name="Автор оголошення")
    is_active = models.BooleanField(default=True, db_index=True, verbose_name='Виводити на головній сторінці?')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Опубліковано')

    def __str__(self):
        return self.title

    def delete(self, *args, **kwargs):
        for ai in self.additionalimage_set.all():
            ai.delete()
        super().delete(*args, **kwargs)

    def full_name(obj):
        return "%s %s %s" % (obj.author.last_name, obj.author.first_name, obj.author.middle_name)

    full_name.short_description = 'Викладач'

    class Meta:
        verbose_name_plural = "Оголошення"
        verbose_name = "Оголошення"
        ordering = ['-created_at']


class Group(models.Model):
    name = models.CharField(max_length=50, db_index=True, unique=True, verbose_name='Назва')
    order = models.SmallIntegerField(default=0, db_index=True, verbose_name='Порядок')
    super_group = models.ForeignKey('SuperGroup', on_delete=models.PROTECT, null=True, blank=True,
                                    verbose_name='Форма навчання')


class SuperGroupManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(super_group__isnull=True)


class SuperGroup(Group):
    objects = SuperGroupManager()

    def __str__(self):
        return self.name

    class Meta:
        proxy = True
        ordering = ["order", "name"]
        verbose_name = 'Форма навчання'
        verbose_name_plural = 'Форми навчання'


class SubGroupManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(super_group__isnull=False)


class SubGroup(Group):
    objects = SubGroupManager()

    def __str__(self):
        return '%s - %s' % (self.super_group.name, self.name)

    class Meta:
        proxy = True
        ordering = ['super_group__order', 'super_group__name', 'order', 'name']
        verbose_name = 'Група'
        verbose_name_plural = 'Групи'


user_registrated = Signal(providing_args=['instance'])


def user_registrated_dispatcher(sender, **kwargs):
    send_activation_notification(kwargs['instance'])


user_registrated.connect(user_registrated_dispatcher)


class AdvUser(AbstractUser):
    USERNAME_FIELD = 'email'
    email = models.EmailField(_('email address'), unique=True)  # changes email to unique and blank to false
    REQUIRED_FIELDS = []  # removes email from REQUIRED_FIELDS
    username = models.CharField(max_length=40, unique=False, default='')
    group = models.ForeignKey('SubGroup', on_delete=models.PROTECT, null=True, verbose_name='Група')
    is_teacher = models.BooleanField(default=False, verbose_name='Викладач')
    is_activated = models.BooleanField(default=True, db_index=True, verbose_name='Пройшов активацію?')
    send_messages = models.BooleanField(default=True, verbose_name='Слати оповещанія про нові коментарі?')

    def delete(self, *args, **kwargs):
        Comment.objects.filter(author=self.pk).delete()
        super().delete(*args, **kwargs)

    def full_name(obj):
        return "%s %s" % (obj.last_name, obj.first_name)

    full_name.short_description = 'Студент'

    class Meta(AbstractUser.Meta):
        verbose_name_plural = 'Студенти'
        verbose_name = 'Студент'
        ordering = ['last_name']


class Teacher(AdvUser):
    middle_name = models.CharField(max_length=50, db_index=True, verbose_name='По батькові')
    position = models.CharField(max_length=50, db_index=True, verbose_name='Посада')
    degree = models.CharField(max_length=100, blank=True, verbose_name='Ступінь')
    rank = models.CharField(max_length=40, blank=True, verbose_name='Звання')

    def delete(self, *args, **kwargs):
        Comment.objects.filter(author=self.pk).delete()
        for bb in self.bb_set.all():
            bb.delete()
        super().delete(*args, **kwargs)

    def full_name(obj):
        return "%s %s %s" % (obj.last_name, obj.first_name, obj.middle_name)

    full_name.short_description = 'Викладач'

    class Meta(AbstractUser.Meta):
        verbose_name_plural = 'Викладачі'
        verbose_name = 'Викладач'
        ordering = ['last_name', 'first_name', 'middle_name']


def notify_student(sender, instance, created, **kwargs):
    '''Оповещает студента о добавлении нового объявления.'''
    if created:
        signer = Signer()
        if ALLOWED_HOSTS:
            host = 'http://' + ALLOWED_HOSTS[0] + '/accounts/profile/' + str(instance.pk)
        else:
            host = 'http://localhost:8000/accounts/profile/' + str(instance.pk)
        subject = 'Додане нове оголошення'
        html_message = '<p>Для вашої групи було додано нове оголошення.</p>' \
                       '<p>Для того, щоб його подивитись, перейдіть за посиланням: <br\>' \
                       '<a href="%s">%s</a></p> ' \
                       '<p>З повагою, адміністрація сайту Teach&Study</p> ' \
                       % (host, host)
        admin = AdvUser.objects.filter(username='admin')
        email = ''
        for a in admin:
            email = a.email
        from_addr = email
        students = AdvUser.objects.filter(group=instance.group)
        students_email = []
        for s in students:
            if s.email not in students_email:
                students_email.append(s.email)
        for e in students_email:
            recipient_list = (e,)
            msg = EmailMultiAlternatives(subject, html_message, from_addr, recipient_list)
            msg.content_subtype = "html"  # Main content is now text/html
            msg.send()


signals.post_save.connect(notify_student, sender=Bb)


def notify_admin(sender, instance, created, **kwargs):
    '''Оповещает администратора о добавлении нового пользователя.'''
    if created:
        signer = Signer()
        if ALLOWED_HOSTS:
            host = 'http://' + ALLOWED_HOSTS[
                0] + '/admin/main/teacher/?q=' + instance.last_name + "+" + instance.first_name
        else:
            host = 'http://localhost:8000/admin/main/teacher/?q=' + instance.last_name + "+" + instance.first_name
        subject = 'Створений новий викладач'
        html_message = '<p>Був зареєстрований викладач <strong>%s</strong> <strong>%s</strong> ' \
                       '<strong>%s</strong>.' \
                       '<p>Активуйте користувача в <a href="%s">адмін-панелі</a>, ' \
                       'ящко це дійсно викладач, або видаліть, ящко це не так.</p> ' \
                       % (instance.last_name, instance.first_name, instance.middle_name, host)
        from_addr = instance.email
        admin = AdvUser.objects.filter(username='admin')
        email = ''
        for a in admin:
            email = a.email
        recipient_list = (email,)
        msg = EmailMultiAlternatives(subject, html_message, from_addr, recipient_list)
        msg.content_subtype = "html"  # Main content is now text/html
        msg.send()
    if instance.is_activated and instance.is_active:
        signer = Signer()
        if ALLOWED_HOSTS:
            host = 'http://' + ALLOWED_HOSTS[0] + '/accounts/login/'
        else:
            host = 'http://localhost:8000/accounts/login/'
        subject = 'Активація акаунту'
        html_message = '<p>Ви були зареєстровані на сайті <i>Teach&Study</i>.</p>' \
                       '<p>Ви можете <a href="%s">увійти</a> на сайт із правами викладача.</p>' \
                       '<p>Вітаємо вас, колега.</p> <br\>' \
                       '<p>З повагою, адміністрація сайту Teach&Study</p> ' \
                       % (host,)
        admin = AdvUser.objects.filter(username='admin')
        email = ''
        for a in admin:
            email = a.email
        from_addr = email
        recipient_list = (instance.email,)
        msg = EmailMultiAlternatives(subject, html_message, from_addr, recipient_list)
        msg.content_subtype = "html"  # Main content is now text/html
        msg.send()


signals.post_save.connect(notify_admin, sender=Teacher)
