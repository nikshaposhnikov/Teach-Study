from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import PasswordResetForm
from django.core.exceptions import ValidationError
from django.forms import inlineformset_factory
from django.forms.formsets import formset_factory
from django.utils.translation import gettext_lazy as _

from .middlewares import help_text
from .models import user_registrated
from .models import *


class UserCommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        exclude = ('is_active',)
        widgets = {'bb': forms.HiddenInput, 'author': forms.HiddenInput}


class GuestCommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        exclude = ('is_active', 'content',)
        widgets = {'bb': forms.HiddenInput}


AIFormFileSet = inlineformset_factory(Subject, AdditionalFile, fields='__all__', extra=5)


class BbForm(forms.ModelForm):
    class Meta:
        model = Bb
        fields = '__all__'
        widgets = {'author': forms.HiddenInput}


AIFormSet = inlineformset_factory(Bb, AdditionalImage, fields='__all__')


class SearchForm(forms.Form):
    keyword = forms.CharField(required=False, max_length=20, label='')


class SubGroupForm(forms.ModelForm):
    super_group = forms.ModelChoiceField(queryset=SuperGroup.objects.all(), empty_label=None,
                                         label='Форма навчання', required=True)

    class Meta:
        model = SubGroup
        fields = '__all__'


class EmailValidationOnForgotPassword(PasswordResetForm):
    email = forms.EmailField(widget=forms.TextInput(attrs={'placeholder': 'Email'}))
    def clean_email(self):
        email = self.cleaned_data['email']
        if not AdvUser.objects.filter(email__iexact=email, is_active=True).exists():
            raise ValidationError("Користувача не існує")
        return email


class RegisterTeacherForm(forms.ModelForm):
    first_name = forms.CharField(required=True, label="Ім'я**", widget=forms.TextInput)
    last_name = forms.CharField(required=True, label='Прізвище**', widget=forms.TextInput)
    middle_name = forms.CharField(required=True, label='По батькові**', widget=forms.TextInput)
    email = forms.EmailField(required=True, label='Адреса електронної пошти**', widget=forms.EmailInput)
    password1 = forms.CharField(label='Пароль**', widget=forms.PasswordInput,
                                help_text=help_text())
    password2 = forms.CharField(label='Пароль (повторно)**', widget=forms.PasswordInput,
                                help_text='Повторіть пароль')
    position = forms.CharField(required=True, label='Посада**', widget=forms.TextInput)
    degree = forms.CharField(required=False, label='Ступінь', widget=forms.TextInput)
    rank = forms.CharField(required=False, label='Звання', widget=forms.TextInput)

    is_teacher = forms.BooleanField(required=True, label='Викладач', initial=True, widget=forms.HiddenInput())

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        list_email = AdvUser.objects.filter(email=email)
        if list_email.count():
            raise ValidationError('Такий email вже зареєстрований')
        return email


    def clean_password1(self):
        password1 = self.cleaned_data['password1']
        if password1:
            password_validation.validate_password(password1)
        return password1

    def clean(self):
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data and \
                self.cleaned_data['password1'] != self.cleaned_data['password2']:
            raise forms.ValidationError("Введені паролі не збігаються")
        return self.cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.is_active = False
        user.is_activated = False
        if commit:
            user.save()
        return user

    class Meta:
        model = Teacher
        fields = ('email', 'password1', 'password2', 'last_name', 'first_name', 'middle_name',
                  'position', 'degree', 'rank', 'send_messages', 'is_teacher')


class RegisterUserForm(forms.ModelForm):
    first_name = forms.CharField(required=True, label="Ім'я**", widget=forms.TextInput)
    last_name = forms.CharField(required=True, label='Прізвище**', widget=forms.TextInput)
    group = forms.ModelChoiceField(queryset=SubGroup.objects.all(), required=True, label='Група*', )
    email = forms.EmailField(required=True, label='Адреса електронної пошти**', widget=forms.EmailInput)
    password1 = forms.CharField(label='Пароль*', widget=forms.PasswordInput,
                                help_text=help_text())
    password2 = forms.CharField(label='Пароль (повторно)**', widget=forms.PasswordInput,
                                help_text='Повторіть пароль')


    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        list_email = AdvUser.objects.filter(email=email)
        if list_email.count():
            raise ValidationError('Такий email вже зареєстрований')
        return email

    def clean_password1(self):
        password1 = self.cleaned_data['password1']
        if password1:
            password_validation.validate_password(password1)
        return password1

    def clean(self):
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data and \
                self.cleaned_data['password1'] != self.cleaned_data['password2']:
            raise forms.ValidationError("Введені паролі не збігаються")
        return self.cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.is_active = False
        user.is_activated = False
        if commit:
            user.save()
        user_registrated.send(RegisterUserForm, instance=user)
        return user

    class Meta:
        model = AdvUser
        fields = ('email', 'password1', 'password2', 'last_name', 'first_name', 'group')


class ChangeTeacherInfoForm(forms.ModelForm):
    first_name = forms.CharField(required=True, label="Ім'я", widget=forms.TextInput)
    last_name = forms.CharField(required=True, label='Прізвище', widget=forms.TextInput)
    middle_name = forms.CharField(required=True, label='По батькові', widget=forms.TextInput)
    email = forms.EmailField(required=True, label='Адреса електронної пошти', widget=forms.EmailInput)
    position = forms.CharField(required=True, label='Посада', widget=forms.TextInput)
    degree = forms.CharField(required=False, label='Ступінь', widget=forms.TextInput)
    rank = forms.CharField(required=False, label='Звання', widget=forms.TextInput)


    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        list_email = AdvUser.objects.filter(email=email)
        if list_email.count():
            raise ValidationError('Такий email вже зайнятий')
        return email

    class Meta:
        model = Teacher
        fields = ('email', 'first_name', 'last_name', 'middle_name',
                  'position', 'degree', 'rank', 'send_messages')


class ChangeUserInfoForm(forms.ModelForm):
    first_name = forms.CharField(required=True, label="Ім'я", widget=forms.TextInput)
    last_name = forms.CharField(required=True, label='Прізвище', widget=forms.TextInput)
    email = forms.EmailField(required=True, label='Адреса електронної пошти', widget=forms.EmailInput)

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        list_email = AdvUser.objects.filter(email=email)
        if list_email.count():
            raise ValidationError('Такий email вже зайнятий')
        return email

    # def __init__(self, *args, **kwargs):
    #     super(ChangeUserInfoForm, self).__init__(*args, **kwargs)
    #     instance = getattr(self, 'instance', None)
    #     if instance and instance.id:
    #         self.fields['group'].widget.attrs['disabled'] = 'disabled'

    class Meta:
        model = AdvUser
        fields = ('first_name', 'last_name', 'email')



class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    error_messages = {
        'password_mismatch': _('Два поля пароля не збігаються.'),
    }
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text=help_text(),
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        password_validation.validate_password(password2, self.user)
        return password2

    def save(self, commit=True):
        password = self.cleaned_data["new_password1"]
        self.user.set_password(password)
        if commit:
            self.user.save()
        return self.user


class PasswordChangeForm(SetPasswordForm):
    """
    A form that lets a user change their password by entering their old
    password.
    """
    error_messages = {
        **SetPasswordForm.error_messages,
        'password_incorrect': _("Ваш старий пароль був введений неправильно. Будь ласка, введіть його знову."),
    }
    old_password = forms.CharField(
        label=_("Old password"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password', 'autofocus': True}),
    )

    field_order = ['old_password', 'new_password1', 'new_password2']

    def clean_old_password(self):
        """
        Validate that the old_password field is correct.
        """
        old_password = self.cleaned_data["old_password"]
        if not self.user.check_password(old_password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'],
                code='password_incorrect',
            )
        return old_password


class LoginForm(forms.ModelForm):
    email = forms.EmailField(required=True, label='Email',  widget=forms.EmailInput)
    password = forms.CharField(label='Пароль', widget=forms.PasswordInput)

    class Meta:
        model = AdvUser
        fields = ('email', 'password')
