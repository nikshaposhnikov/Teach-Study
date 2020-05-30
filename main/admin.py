from django.contrib import admin
import datetime

from .forms import SubGroupForm
from .models import *
from .utilities import send_activation_notification
from django.contrib import messages

admin.site.site_header = 'Адміністрування Study&Teach'


class AdditionalScheduleInline(admin.TabularInline):
    model = AdditionalSchedule

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        field = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == 'teacher':
            kwargs['queryset'] = Teacher.objects.filter(is_teacher=True)
            field.label_from_instance = lambda u: f'{u.last_name} {u.first_name} {u.middle_name}'
        return field


class ScheduleAdmin(admin.ModelAdmin):
    list_filter = ('group',)
    inlines = [AdditionalScheduleInline, ]


admin.site.register(Schedule, ScheduleAdmin)


class AuditoryAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    search_fields = ('auditory_number',)
    fields = ('auditory_number',)


admin.site.register(Auditory, AuditoryAdmin)


class StructureAdmin(admin.ModelAdmin):
    list_display = ('__str__',)
    search_fields = ('structure_name',)
    fields = ('structure_name',)


admin.site.register(Structure, StructureAdmin)


class AdditionalFileInline(admin.TabularInline):
    model = AdditionalFile


class SubjectAdmin(admin.ModelAdmin):
    list_display = ('name_of_subject',)
    list_display_links = ['name_of_subject']
    search_fields = ('name_of_subject',)
    fields = ('name_of_subject',)
    inlines = (AdditionalFileInline,)


admin.site.register(Subject, SubjectAdmin)


class CommentAdmin(admin.ModelAdmin):
    list_display = ('author', 'content', 'created_at', 'is_active')
    list_display_links = ('author', 'content')
    list_filter = ('is_active',)
    search_fields = ('author', 'content',)
    date_hierarchy = 'created_at'
    fields = ('bb', 'author', 'content', 'is_active', 'created_at')
    readonly_fields = ('created_at',)


admin.site.register(Comment, CommentAdmin)


class AdditionalImageInline(admin.TabularInline):
    model = AdditionalImage


class BbAdmin(admin.ModelAdmin):
    list_display = ('title', 'group', 'full_name', 'created_at')
    list_display_links = ('title',)
    search_fields = ('title', 'content', 'group__name', 'author__first_name', 'author__last_name',
                     'author__middle_name',)
    date_hierarchy = 'created_at'
    fields = (('group', 'author'), 'title', 'content', 'image', 'is_active')
    inlines = (AdditionalImageInline,)


admin.site.register(Bb, BbAdmin)


class SubGroupAdmin(admin.ModelAdmin):
    form = SubGroupForm


admin.site.register(SubGroup, SubGroupAdmin)


class SubGroupInline(admin.TabularInline):
    model = SubGroup


class SuperGroupAdmin(admin.ModelAdmin):
    exclude = ('super_group',)
    inlines = (SubGroupInline,)


admin.site.register(SuperGroup, SuperGroupAdmin)


def send_activation_notifications(modeladmin, request, queryset):
    for rec in queryset:
        if not rec.is_activated:
            send_activation_notification(rec)
    modeladmin.message_user(request, 'Листи з оповіщеннням відправлені')


send_activation_notifications.short_description = 'Відправлення листів з оповіщенням про активацію'


class NonactivatedFilter(admin.SimpleListFilter):
    title = 'Пройшли активацію?'
    parameter_name = 'actstate'

    def lookups(self, request, model_admin):
        return (
            ('activated', 'Пройшли'),
            ('threedays', 'Не пройшли більше 3 днів'),
            ('week', 'Не пройшли більше тижня'),
        )

    def queryset(self, request, queryset):
        val = self.value()
        if val == 'activated':
            return queryset.filter(is_active=True, is_activated=True)
        elif val == 'threedays':
            d = datetime.date.today() - datetime.timedelta(days=3)
            return queryset.filter(is_active=False, is_activated=False, date_joined__date__lt=d)
        elif val == 'week':
            d = datetime.date.today() - datetime.timedelta(weeks=1)
            return queryset.filter(is_active=False, is_activated=False, date_joined__date__lt=d)


class TeacherAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'is_activated', 'date_joined')
    search_fields = ('first_name', 'last_name', 'middle_name')
    list_filter = (NonactivatedFilter,)
    fields = (('email', 'first_name', 'last_name', 'middle_name'),
              ('send_messages', 'is_active', 'is_activated', 'is_teacher'),
              ('position', 'degree', 'rank'),
              ('last_login', 'date_joined'))
    readonly_fields = ('last_login', 'date_joined')
    actions = (send_activation_notifications,)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        field = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == 'teacher':
            kwargs['queryset'] = Teacher.objects.filter(is_teacher=True)
            field.label_from_instance = lambda u: f'{u.last_name} {u.first_name} {u.middle_name}'
        return field


admin.site.register(Teacher, TeacherAdmin)


class AdvUserAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'is_activated', 'date_joined',)
    search_fields = ('email', 'first_name', 'last_name')
    list_filter = (NonactivatedFilter,)
    fields = (('email', 'first_name', 'last_name', 'group'),
              ('is_active', 'is_activated'),
              ('last_login', 'date_joined'))
    readonly_fields = ('last_login', 'date_joined')
    actions = (send_activation_notifications,)

    def get_queryset(self, request):
        qs = super(AdvUserAdmin, self).get_queryset(request)
        return qs.filter(is_teacher=False)


admin.site.register(AdvUser, AdvUserAdmin)
