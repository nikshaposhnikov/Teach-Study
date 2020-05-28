from django.utils.html import format_html_join, format_html

from .models import SubGroup


def help_text():
    help_texts = ['Ваш пароль не може бути занадто схожий на іншу вашу особисту інформацію.',
                  'Ваш пароль повинен містити як мінімум 8 символів.',
                  'Ваш пароль не може бути часто використовуваним паролем.',
                  'Ваш пароль не може бути повністю цифровим.']
    help_items = format_html_join('', '<li>{}</li>', ((help_text,) for help_text in help_texts))
    return format_html('<ul>{}</ul>', help_items) if help_items else ''


def bboard_context_processor(request):
    context = {}
    context['groups'] = SubGroup.objects.all()
    context['keyword'] = ''
    context['all'] = ''
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        if keyword:
            context['keyword'] = '?keyword=' + keyword
            context['all'] = context['keyword']
    if 'page' in request.GET:
        page = request.GET['page']
        if page != '1':
            if context['all']:
                context['all'] += '&page=' + page
            else:
                context['all'] = '?page=' + page
    return context
