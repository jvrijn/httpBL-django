from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


# Make sure the api key for httpBL is defined.
if not getattr(settings, 'HTTPBLKEY', None):
    raise ImproperlyConfigured("httpBL_django needs to have your http:BL API key defined as HTTPBLKEY defined in your project settings! "
                               "A key can be obtained on http://projecthoneypot.org/")


if settings.DEBUG:
    cache_duration = float(10)
else:
    cache_duration = float(7 * 24 * 60 * 60)


HTTPBL_DOMAIN = 'dnsbl.httpbl.org'

SEARCH_ENGINES = {
    '0': 'Undocumented',
    '1': 'AltaVista',
    '2': 'Ask',
    '3': 'Baidu',
    '4': 'Excite',
    '5': 'Google',
    '6': 'Looksmart',
    '7': 'Lycos',
    '8': 'MSN',
    '9': 'Yahoo',
    '10': 'Cuil',
    '11': 'InfoSeek',
    '12': 'Miscellaneous',
}