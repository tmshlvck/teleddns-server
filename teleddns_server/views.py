"""
TeleDDNS Server - Common Views
(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from django.shortcuts import redirect
from django.http import HttpResponse
from django.views.decorators.cache import cache_page


def root_redirect(request):
    """Redirect root URL to admin interface"""
    return redirect('/admin/')


@cache_page(60 * 60 * 24)  # Cache for 24 hours
def robots_txt(request):
    """Serve robots.txt to disallow all crawlers"""
    content = """# robots.txt for TeleDDNS Server
# This file prevents web crawlers from indexing any part of this site

User-agent: *
Disallow: /
"""
    return HttpResponse(content, content_type='text/plain')
