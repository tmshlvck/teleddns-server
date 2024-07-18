#!/usr/bin/env python3
#
# TeleDDNS-Server
# (C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import uvicorn
import sys

from .settings import settings

def main():
    uvicorn.run("teleddns_server.main:app", host=settings.LISTEN_ADDRESS, port=settings.LISTEN_PORT, proxy_headers=True, reload=True)
    return 0

if __name__ == '__main__':
    sys.exit(main())