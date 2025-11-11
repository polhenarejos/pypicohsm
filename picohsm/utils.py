"""
/*
 * This file is part of the pypicohsm distribution (https://github.com/polhenarejos/pypicohsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"""

import urllib
import json

def int_to_bytes(x, length=None, byteorder='big'):
    return x.to_bytes(length or (x.bit_length() + 7) // 8, byteorder=byteorder)


def get_pki_data(url, data=None, method='GET'):
    user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; '
    'rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7'
    method = 'GET'
    if (data is not None):
        method = 'POST'
    req = urllib.request.Request(f"https://www.picokeys.com/pico/pico-hsm/{url}/",
                                method=method,
                                data=data,
                                headers={'User-Agent': user_agent, })
    response = urllib.request.urlopen(req)
    resp = response.read().decode('utf-8')
    j = json.loads(resp)
    return j
