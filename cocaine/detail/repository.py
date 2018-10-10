#
#    Copyright (c) 2018+ Artem Selishev <arselishev@gmail.com>
#
#    This file is part of Cocaine.
#
#    Cocaine is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    Cocaine is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
from .locator import LOCATOR_SERVICE_NAME, LOCATOR_DEFAULT_ENDPOINTS, Locator
from .secadaptor import create_ticket_service, create_secure_provider, SecureServiceAdaptor
from .service import Service


class ServiceRepository(object):
    def __init__(self, endpoints=LOCATOR_DEFAULT_ENDPOINTS):
        self._locator = Locator(endpoints)
        self._cache = {}

    def create_service(self, name):
        if name in self._cache:
            return self._cache[name]

        if name == LOCATOR_SERVICE_NAME:
            return self._locator

        service = Service(
            name,
            locator=self._locator
        )

        self._cache[name] = service
        return service


class SecureServiceRepository(ServiceRepository):
    def __init__(self, endpoints=LOCATOR_DEFAULT_ENDPOINTS, mod='', token_expiration_s=0, **kwargs):
        """
        :param endpoints: Locator endpoints.
        :param mod: Type of authentication.
        :param token_expiration_s: Token update interval in seconds.
        :param kwargs: Mod-specific arguments. For TVM/TVM2 it is `client_id` and `client_secret`.
        """
        super(SecureServiceRepository, self).__init__(endpoints)
        self._token_expiration_s = token_expiration_s
        self._secure_provider = create_secure_provider(
            mod,
            create_ticket_service(mod, endpoints),
            **kwargs
        )
        self._cache_secured = {}

    def create_secure_service(self, name):
        if name in self._cache_secured:
            return self._cache_secured[name]

        service = SecureServiceAdaptor(
            self.create_service(name),
            self._secure_provider,
            self._token_expiration_s
        )

        self._cache_secured[name] = service
        return service
