"""Secure service adaptor.

Provides method for Service adaptor construction, capable to wrap Cocaine
service and inject security token into the header of service request.
"""

import time

from collections import namedtuple
from tornado import gen

from .locator import LOCATOR_DEFAULT_ENDPOINTS
from .service import Service
from ..exceptions import CocaineError


class SecureServiceError(CocaineError):
    pass


class Promiscuous(object):
    """Null token fetch interface implementation.

    Used for fallback in case of unsupported (not set) secure module type
    provided by user, access errors due empty token will be propagated
    to caller code.
    """
    @gen.coroutine
    def fetch_token(self):
        raise gen.Return('')


Credentials = namedtuple('Credentials', [
    'client_id',
    'client_secret',
])


def _make_token(auth_type, ticket):
    return '{} {}'.format(auth_type, ticket)


class TVM(object):
    """Tokens fetch interface implementation with using of TVM protocol.

    Provides public `fetch_token` method, which should be common
    among various token backend types.
    """
    # Can be taken from class name in case of TVM, but could be inconvenient
    # in less general name formatting rules.
    TYPE = 'TVM'

    def __init__(self, service, credentials):
        """TVM

        :param service: TVM service.
        :param credentials: Credentials for token fetching
        """
        self._tvm = service
        self._credentials = credentials

    @gen.coroutine
    def fetch_token(self):
        """Gains token from secure backend service.
        Token allows to visit any destination under TVM protection

        :return: Token formatted for Cocaine protocol header.
        """
        grant_type = 'client_credentials'
        channel = yield self._tvm.ticket_full(
            self._credentials.client_id,
            self._credentials.client_secret,
            grant_type,
            {}
        )
        ticket = yield channel.rx.get()

        raise gen.Return(_make_token(self.TYPE, ticket))


class TVM2(object):
    """Tokens fetch interface implementation with using of TVM2 protocol.

    Provides public `fetch_token` method, which should be common
    among various token backend types.
    """
    TYPE = 'TVM2'

    def __init__(self, service, credentials):
        """TVM2

        :param service: TVM service.
        :param credentials: Credentials for token fetching
        """
        self._tvm2 = service
        self._credentials = credentials

    @gen.coroutine
    def fetch_token(self):
        """Gains token from secure backend service.
        Token allows to visit any Cocaine service under TVM2 protection

        :return: Token formatted for Cocaine protocol header.
        """
        channel = yield self._tvm2.ticket(
            self._credentials.client_id,
            self._credentials.client_secret,
        )
        ticket = yield channel.rx.get()

        raise gen.Return(_make_token(self.TYPE, ticket))


class SecureServiceAdaptor(object):
    """Wrapper for injecting service method with secure token.
    """
    def __init__(self, wrapped, secure, token_expiration_s=0):
        """
        :param wrapped: Cocaine service.
        :param secure: Tokens provider with `fetch_token` implementation.
        :param token_expiration_s: Token update interval in seconds.
        """
        self._wrapped = wrapped
        self._secure = secure
        self._token_expiration_s = token_expiration_s

        self._token = None
        self._to_expire = 0

    @gen.coroutine
    def connect(self, traceid=None):
        yield self._wrapped.connect(traceid)

    def disconnect(self):
        return self._wrapped.disconnect()

    @gen.coroutine
    def _get_token(self):
        try:
            if time.time() >= self._to_expire:
                self._token = yield self._secure.fetch_token()
                self._to_expire = time.time() + self._token_expiration_s
        except Exception as err:
            raise SecureServiceError(
                'failed to fetch secure token: {}'.format(err))

        raise gen.Return(self._token)

    def __getattr__(self, name):
        @gen.coroutine
        def wrapper(*args, **kwargs):
            kwargs['authorization'] = yield self._get_token()
            raise gen.Return(
                (yield getattr(self._wrapped, name)(*args, **kwargs))
            )

        return wrapper


def create_ticket_service(mod='', endpoints=LOCATOR_DEFAULT_ENDPOINTS):
    if mod == TVM.TYPE:
        return Service('tvm', endpoints)
    elif mod == TVM2.TYPE:
        return Service('tvm2', endpoints)
    return None


def create_secure_provider(mod='', ticket_service=None, **kwargs):
    if mod == TVM.TYPE:
        return TVM(
            ticket_service,
            Credentials(**kwargs)
        )
    elif mod == TVM2.TYPE:
        return TVM2(
            ticket_service,
            Credentials(**kwargs)
        )
    return Promiscuous()


class SecureServiceFactory(object):

    @staticmethod
    def make_secure_adaptor(service, endpoints=None, mod='', token_expiration_s=0, **kwargs):
        """
        :param service: Service to wrap in.
        :param endpoints: Token service endpoints. By default endpoints from service will be used.
        :param mod: Type of authentication.
        :param token_expiration_s: Token update interval in seconds.
        :param kwargs: Mod-specific arguments. For TVM/TVM2 it is `client_id` and `client_secret`.
        """
        endpoints = endpoints or service.endpoints

        ticket_service = create_ticket_service(mod, endpoints)
        provider = create_secure_provider(mod, ticket_service, **kwargs)
        return SecureServiceAdaptor(service, provider, token_expiration_s)
