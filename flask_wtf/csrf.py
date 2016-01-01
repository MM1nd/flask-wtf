# coding: utf-8
"""
    flask_wtf.csrf
    ~~~~~~~~~~~~~~

    CSRF protection for Flask.

    :copyright: (c) 2013 by Hsiaoming Yang.
"""

import os
import hmac
import hashlib
import time
from flask import Blueprint
from flask import current_app, session, request, abort
from werkzeug.security import safe_str_cmp
from ._compat import to_bytes, string_types

from wtforms.csrf.session import SessionCSRF
try:
    from urlparse import urlparse
except ImportError:
    # python 3
    from urllib.parse import urlparse


__all__ = ('generate_csrf', 'validate_csrf', 'CsrfProtect')


class CsrfProtect(object):
    """Enable csrf protect for Flask.

    Register it with::

        app = Flask(__name__)
        CsrfProtect(app)

    And in the templates, add the token input::

        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

    If you need to send the token via AJAX, and there is no form::

        <meta name="csrf_token" content="{{ csrf_token() }}" />

    You can grab the csrf token with JavaScript, and send the token together.
    """

    def __init__(self, app=None):
        self._exempt_views = set()
        self._exempt_blueprints = set()

        if app:
            self.init_app(app)

    def init_app(self, app):
        self._app = app
        app.jinja_env.globals['csrf_token'] = generate_csrf
        app.config.setdefault(
            'WTF_CSRF_HEADERS', ['X-CSRFToken', 'X-CSRF-Token']
        )
        app.config.setdefault('WTF_CSRF_SSL_STRICT', True)
        app.config.setdefault('WTF_CSRF_ENABLED', True)
        app.config.setdefault('WTF_CSRF_CHECK_DEFAULT', True)
        app.config.setdefault('WTF_CSRF_METHODS', ['POST', 'PUT', 'PATCH'])

        # expose csrf_token as a helper in all templates
        @app.context_processor
        def csrf_token():
            return dict(csrf_token=generate_csrf)

        @app.before_request
        def _csrf_protect():
            # many things come from django.middleware.csrf
            if not app.config['WTF_CSRF_ENABLED']:
                return

            if not app.config['WTF_CSRF_CHECK_DEFAULT']:
                return

            if request.method not in app.config['WTF_CSRF_METHODS']:
                return

            if self._exempt_views or self._exempt_blueprints:
                if not request.endpoint:
                    return

                view = app.view_functions.get(request.endpoint)
                if not view:
                    return

                dest = '%s.%s' % (view.__module__, view.__name__)
                if dest in self._exempt_views:
                    return
                if request.blueprint in self._exempt_blueprints:
                    return

            self.protect()

    def _get_csrf_token(self):
        # find the ``csrf_token`` field in the subitted form
        # if the form had a prefix, the name will be
        # ``{prefix}-csrf_token``
        for key in request.form:
            if key.endswith('csrf_token'):
                csrf_token = request.form[key]
                if csrf_token:
                    return csrf_token

        for header_name in self._app.config['WTF_CSRF_HEADERS']:
            csrf_token = request.headers.get(header_name)
            if csrf_token:
                return csrf_token
        return None

    def protect(self):
        if request.method not in self._app.config['WTF_CSRF_METHODS']:
            return

        if not validate_csrf(self._get_csrf_token()):
            reason = 'CSRF token missing or incorrect.'
            return self._error_response(reason)

        if request.is_secure and self._app.config['WTF_CSRF_SSL_STRICT']:
            if not request.referrer:
                reason = 'Referrer checking failed - no Referrer.'
                return self._error_response(reason)

            good_referrer = 'https://%s/' % request.host
            if not same_origin(request.referrer, good_referrer):
                reason = 'Referrer checking failed - origin does not match.'
                return self._error_response(reason)

        request.csrf_valid = True  # mark this request is csrf valid

    def exempt(self, view):
        """A decorator that can exclude a view from csrf protection.

        Remember to put the decorator above the `route`::

            csrf = CsrfProtect(app)

            @csrf.exempt
            @app.route('/some-view', methods=['POST'])
            def some_view():
                return
        """
        if isinstance(view, Blueprint):
            self._exempt_blueprints.add(view.name)
            return view
        if isinstance(view, string_types):
            view_location = view
        else:
            view_location = '%s.%s' % (view.__module__, view.__name__)
        self._exempt_views.add(view_location)
        return view

    def _error_response(self, reason):
        return abort(400, reason)

    def error_handler(self, view):
        """A decorator that set the error response handler.

        It accepts one parameter `reason`::

            @csrf.error_handler
            def csrf_error(reason):
                return render_template('error.html', reason=reason)

        By default, it will return a 400 response.
        """
        self._error_response = view
        return view


def same_origin(current_uri, compare_uri):
    parsed_uri = urlparse(current_uri)
    parsed_compare = urlparse(compare_uri)

    if parsed_uri.scheme != parsed_compare.scheme:
        return False

    if parsed_uri.hostname != parsed_compare.hostname:
        return False

    if parsed_uri.port != parsed_compare.port:
        return False
    return True
