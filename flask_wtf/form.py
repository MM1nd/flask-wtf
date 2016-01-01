# coding: utf-8

import werkzeug.datastructures

from flask import request, session, current_app
from wtforms.validators import ValidationError
from wtforms.form import Form
from .widgets import HiddenTag

try:
    from .i18n import translations
except ImportError:
    translations = None  # babel not installed


class _Auto():
    '''Placeholder for unspecified variables that should be set to defaults.

    Used when None is a valid option and should not be replaced by a default.
    '''
    pass


class Form(Form):
    """
    Flask-specific subclass of WTForms **SecureForm** class.

    If formdata is not specified, this will use flask.request.form.
    Explicitly pass formdata = None to prevent this.

    :param meta:       A dictionary as described in the WTForms docs.
                       
                       meta["csrf"]:    define whether to use CSRF protection. 
                                        If False, all csrf behavior is suppressed.
                                        If True, a HiddenInput field csrf_token is created for you.
                                        That field's widget is set to HiddenTag, so cf.
                                        the documentation there.

                                        Default: WTF_CSRF_ENABLED config value or,
                                        if that is not set: True
                       
                       meta["csrf_secret"]:
                                        a secret key for building CSRF tokens. 
                                        If this isn't specified, the form will take 
                                        the first of these that is defined:

                                       * SECRET_KEY attribute on this class
                                       * WTF_CSRF_SECRET_KEY config of flask app
                                       * SECRET_KEY config of flask app
                       meta["csrf_context"]:
                                        a session or dict-like object to use when 
                                        making CSRF tokens. 
                                        Default: flask.session.
    """

    SECRET_KEY = None
    TIME_LIMIT = None

    

    def __init__(self, formdata=_Auto, obj=None, prefix='', data=None, meta=None, **kwargs):

        if not meta:
            meta = {}

        if "csrf" not in meta:
            meta["csrf"]=current_app.config.get('WTF_CSRF_ENABLED', True)

        if meta["csrf"]:
            if "csrf_secret" not in meta:
                meta["csrf_secret"] =  getattr(self, "SECRET_KEY", None)

            if not meta["csrf_secret"]:
                 meta["csrf_secret"] = current_app.config.get('WTF_CSRF_SECRET_KEY', None)

            if not meta["csrf_secret"]:
                 meta["csrf_secret"] = current_app.config.get('SECRET_KEY', None)

            meta["csrf_secret"]=meta["csrf_secret"].encode()

            if "csrf_context" not in meta:
                meta["csrf_context"] = session

        if formdata is _Auto:
            if self.is_submitted():
                formdata = request.form
                if request.files:
                    formdata = formdata.copy()
                    formdata.update(request.files)
                elif request.json:
                    formdata = werkzeug.datastructures.MultiDict(request.json)
            else:
                formdata = None


        super(Form, self).__init__(formdata, obj, prefix, data, meta, **kwargs)
        
        if meta["csrf"]:
            self.csrf_token.widget = HiddenTag()

    def generate_csrf_token(self, csrf_context=None):
        if not self.csrf_enabled:
            return None
        return generate_csrf(self.SECRET_KEY, self.TIME_LIMIT)

    def validate_csrf_token(self, field):
        if not self.meta.csrf:
            return True
        if hasattr(request, 'csrf_valid') and request.csrf_valid:
            # this is validated by CsrfProtect
            return True

    def validate_csrf_data(self, data):
        """Check if the csrf data is valid.

        .. versionadded: 0.9.0

        :param data: the csrf string to be validated.
        """
        return validate_csrf(data, self.SECRET_KEY, self.TIME_LIMIT)

    def is_submitted(self):
        """
        Checks if form has been submitted. The default case is if the HTTP
        method is **PUT** or **POST**.
        """

        return request and request.method in ("PUT", "POST")

    def validate_on_submit(self):
        """
        Checks if form has been submitted and if so runs validate. This is
        a shortcut, equivalent to ``form.is_submitted() and form.validate()``
        """
        return self.is_submitted() and self.validate()

    @property
    def data(self):
        d = super(Form, self).data
        # https://github.com/lepture/flask-wtf/issues/208
        if self.csrf_enabled:
            d.pop('csrf_token')
        return d

    def _get_translations(self):
        if not current_app.config.get('WTF_I18N_ENABLED', True):
            return None
        return translations
