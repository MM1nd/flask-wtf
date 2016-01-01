from wtforms.widgets import HiddenInput, HTMLString
from flask import current_app
from jinja2 import escape



class HiddenTag(HiddenInput):
    def __call__(self, field, **kwargs):

        actual_input = super(HiddenTag, self).__call__(field, **kwargs)

        name = current_app.config.get('WTF_HIDDEN_TAG', None)
        
        if name:
            attrs = current_app.config.get('WTF_HIDDEN_TAG_ATTRS', {'style': 'display:none;'})

            tag_attrs = u' '.join(u'%s="%s"' % (escape(k), escape(v)) for k, v in attrs.items())
            tag_start = u'<%s %s>' % (escape(name), tag_attrs)
            tag_end = u'</%s>' % escape(name)

            return HTMLString(tag_start+actual_input+tag_end)

        return actual_input
