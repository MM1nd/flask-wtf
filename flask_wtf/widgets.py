from wtforms.widgets import HiddenInput, HTMLString
from flask import current_app
from jinja2 import escape


class HiddenTag(HiddenInput):

    """ 
    Apparently XHTML requires hidden inputs to be wrapped in another tag.
    This is none of our business, since Widgets and Templates are both there to solve such problems.
    Old falsk-wtf's "hidden_tag" was a purely convinience method with a very limited usecase.
    In order not to brak with functionality users have come to expect from flask-wtf,
    we provide a HiddenTag Widget that can be used to wrap inputs on a per field basis.
    
    This will return the same as vanilla HiddenInput, unless 'WTF_HIDDEN_TAG' is provided in flask's configuration.
    Then it will wrap the field in the provided tag. Optionally, a dictionary 'WTF_HIDDEN_TAG_ATTRS' may be provided,
    if not it will default to {'style': 'display:none;'}.

    Note that the original hidden_tag function wrapped all hidden inputs in the same tag,
    this might have been counter-intuitive and is no longer so. 

    """

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
