import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from google.appengine.ext import db
from string import letters


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
