import os
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
    
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):

    def render_str(template,**params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

class MainPage(BlogHandler):
    def get(self):
        self.write("Welcome to Multiblog!!")

def ValidateUsername(username):
	username_pattern = r"^[a-zA-Z0-9_-]{3,15}$"
	pattern = re.compile(username_pattern)
	return pattern.match(username)

def ValidatePassword(password):
	password_pattern = r"^[a-zA-Z0-9_]{6,15}$"
	pattern = re.compile(password_pattern)
	return password and pattern.match(password)

def ValidateEmail(email):
	email_pattern = r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$"
	pattern = re.compile(email_pattern)
	return email and pattern.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username, email = email)

        if not ValidateUsername(username):
        	params['error_username'] = "Not a valid Username"
        	have_error = True

        if not ValidatePassword(password):
        	params['error_password'] = "Not a valid Password"
        	have_error = True
        elif password != verify:
        	params['error_verify'] = "Password not a match!"
        	have_error = True

        if not ValidateEmail(email):
        	params['error_email'] = "Not a valid Email Address"
        	have_error = True

        if have_error:	
        	self.render('signup.html', **params)
        else:
            self.redirect('/welcome?username=' + username)

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        params = dict(username = username)
        if ValidateUsername(username):
            self.render('welcome.html', **params)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage), 
                               ('/signup', Signup),
                               ('/welcome', Welcome)],
                              debug=True)