import os
import re
from string import letters
import random 
import hashlib
import hmac 
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'notyoursecret'

def make_hashed_val(val):
    hashed_val = hmac.new(secret,val).hexdigest()
    return '%s|%s' % (val,hashed_val)

def check_hashed_val(hashed_val):
    val = hashed_val.split('|')[0]
    if hashed_val == make_hashed_val(val):
        return val 
    
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

    def set_secure_cookie(self,user,val):
        hashed_val = make_hashed_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (user,hashed_val))

    def read_secure_cookie(self,user):
        cookie_val = self.request.cookies.get(user)
        if check_hashed_val(cookie_val):
            return cookie_val

    def login(self,user):
        self.set_secure_cookie('user_id',str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')

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

class SignupHandler(BlogHandler):

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

class WelcomeHandler(BlogHandler):
    def get(self):
        username = self.request.get('username')
        params = dict(username = username)
        if ValidateUsername(username):
            posts = db.GqlQuery("select * from BlogPost order by created desc limit 10")
            self.render('welcome.html', **params)
        else:
            self.redirect('/signup')

class BlogPost(db.Model):
    title = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFrontHandler(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from BlogPost order by created desc limit 10")
        self.render('front.html', posts = posts)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def make_salt(length=5):
    return ''.join(random.choice(string.letters) for i in range(length))

def make_pwd_hash(user, pwd, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(user + pwd + salt).hexdigest()
    return '%s,%s' % (salt,h)

def validate_hashed_pwd(user,pwd,h):
    salt = h.split(',')[0]
    return h == make_pw_hash(user, pwd, salt)

class User(db.Model):
    
    user = db.StringProperty(required = True)
    pwd_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

    @classmethod
    def get_user(cls,user):
        u = User.all().filter('user =', user).get()
        return u 
    
    @classmethod
    def signin(cls,user,pwd):
        u = cls.get_user(user)
        if u and validate_hashed_pwd(user,pwd,u.pwd_hash):
            return u 

    @classmethod 
    def register(cls,user,pwd,email):
        pwd_hash = make_pwd_hash(user, pwd)
        return User(parent = users_key(), user = user, pwd_hash = pwd_hash, email = email)

class SigninHandler(BlogHandler):
    
    def get(self):
        self.render('signin.html')
    
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.signin(username,password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = "Invalid login info"
            self.render('signin.html', error = msg)

class RegisterHandler(SignupHandler):
    
    def done(self):
        u = User.get_user(self.username)
        if u:
            msg = "User already exist!"
            self.render('signin.html', error_username = msg)
        else: 
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.redirect('/welcome')

class SignoutHandler(BlogHandler):
    
    def get(self):
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([('/', BlogFrontHandler), 
                               ('/signup', RegisterHandler),
                               ('/welcome', WelcomeHandler),
                               ('/signin', SigninHandler), 
                               ('/signout', SignoutHandler)], debug=True)

