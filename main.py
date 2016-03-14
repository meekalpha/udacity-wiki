import os
import jinja2
import webapp2
import re
import logging
import random
import string
import hashlib	#passwords
import hmac #secure cookies

from time import sleep

from google.appengine.ext import db 
from google.appengine.api import memcache


SECRET = 'blizzcon'

################### TEMPLATE SETUP #############

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)
################### USEFUL FUNCTIONS ###########
########### page lists #################
def recently_edited_pages(n=5):
	pages = db.GqlQuery("SELECT * FROM Page ORDER BY last_modified DESC")[:n]
	return list(pages)

def newest_pages(n=5):
	pages = db.GqlQuery("SELECT * FROM Page ORDER BY created DESC")[:n]
	return list(pages)

########### password validation #######
def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h,salt)

def valid_pw(name, pw, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

############# cookie validation ######
def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

########### Regular Expressions, Input Validation #################
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

################### MODELS #####################
class Page(db.Model):
	page_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_page_id(cls, page_id):
		return cls.all().filter('page_id',page_id).get()

class User(db.Model):
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls,username):
		return cls.all().filter('username', username).get()

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return cls(	parent = users_key(),
					username = name,
					password = pw_hash,
					email = email)

	@classmethod
	def login(cls, username, password):
		u = cls.by_name(username)
		if u and valid_pw(username, password, u.password):
			return u

################### HANDLERS ###################

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		kw['user'] = self.user
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id',str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

class MainHandler(Handler):
	def get(self):
		self.redirect('/main')

class MainEditHandler(Handler):
	def get(self):
		self.redirect('/_edit/main')

class PageHandler(Handler):
	def get(self, page_id):
		content = ""
		p = Page.by_page_id(page_id)
		if p:
			content = p.content
		else:
			self.redirect('/_edit/%s' % page_id)
		recently_edited = recently_edited_pages()
		newest = newest_pages()
		self.render('wiki_page.html', 	page_id = page_id, 
										content=content, 
										recently_edited=recently_edited,
										newest=newest)

class EditHandler(Handler):
	def render_front(self, page_id = "", content=""):
		p = Page.by_page_id(page_id)
		if p:
			content = p.content
		self.render('edit.html',content=content)

	def get(self, page_id):
		if self.user:
			self.render_front(page_id)
		else:
			self.render("message.html", message = "You must be logged in to edit posts!")

	def post(self, page_id):
		if self.user:
			content = self.request.get("content")
			p = Page.by_page_id(page_id)
			if p:
				p.content = content
			else:
				p = Page(page_id=page_id, content=content)
			p.put()
			sleep(0.1)
			self.redirect("/%s"%page_id)
		else:
			self.render("message.html", message = "You must be logged in to edit posts!")

class SignupHandler(Handler):
	def done(self):
		u = User.by_name(self.username)
		if u:
			self.render('signup_form.html', error_username = "That username is taken")
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.redirect('/')

	def get(self):
		self.render("signup_form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup_form.html', **params)
		else:
			self.done()

class LoginHandler(Handler):
	def get(self):
		self.render('login_form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		
		if u:
			self.login(u)
			self.redirect('/welcome')
		else:
			self.render('login_form.html',
						username=username, 
						error = "Incorrect username or password")

class WelcomeHandler(Handler):
	def get(self):
		if self.user:
			username = self.user.username
			self.render("message.html", message = "Welcome, %s!" % username)
class LogoutHandler(Handler):
	def get(self):
		self.logout()
		self.redirect('/')

class UIDHandler(Handler):
	def get(self):
		self.write(self.read_secure_cookie('user_id'))

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/userid/?', UIDHandler),
	('/login/?', LoginHandler),
	('/logout/?', LogoutHandler),
	('/signup/?', SignupHandler),
	('/welcome/?', WelcomeHandler),
	('/_edit/?', MainEditHandler),
	('/(\w+)/?', PageHandler),
	('/_edit/(\w+)/?', EditHandler),
], debug=True)