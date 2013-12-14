#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
import jinja2
import hashlib
import hmac
import re
import random
import sys
import urllib2
import json
from xml.dom import minidom
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), '')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

art_key = db.Key.from_path('ASCIIChan', 'arts')
IP_URL = "http://api.hostip.info/?ip="
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
SECRET = "imsosecret"
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PSSWD_RE = re.compile(r"^.{3,20}$")
VERIFY_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())
def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val
def valid_user(name, pw):
	user = get_user(name)
	if user and user.password_hash == 1 + (pwd):
		return user
def valid_password(name, pw, h):
	salt = h.split('|')[1]
	print "name: " + str(name)
	print "pw: " + str(pw)
	print "h: " + str(h)
	print "hash: " + str('%s,%s' % (hashlib.sha256(name+pw+salt).hexdigest(),salt))
	return (h == ('%s|%s' % (hashlib.sha256(name+pw+salt).hexdigest(),salt)))
def verify_username(username):
	return USER_RE.match(username)
def verify_password(password):
	return PSSWD_RE.match(password)
def verify_email(email):
	return EMAIL_RE.match(email)
def escape_html(s):
	return cgi.escape(s, quote = True)
def make_salt():
	return str(random.randrange(0, 99999))
def check_secure(h, pw):
	val = h.split('|')[1]
	if h == make_hash(val, pw):
		return val
def make_hash(name, pw):
	salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s|%s' % (h, salt)
def users_key(group = 'default'):
	return db.key.from_path('users', group)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	@classmethod
	def by_id(cls, user_id):
		return User.get_by_id(user_id, parent = users_key())

class Blog(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	def render_json(self, d):
		json_txt = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.write(json_txt)

class BlogPageHandler(Handler):
	def render_front(self, subject="", content="", error=""):
		blogs = db.GqlQuery("select * from Blog order by created desc")
		self.render("front.html", subject=subject, content=content, error=error, blogs=blogs)
	def self_render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	def get(self):
		# Get User Info From Cookie
		#cookie_val = str(self.request.cookies.get('user_id', ''))
		#user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		#if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
		self.render_front()
		#else:
			# Return back to signup page if invalid cookie
			#self.redirect('/signup')

class BlogPageJSONHandler(Handler):
	def get(self):
		# Get User Info From Cookie
		#cookie_val = str(self.request.cookies.get('user_id', ''))
		#user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		#if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
		self.render_front()
		#else:
			# Return back to signup page if invalid cookie
			#self.redirect('/signup')
	def render_front(self, subject="", content="", error=""):
		blogs = db.GqlQuery("select * from Blog order by created desc")
		blogs = list(blogs)
		json_blogs_list = []
		time_fmt = '%c'
		for blog in blogs:
			json_blogs_entry = {
				'subject': blog.subject,
				'content': blog.subject,
				'created': blog.created.strftime(time_fmt),
				'last_modified': blog.last_modified.strftime(time_fmt)
			}
			#self.render_json(json_blogs_entry)
			json_blogs_list.append(json_blogs_entry)
		self.render_json(json_blogs_list)

class NewPostPageHandler(Handler):
	def render_post(self, subject="", content="", error=""):
		self.render("newpost.html", subject=subject, content=content, error=error)
	def self_render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	def get(self):
		# Get User Info From Cookie
		cookie_val = str(self.request.cookies.get('user_id', ''))
		user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
			self.render_post()
		else:
			# Return back to signup page if invalid cookie
			self.redirect('/signup')
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		if subject and content:
			b = Blog(subject = subject, content = content)
			b_key = b.put()      
			self.redirect("/blog/%d" % b_key.id())
		else:
			error = "We need both a subject and some text!"
			self.render_post(subject, content, error)

class PermalinkHandler(BlogPageHandler):
	def get(self, blog_id):# Get User Info From Cookie
		cookie_val = str(self.request.cookies.get('user_id', ''))
		user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
			s = Blog.get_by_id(int(blog_id))
			self.render("front.html", blogs=[s])
		else:
			# Return back to signup page if invalid cookie
			self.redirect('/signup')

class PermalinkJSONHandler(BlogPageHandler):
	def get(self, blog_id):
		cookie_val = str(self.request.cookies.get('user_id', ''))
		user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
			self.render_front(blog_id=blog_id)
		else:
			# Return back to signup page if invalid cookie
			self.redirect('/signup')
	def render_front(self, subject="", content="", error="", blog_id=""):
		blog = Blog.get_by_id(int(blog_id))
		time_fmt = '%c'
		json_blogs_entry = {
			'subject': blog.subject,
			'content': blog.subject,
			'created': blog.created.strftime(time_fmt),
			'last_modified': blog.last_modified.strftime(time_fmt)
		}
		self.render_json(json_blogs_entry)

class SignupHandler(Handler):
	def write_signup_form(self, username="", error_username="", password="", error_password="",
		 verify="", error_verify="", email="", error_email=""):
		# Update Form
		self.render("index.html", username=username, error_username=error_username, password=password,
		 error_password=error_password, verify=verify, error_verify=error_verify, email=email, error_email=error_email)
	def get(self):
		# Render Forum for user to reis
		self.write_signup_form()
	def post(self):
		# Get User Input
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		# Status Codes
		status_error = False
		error_username = ""
		error_password = ""
		error_verify = ""
		error_email = ""
		# Verify User Info
		if not verify_username(username):
			error_username = "That's not a valid username. "
			status_error = True
		if not verify_password(password):
			error_password = "That wasn't a valid password. "
			status_error = True
		else:
			if password != verify:
				error_verify = "Your passwords didn't match "
				status_error = True
		if email:
			if not (verify_email(email)):
				error_email = "That's not a valid email "
				status_error = True
		# Verify username does not already exist
		query = "select * from User where username =:usr"
		users = db.GqlQuery(query, usr=username)
		for user in users:
			if user.username == username:
				status_error = True
				error_username = "Username already exist"
		if status_error:
			# Report Errors
			self.write_signup_form(username, error_username, password, error_password, verify, error_verify, email, error_email)
		else:
			# Store User Info
			# Hash Password, store in Database
			hashed_pwd = str(make_hash(username, password))
			u = User(username=username, password=hashed_pwd, email=email)
			u.put()
			# Get User's Database ID
			user_id = (u.key().id())
			# Hash and Store in Cookie
			hashed_usr = make_secure_val(str(user_id))
			cookie_val = 'user_id=' + hashed_usr + '; Path=/'
			self.response.headers['Content-Type'] = 'text/plain'
			self.response.headers.add_header('Set-Cookie', str(cookie_val))
			# Redirect to Welcome Page
			#self.response.out.write("Redirecting to welcome handler")
			self.redirect('/welcome')
			#self.redirect('/blog')

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		# Get User Info From Cookie
		cookie_val = str(self.request.cookies.get('user_id', ''))
		user_id = cookie_val.split('|')[0]
		# Verify valid cookie
		#if user_id and cookie_val and (cookie_val == make_secure_val(user_id)):
		# Get User from database using User_ID 
		usr = User.get_by_id(int(user_id))
		username = usr.username
		# Welcome User
		self.response.out.write("Welcome, %(username)s!" % {"username": username})
		"""else:
			# Return back to signup page if invalid cookie
			self.redirect('/signup')"""

class FrontPageHandler(webapp2.RequestHandler):
	def get(self):
		self.response.out.write("Welcome to my blog.")

class LoginHandler(Handler):
	def write_login_form(self, login_error=""):
		# Update Login
		self.render("login.html", login_error=login_error)
	def get(self):
		self.write_login_form()
	def post(self):
		# Initialize Status Codes
		status_error = True
		login_error = ""
		# Get User Input
		username = self.request.get('username')
		password = self.request.get('password')
		# Verify User Info
		# Get User Entity from Database 
		query = "select * from User where username =:usr"
		users = db.GqlQuery(query, usr=username)
		# If User exist
		if users:
			for user in users:
				# Verify username from login matches database and check if valid hash
				print "user.password: " + str(user.password)
				print "password: " + str(password)
				if (user.username == username) and valid_password(username, password, user.password):
					# Update Status
					status_error = False
		if status_error:
			login_error = "Invalid Login"
			self.write_login_form(login_error)
		else:
			# Store User Info in Cookie
			# Get User's Database ID
			user_id = user.key().id()
			#user_id = user.get_by_id()  
			# Hash and Store in Cookie
			hashed_usr = make_secure_val(str(user_id))
			cookie_val = 'user_id=' + hashed_usr + '; Path=/'
			self.response.headers['Content-Type'] = 'text/plain'
			self.response.headers.add_header('Set-Cookie', str(cookie_val))
			# Redirect to Welcome Page
			self.redirect('/welcome')
			#self.redirect('/blog')

class LogoutHandler(Handler):
	def get(self):
		# Reset cookie if user has one
		#self.response.headers['Content-Type'] = 'text/plain'
		self.response.headers['Content-Type'] = 'application/json'
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		# Redirect to Welcome Page
		self.redirect('/signup')

app = webapp2.WSGIApplication([
	#('/', FrontPageHandler),
	#('/blog.json', FrontPageJSON),
	#('/', WelcomeNewHandler),
	('/blog', BlogPageHandler),
	('/blog.json', BlogPageJSONHandler),
	('/newpost', NewPostPageHandler),
	('/blog/(\d+).json', PermalinkJSONHandler),
	('/blog/(\d+)', PermalinkHandler),
	('/signup', SignupHandler),
	('/welcome', WelcomeHandler),
	('/login', LoginHandler),
	('/logout', LogoutHandler)], debug=True)
