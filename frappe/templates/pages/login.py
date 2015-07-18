# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
import frappe
import json
import frappe.utils
from frappe import _
import urllib2

class SignupDisabledError(frappe.PermissionError): pass

no_cache = True

WEIXIN_CORPID = ""
WEIXIN_CORPSECRET = frappe.local.conf.wx_secret or ""

WEIXIN_ACCESSTOKEN_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid="
WEIXIN_USERINFO_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?"
WEIXIN_USERINFO_GET = "https://qyapi.weixin.qq.com/cgi-bin/user/get?"
WEIXIN_OAUTH2_AUTHORIZE_ADDR = "https://open.weixin.qq.com/connect/oauth2/authorize?"
WEIXIN_SENDMSG_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token="
WEIXIN_AUTH_SUCC = "https://qyapi.weixin.qq.com/cgi-bin/user/authsucc?access_token="

def get_context(context):
	if frappe.session.user != "Guest" and frappe.session.data.user_type=="System User":
		frappe.local.flags.redirect_location = "/desk"
		raise frappe.Redirect

	# get settings from site config
	context["title"] = "Login"
	context["disable_signup"] = frappe.utils.cint(frappe.db.get_value("Website Settings", "Website Settings", "disable_signup"))

	for provider in ("google", "github", "facebook"):
		if get_oauth_keys(provider):
			context["{provider}_login".format(provider=provider)] = get_oauth2_authorize_url(provider)
			context["social_login"] = True

	return context

oauth2_providers = {
	"google": {
		"flow_params": {
			"name": "google",
			"authorize_url": "https://accounts.google.com/o/oauth2/auth",
			"access_token_url": "https://accounts.google.com/o/oauth2/token",
			"base_url": "https://www.googleapis.com",
		},

		"redirect_uri": "/api/method/frappe.templates.pages.login.login_via_google",

		"auth_url_data": {
			"scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
			"response_type": "code"
		},

		# relative to base_url
		"api_endpoint": "oauth2/v2/userinfo"
	},

	"github": {
		"flow_params": {
			"name": "github",
			"authorize_url": "https://github.com/login/oauth/authorize",
			"access_token_url": "https://github.com/login/oauth/access_token",
			"base_url": "https://api.github.com/"
		},

		"redirect_uri": "/api/method/frappe.templates.pages.login.login_via_github",

		# relative to base_url
		"api_endpoint": "user"
	},

	"facebook": {
        "flow_params": {
            "name": "weixin",
            "authorize_url": "https://open.weixin.qq.com/connect/oauth2/authorize",
            "access_token_url": "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            "base_url": "https://qyapi.weixin.qq.com"
        },

        "redirect_uri": "/api/method/frappe.templates.pages.login.login_via_weixin",

        "auth_url_data": {
            "response_type": "code",
            'scope': 'snsapi_base',
            'appid': WEIXIN_CORPID,
        },

        # relative to base_url
        "api_endpoint": "cgi-bin/user/getuserinfo"
    }
}

def get_oauth_keys(provider):
	"""get client_id and client_secret from database or conf"""

	# try conf
	keys = frappe.conf.get("{provider}_login".format(provider=provider))

	if not keys:
		# try database
		social = frappe.get_doc("Social Login Keys", "Social Login Keys")
		keys = {}
		for fieldname in ("client_id", "client_secret"):
			value = social.get("{provider}_{fieldname}".format(provider=provider, fieldname=fieldname))
			if not value:
				keys = {}
				break
			keys[fieldname] = value

	return keys

def get_oauth2_authorize_url(provider):
	flow = get_oauth2_flow(provider)

	# relative to absolute url
	data = { "redirect_uri": get_redirect_uri(provider) }

	# additional data if any
	data.update(oauth2_providers[provider].get("auth_url_data", {}))

	return flow.get_authorize_url(**data)

def get_oauth2_flow(provider):
	from rauth import OAuth2Service

	# get client_id and client_secret
	params = get_oauth_keys(provider)

	# additional params for getting the flow
	params.update(oauth2_providers[provider]["flow_params"])

	# and we have setup the communication lines
	return OAuth2Service(**params)

def get_redirect_uri(provider):
	redirect_uri = oauth2_providers[provider]["redirect_uri"]
	return frappe.utils.get_url(redirect_uri)

@frappe.whitelist(allow_guest=True)
def login_via_google(code):
	login_via_oauth2("google", code, decoder=json.loads)

@frappe.whitelist(allow_guest=True)
def login_via_github(code):
	login_via_oauth2("github", code)

@frappe.whitelist(allow_guest=True)
def login_via_facebook(code):
	login_via_oauth2("facebook", code)

def login_via_oauth2(provider, code, decoder=None):
	flow = get_oauth2_flow(provider)

	args = {
		"data": {
			"code": code,
			"redirect_uri": get_redirect_uri(provider),
			"grant_type": "authorization_code"
		}
	}
	if decoder:
		args["decoder"] = decoder

	session = flow.get_auth_session(**args)

	api_endpoint = oauth2_providers[provider].get("api_endpoint")
	info = session.get(api_endpoint).json()

	if "verified_email" in info and not info.get("verified_email"):
		frappe.throw(_("Email not verified with {1}").format(provider.title()))

	login_oauth_user(info, provider=provider)

@frappe.whitelist(allow_guest=True)
def login_oauth_user(data=None, provider=None, email_id=None, key=None):
	if email_id and key:
		data = json.loads(frappe.db.get_temp(key))
		data["email"] = email_id

	elif not (data.get("email") and get_first_name(data)) and not frappe.db.exists("User", data.get("email")):
		# ask for user email
		key = frappe.db.set_temp(json.dumps(data))
		frappe.db.commit()
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = "/complete_signup?key=" + key
		return
	
	user = data["email"]
	result = 1
	try:
		result = update_oauth_user(user, data, provider)
	except SignupDisabledError:
		return frappe.respond_as_web_page("Signup is Disabled", "Sorry. Signup from Website is disabled.",
			success=False, http_status_code=403)

	if result ==0 :
		return
	
	# frappe.local.login_manager.clear_cookies()
	frappe.local.login_manager.user = user
	frappe.local.login_manager.post_login()
	
	# redirect!
	frappe.local.response["type"] = "redirect"

	# the #desktop is added to prevent a facebook redirect bug
	frappe.local.response["location"] = "/desk#desktop" if frappe.local.response.get('message') == 'Logged In' else "/"

	# because of a GET request!
	frappe.db.commit()

def update_oauth_user(user, data, provider):
	if isinstance(data.get("location"), dict):
		data["location"] = data.get("location").get("name")

	save = False

	if not frappe.db.exists("User", user):
		frappe.respond_as_web_page("Not found user",
				"<pre>please contract system manager.</pre>",
				http_status_code=401)
		response = frappe.website.render.render("message", http_status_code=401)
		return 0
		# is signup disabled?
		if frappe.utils.cint(frappe.db.get_single_value("Website Settings", "disable_signup")):
			raise SignupDisabledError

		save = True
		user = frappe.new_doc("User")
		gender = ""
		sex = (data.get("gender") or "")
		if (sex == "1"):
			gender = "Male"
		elif (sex == "2"):
			gender = "Female"
		elif (sex == "3"):
			gender = "Other"
		
		user.update({
			"doctype":"User",
			# "name":data["userid"],
			"first_name": get_first_name(data),
			"last_name": get_last_name(data),
			"email": data["email"],
			"gender": gender.title(),
			"enabled": 0,
			"new_password": frappe.generate_hash(data["email"]),
			"location": data.get("location"),
			"user_type": "System User",
			"user_image": data.get("picture") or data.get("avatar_url")
		})

	else:
		user = frappe.get_doc("User", user)
		if (user.enabled == 0):
			frappe.respond_as_web_page("Login failed",
				"<pre>User is disabled!</pre>",
				http_status_code=401)
			response = frappe.website.render.render("message", http_status_code=401)
			return 0

	if save:
		user.flags.ignore_permissions = True
		user.flags.no_welcome_mail = True
		user.save()
		
	return 1

def get_first_name(data):
	return data.get("first_name") or data.get("given_name") or data.get("name") or data.get("email")

def get_last_name(data):
	return data.get("last_name") or data.get("family_name")

@frappe.whitelist(allow_guest=True)
def login_via_weixin(code, appid, path):
    provider = 'weixin'
    WEIXIN_CORPID = appid

    token = getAccessToken(appid)
    url = WEIXIN_USERINFO_ADDR + "access_token=" + token + "&code=" + code
    resp = urllib2.urlopen(url)
    description = json.loads(resp.read())
    userId = description.get('UserId', None)
	
    if userId == None:
        frappe.throw(url)
    else:
    	#get user info
    	geturl = WEIXIN_USERINFO_GET + "access_token=" + token + "&userid=" + userId
    	inforesp = urllib2.urlopen(geturl)
    	infojson = json.loads(inforesp.read())
    	
    	login_oauth_user({"userid":userId,"name":infojson.get("name",userId),"gender":infojson.get('gender'),"email":infojson.get('email')}, provider=provider)
    	authSucc(token, userId)
    location = "desk#" + path
    frappe.local.response["location"] = location


def authSucc(token, userid):
    url_auth_suc = WEIXIN_AUTH_SUCC + token + "&userid=" + userid
    resp = urllib2.urlopen(url_auth_suc)
    description = json.loads(resp.read())


def getAccessToken(appid):
	addr = WEIXIN_ACCESSTOKEN_ADDR + appid + "&corpsecret=" + WEIXIN_CORPSECRET
	resp = urllib2.urlopen(addr)
	description = json.loads(resp.read())
	token = description["access_token"]
	return token
