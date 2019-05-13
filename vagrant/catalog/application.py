#! /usr/bin/python

from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   url_for,
                   jsonify,
                   flash,
                   g)
from functools import wraps
from sqlalchemy import create_engine, asc, desc, distinct, or_
from sqlalchemy.orm import sessionmaker
from models import Base, User, Category, CateItem
from flask_httpauth import HTTPBasicAuth

from flask import session as login_session
import flask_login

import random
import string

# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
auth = HTTPBasicAuth()


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///categoryitem.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# query the distinct category name value.
# This will be used for render the Category List
category_distincts = [str(category.name)
                      for category in session.query(Category).all()]


# login_required - for View Decorator to check user login

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if checkLogin():
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('showLogin'))

    return wrap

# Check values in login_session
@app.route('/session', methods=['GET'])
def checkSession():
    if "token" in login_session:
        t = {
            'username': login_session['username'],
            'name': login_session['name'],
            'email': login_session['email'],
            'picture': login_session['picture'],
            'token': login_session['token'],
            'expired': checkLogin()
        }
    else:
        t = {
            "status": "logout"
        }
    return jsonify(t)

# User Profile Page: The page require login to access, if not, it will
# redirect to home page 'showAllItems'
@app.route('/profile')
@login_required
def showProfile():

    return render_template("profile.html",
                           email=login_session.get('email'),
                           picture=login_session.get('session'),
                           user_id=login_session.get('user_id'),
                           username=login_session.get('name'),
                           login=True
                           )


# Edit User name Page:
#     @Template: profile_edit.html
#
#     @method require variable:
#         'user_id': int - user id
#         'name': string - user name
#
#     @allow methods:
#         GET, POST
#
#     @template variable:
#         'user_id': int - user id
#         'name': string -  <input> value
#         'username': string - username
#         'login': boolean - whether to show login button in header
#
#     Page for user login
#     The page require login. If not, it will redirect to Home Page.
#     Once the update succeed, it will redirect back to the User Profile Page.


@app.route(
    '/profile/<string:name>/<int:user_id>/edit',
    methods=[
        'GET',
        'POST'])
@login_required
def editProfile(user_id, name):

    if request.method == 'POST':
        username = request.form['name']
        # query the user by id, then use the form 'name' value to update
        user = session.query(User).filter_by(id=user_id).one()
        user.name = username
        session.add(user)
        session.commit()
        login_session['name'] = username

        # Once succeed, redirect back ro User Profile Page
        return redirect(url_for('showProfile'))

    # GET request - render the template.
    return render_template("profile_edit.html",
                           user_id=user_id,
                           name=name,
                           username=login_session.get('name'),
                           login=True)


# Login Page:
#     @Template: login.html
#
#     @allow methods:
#         GET, POST
#
#     @template variable:
#         'state': string - anti-forgery state token
#         'user_page': boolean - show the login/user info section in Header
#
#     If already logined, it will redirect to Home Page.
# Once the Login succeed, it will refresh the token, save the user info to
# login_session and redirect to the Home Page.


@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    if request.method == 'POST':
        # Post request
        username = request.form['username']
        password = request.form['password']
        # check if user exist and verify password. If False, it will show
        # warning flash message and redirect back to login page
        user = session.query(User).filter_by(username=username).first()
        if not user or not user.verify_password(password):
            flash('Email or password wrong')
            return redirect(url_for('showLogin'))
        else:
            # Login suceed, call login() method to refresh the token and save
            # user info to login_session
            login(user, user.generate_auth_token())
            return redirect(url_for('showAllItems'))
    else:
        # GET request
        if checkLogin():
            # If already logined, redirect to Home Page
            return redirect(url_for('showAllItems'))
        else:
            # Not logined, show the Login Page, and generate the anti-forgery
            # state token
            state = ''.join(
                random.choice(
                    string.ascii_uppercase +
                    string.digits) for x in xrange(32))
            login_session['state'] = state

            # render the Login Page. If user_page = True, header will hide the
            # login button
            return render_template('login.html', STATE=state, user_page=True)


# Registration Page:
#     @Template: registration.html
#
#     @allow methods:
#         GET, POST
#
#     Page for user registration
#     If already logined, it will redirect to Home Page.
#     After registration, it will login & save the user info to login_session.
#     Redirect to the Home Page.
#
@app.route('/registration', methods=['GET', 'POST'])
def registration():
    # POST request
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # check if user name exist by querying the username (unique in DB)
        user = session.query(User).filter_by(username=username).first()

        if user:
            # username has been registered, it will show flask warning message
            # and redirect to Registration Page
            flash('username has been registered')
            return redirect(url_for('registration'))
        else:
            # username does not exist
            # create new user, login, and redirect to Home Page
            newUser = User(username=username)
            if "email" in request.form:
                newUser.email = request.form['email']
            if "name" in request.form:
                newUser.name = request.form['name']
            else:
                newUser.name = "New User"
            newUser.hash_password(password)
            session.add(newUser)
            session.commit()
            login(newUser, newUser.generate_auth_token())
            return redirect(url_for('showAllItems'))

    # render the Registration Page. If user_page = True, header will hide the
    # login button
    return render_template('registration.html', user_page=True)


# Create user function:
def createUser(**kwargs):
    newUser = User()
    # username or email is necessary for registration

    if "username" not in kwargs and "email" not in kwargs:
        return False

    if "username" in kwargs:
        newUser.username = kwargs['username']

    if "email" in kwargs:
        newUser.email = kwargs['email']
    # if only pass 'email' without 'username', it means login with G account
    # will use the email for the unique username
    if "username" not in kwargs and "email" in kwargs:
        newUser.username = kwargs['email']
        newUser.email = kwargs['email']

    if "name" in kwargs:
        newUser.name = kwargs['name']

    if "g_id" in kwargs:
        newUser.g_id = kwargs['g_id']

    if "picture" in kwargs:
        newUser.picture = kwargs['picture']

    if "password" in kwargs:
        newUser.hash_password(kwargs['password'])

    session.add(newUser)
    session.commit()
    return newUser


# Google Login Page:
#     @Template: N/A
#
#     @allow methods:
#         POST
#
#     Page for Google account login.
#     If already logined, it will redirect to Home Page.
# Once the registration succeed, it will auto-login, save the user info to
# login_session and redirect to the Home Page.

@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        name = login_session['username']
        email = login_session['email']
        user = session.query(User).filter(or_(User.username == name,
                                              User.email == email)).first()

        login(user, user.generate_auth_token(),
              access_token=credentials.access_token)

        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    user = session.query(User).filter_by(email=data['email']).first()
    if not user:
        # this G account has not been register, register new user in DB
        print ("register new account")
        user = createUser(
            username=data['email'],
            name=data['name'],
            picture=data['picture'],
            email=data['email'])

    # Login user and save the info to login_session
    token = user.generate_auth_token()
    login(user, token)

    return "login"

# login() function - save logined user info to login_session
#   @Parameter:
#       'user': user object
#       'token': user token
#       'kwargs': for access_token from G account login
#


def login(user, token, **kwargs):
    # update the login_session
    login_session['name'] = user.name
    login_session['username'] = user.username
    login_session['picture'] = user.picture
    login_session['email'] = user.email
    login_session['token'] = token
    login_session['user_id'] = user.id
    if "access_token" in kwargs:
        login_session['access_token'] = kwargs['access_token']

    return user


# Logout Page:
#     @Template: N/A
#
#     @allow methods:
#         POST
#
#     Page for account logout.
#     If login with G account, will call G Oauth2 API to revoke access token.
#     If logout, it will clear the login_session and return JSON response.
#
@app.route('/logout', methods=['POST'])
def logout():
    g_connected = login_session.get('access_token')
    print ("g_connect:", g_connected)
    if g_connected is not None:
        # disconnect with G account, call API to revoke G access token
        url = 'https://accounts.google.com/o/oauth2/ \
               revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] != '200':
            response = make_response(
                json.dumps(
                    'Failed to revoke token for given user.',
                    400))
            response.headers['Content-Type'] = 'application/json'

    # clear login_session and build response
    login_session.clear()
    response = make_response(json.dumps('Already Logout', 200), 200)
    response.headers['Content-Type'] = 'application/json'
    return response

# checkLogin() function - check if user logined by verifying token


def checkLogin():
    # if keyword 'token' in login_session
    # if not, return False
    if 'token' not in login_session:
        return False
    # verify if the token expired
    v_token = User.verify_auth_token(login_session['token'])

    # if token expired, call logout() function
    if v_token is None:
        print ("token expired")
        logout()
        return False
    else:
        return True
    return False

# Home/Category Page:
#     @Template: category.html
#
#     @allow methods:
#         GET
#     @template variable:
#         'categories': array<string> - all distinct category name in DB
#         'latest_items': array<CateItem> - the 5 latest category items
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     Home page that will list all the category and the lastest 5 items.
#     Will latest 5 items from table CateItem
#
@app.route('/')
@app.route('/category')
# @auth.login_required
def showAllItems():
    # query data from DB
    latest_items = session.query(CateItem).order_by(
        desc(CateItem.created_date)).limit(6).all()
    # return "front page of app"
    return render_template('category.html',
                           categories=category_distincts,
                           latest_items=latest_items,
                           login=checkLogin(),
                           username=login_session.get('name'))

# Category Item Page:
#     @Template: categoryItem.html
#
#     @allow methods:
#         GET
#     @template variable:
#         'categories': array<string> - all distinct category name in DB
#         'items': array<CateItem> - category items of selected category
#         'category_name': string - selected category name
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     Category item page that list all the category item of selected category.
#     Query all items with the selected category name from table CateItem
#
@app.route('/category/<string:category_name>')
def showCategoryItem(category_name):
    # query data from DB
    category_items = session.query(CateItem).join(Category).filter(
        Category.name == category_name).order_by(asc(CateItem.name)).all()

    return render_template('categoryItem.html',
                           categories=category_distincts,
                           items=category_items,
                           category_name=category_name,
                           login=checkLogin(),
                           username=login_session.get('name')
                           )

# Item Page:
#     @Template: item.html
#
#     @allow methods:
#         GET
#     @template variable:
#         'items': CateItem - selected category item
#         'category_name': string - selected category name
#         'owner': boolean - if the login user is the item owner
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     Item page that will show the description of selected item.
#     Will query the selected item from table CateItem
#
@app.route('/category/<string:category_name>/<string:item_name>')
def showItemDetail(category_name, item_name):
    owner = False
    item = session.query(CateItem).join(Category).filter(
        Category.name == category_name).filter(
        CateItem.name == item_name).one_or_none()
    if checkLogin() and login_session['username'] == item.user.username:
        owner = True

    return render_template('item.html',
                           category_name=category_name,
                           item=item,
                           owner=owner,
                           login=checkLogin(),
                           username=login_session.get('name'))


# New Item Page:
#     @Template: item_new.html
#
#     @allow methods:
#         GET, POST
#
#     @template variable:
#         'categories': array<string> - all distinct category name in DB
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     New Item page to create new category item.
#     The page require login. If not, it will redirect back to Home Page
#
@app.route('/category/new', methods=['GET', 'POST'])
@login_required
def newItem():
    if request.method == 'POST':
        # POST request
        # Get value from form and create new category item
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        newItem = CateItem(name=request.form['name'],
                           description=request.form['description'],
                           category=category,
                           user_id=login_session.get('user_id'))
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        # redirect to Home Page
        return redirect(url_for('showAllItems'))
    else:
        # GET request
        # render the item_new.html template
        return render_template("item_new.html",
                               categories=category_distincts,
                               username=login_session.get('name'),
                               login=checkLogin())

# Edit Item Page:
#     @Template: item_edit.html
#
#     @allow methods:
#         GET, POST
#
#     @template variable:
#         'category_name': string - category name of the selected item
#         'item': CateItem - the selected item object
#         'categories': array<string> - all distinct category name in DB
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     Edit Item page to edit category item.
#     The page require login. If not, it will redirect back to Home Page
#     Only item owner can access the item edit page.
#     if not, it will show warning page
#


@app.route(
    '/category/<string:category_name>/<string:item_name>/edit',
    methods=[
        'GET',
        'POST'])
@login_required
def editItem(category_name, item_name):

    # Get the select item object
    item = session.query(CateItem).join(Category).filter(
        Category.name == category_name).filter(
        CateItem.name == item_name).one_or_none()
    if request.method == 'POST':
        # POST request
        # Get from value to update item

        if request.form['name'] and request.form['name'] != item.name:
            item.name = request.form['name']
        if request.form['description'] \
           and request.form['description'] != item.description:
            item.description = request.form['description']
        if request.form['category'] \
           and request.form['category'] != item.category.name:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            item.category = category
        session.add(item)
        session.commit()
        flash('Category Item Successfully Edited')
        # redirect to selected Category Item Page
        return redirect(
            url_for(
                'showCategoryItem',
                category_name=request.form['category']))
    else:
        # GET request
        # Only owner can edit the item, check if current is owner first
        owner = False
        item = session.query(CateItem).join(Category).filter(
            Category.name == category_name).filter(
            CateItem.name == item_name).one_or_none()
        if checkLogin(
        ) and login_session['username'] == item.user.username:
            owner = True
        # If user is the item owner, render the item_edit.html template
        if owner:
            return render_template("item_edit.html",
                                   category_name=category_name,
                                   item=item,
                                   categories=category_distincts,
                                   username=login_session.get('name'),
                                   login=checkLogin())

        # If not owner, render the warning.html template
        return render_template(
            "warning.html",
            message="Only authorized for owner, redirecting to home page.")


# Delete Item Page:
#     @Template: item_delete.html
#
#     @allow methods:
#         GET, POST
#
#     @template variable:
#         'category_name': string - category name of the selected item
#         'item_name': CateItem - the selected item object
#         'login': boolean - hide/show the login button and user preference bar
#         'username': string - use for name in user preference bar
#
#     Delete Item page to delete category item.
#     The page require login. If not, it will redirect back to Home Page
#


@app.route(
    '/category/<string:category_name>/<string:item_name>/delete',
    methods=[
        'GET',
        'POST'])
@login_required
def deleteItem(category_name, item_name):

    if request.method == 'POST':
        # POST request
        item = session.query(CateItem).join(Category).filter(
            Category.name == category_name).filter(
            CateItem.name == item_name).one_or_none()
        session.delete(item)
        session.commit()
        flash('Item Successfully Deleted')
        # redirect back to category item page
        return redirect(url_for('showCategoryItem',
                                category_name=category_name,
                                login=True),
                        username=login_session.get('name'))
    else:
        # check if login user is owner.
        owner = False
        item = session.query(CateItem).join(Category).filter(
            Category.name == category_name).filter(
            CateItem.name == item_name).one_or_none()
        if checkLogin(
        ) and login_session['username'] == item.user.username:
            owner = True
        if owner:
            return render_template("item_delete.html",
                                   category_name=category_name,
                                   item_name=item_name,
                                   login=checkLogin(),
                                   username=login_session.get('username'))

        return render_template(
            "warning.html",
            message="Only authorized for owner, redirecting to home page.")


# Warning Page:
#     @Template: warning.html
#
#     @allow methods:
#         GET
#
#     @template variable:
#         'message': string - the display warning message
#
#     Warning page to show warning message.
#     If no message input, the page will show '404 404 404' by default
#
@app.route('/warning')
def showWarningPage(**kwargs):
    # Only authorized for owner, will redirect to home page....
    message = "404 404 404"
    if "message" in kwargs:
        message = kwargs['message']
    return render_template("warning.html",
                           message=message,
                           login=checkLogin(),
                           username=login_session.get('name'))


# JSON APIs to view Categories Information
@app.route('/category/JSON')
def showAllCategoryJSON():
    categories = session.query(Category).order_by(asc(Category.name)).all()
    return jsonify(Category=[i.serialize for i in categories])

# JSON APIs to view Category Items Information
@app.route('/category/<string:category_name>/JSON')
def showCategoryItemJSON(category_name):
    category_items = session.query(CateItem).join(Category).filter(
        Category.name == category_name).order_by(asc(CateItem.name)).all()
    return jsonify(CateItem=[i.serialize for i in category_items])

# JSON APIs to view Item Information
@app.route('/category/<string:category_name>/<string:item_name>/JSON')
def showCategoryItemDetailJSON(category_name, item_name):
    item = session.query(CateItem).join(Category).filter(
        Category.name == category_name).filter(
        CateItem.name == item_name).one_or_none()
    return jsonify(CateItem=item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
