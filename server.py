from flask import Flask, render_template, request, redirect, session,flash # added request
# mysql connection is in lower case b/c is file name!
from mysqlconnection import connectToMySQL
#import hashing stuffs
from flask_bcrypt import Bcrypt
#import email validation
import re # import regex for email validation

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = 'keep it secret, keep it safe' # set a secret key for security purposes
bcrypt = Bcrypt(app)     # we are creating an object called bcrypt,
                         # which is made by invoking the function Bcrypt with our app as an argument

@app.route('/')
def index():

    return render_template('index.html')


@app.route('/process', methods=['POST'])
def process_login():
    is_valid = True
    # print('entered registratn post')
    # print(request.form)
    if len(request.form['firstname']) < 1:
        flash('First name must be longer than 1 letter')
        is_valid = False
        return redirect('/')
    else:
        session['firstname'] = request.form['firstname']
    if len(request.form['lastname']) < 1:
        flash('Last name must be longer than 1 letter')
        is_valid = False
        return redirect('/')
    else:
        session['lastname'] = request.form['lastname']

    if request.form['password'] == request.form['password_confirm']:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
    else:
        flash('Passwords Do Not Match')
        return redirect('/')

    if not EMAIL_REGEX.match(request.form['email']):
        flash('Email not in correct format!!')
        is_valid = False
        return redirect('/')
    else:
        session['email'] = request.form['email']

        ('ELSE STATEMENT')

    mysql = connectToMySQL('login_registration')

    query = 'SELECT * FROM users WHERE email = %(em)s'
    data = {
        'em': request.form['email']
    }
    new_user_id = mysql.query_db(query, data)


    if len(new_user_id) > 0:
        return redirect('/')
        flash('This email has been taken')
        return redirect('/')

    if is_valid:
        mysql = connectToMySQL('login_registration')

        query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s);'
        data = {
            'fn': session['firstname'],
            'ln': session['lastname'],
            'em': session['email'],
            'pw': pw_hash
        }
        new_user_id = mysql.query_db(query, data)
        print('INSERT NEW ID =  ', new_user_id)
        session['userid'] = new_user_id
        print('session user id is ', session['userid'] )
        # print('INSERT NEW ID =  ', new_user_id['id'])

        return redirect('/success')


@app.route('/success')
def display_success():




    return render_template('success.html')


@app.route('/login', methods=['POST'])
def login():
    print('entered login function')
    is_valid = True
    if not EMAIL_REGEX.match(request.form['login_email']):
        flash('Login email not in correct format!!')
        is_valid = False
        return redirect('/')
    else:
        session['email'] = request.form['login_email']
    if is_valid:
        print('success')

    mysql = connectToMySQL('login_registration')
    query = 'SELECT * FROM users WHERE email = %(em)s'
    data = {
        'em': session['email']
    }
    new_user_id = mysql.query_db(query, data)

    print('*'*80)
    print('new_user_id',new_user_id[0])
    print(new_user_id[0]['password'])
    if bcrypt.check_password_hash(new_user_id[0]['password'], request.form['login_password']):
        # if we get True after checking the password, we may put the user id in session
        print('Password Matches')

        session['firstname'] = new_user_id[0]['first_name']
        session['userid'] = new_user_id[0]['id']
        print('session user id is ', session['userid'] )
        return redirect('/success')
    else:
        # print('did not hit hash check')
        flash('Incorect email info.  Please check your email and password.')
        # return render_template('success.html')
        return redirect('/')



@app.route('/users/<id>/destroy')
def delete_user(id):
    # print(session['new_user'])
    mysql = connectToMySQL('restful_users')
    query = 'DELETE FROM users WHERE id = ' + id
    delete_user_id = mysql.query_db(query)

    return redirect('/users')

# @app.route('/destroy_session', methods=['POST'])
@app.route('/destroy_session')
def delete_session():
    session.clear()
    # session.pop('visits') # delete visits
    return redirect('/')
    # return 'Sessions deleted'

if __name__ == "__main__":
    app.run(debug=True)
