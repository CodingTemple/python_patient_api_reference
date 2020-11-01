from flask_api import app, db
from flask_api.models import Patient, User, check_password_hash, patient_schema, patients_schema
from flask import jsonify, request, url_for, redirect, render_template

# Import for Flask Login - login_required, login_user,current_user, logout_user
from flask_login import login_required,login_user, current_user,logout_user 

#Import JsonWebToken(JWT)
import jwt
import uuid

from flask_api.forms import UserForm, LoginForm

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/users/register', methods = ['GET', 'POST'])
def register():
    form = UserForm()
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        user = User(name,email,password)

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form = form)

@app.route('/users/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    email = form.email.data
    password = form.password.data

    logged_user = User.query.filter(User.email == email).first()
    if logged_user and check_password_hash(logged_user.password, password):
        login_user(logged_user)
        return redirect(url_for('get_key'))
    return render_template('login.html',form = form)


@app.route('/patients/create', methods = ['POST'])
def create_patient():
    name = request.json['full_name']
    gender = request.json['gender']
    address = request.json['address']
    ssn = request.json['ssn']
    blood_type = request.json['blood_type']
    email = request.json['email']

    patient = Patient(name,gender,address,ssn,blood_type,email)
    results = patient_schema.dump(patient)
    return jsonify(results)

@app.route('/patients', methods = ['GET'])
def get_patients():
    patients = Patient.query.all()
    return jsonify(patients_schema.dump(patients))

@app.route('/getkey', methods = ['GET'])
def get_key():
    token = jwt.encode({'public_id':current_user.id,'email':current_user.email},app.config['SECRET_KEY'])
    user = User.query.filter_by(email = current_user.email).first()
    user.token = token

    db.session.add(user)
    db.session.commit()
    results = token.decode('utf-8')
    return render_template('token.html', results = results)

@app.route('/updatekey', methods = ['GET','POST','PUT'])
def refresh_key():
    refresh_key = {'refreshToken': jwt.encode({'public_id':current_user.id, 'email':current_user.email}, app.config['SECRET_KEY'])}
    temp = refresh_key.get('refreshToken')
    actual_token = temp.decode('utf-8')
    return render_template('token_refresh.html', actual_token = actual_token)

@app.route('/patients/<id>', methods = ['GET'])
def get_patient(id):
    patient = Patient.query.get(id)
    results = patient_schema.dump(patient)
    return jsonify(results)

@app.route('/patients/<id>', methods = ['POST', 'PUT'])
def update_patient(id):
    patient = Patient.query.get(id)
    
    patient.name = request.json['full_name']
    patient.gender = request.json['gender']
    patient.address = request.json['address']
    patient.ssn = request.json['ssn']
    patient.blood_type = request.json['blood_type']
    patient.email = request.json['email']

    db.session.commit()

    return patient_schema.jsonify(patient)

@app.route('/patients/delete/<id>', methods = ['DELETE'])
def delete_patient(id):
    patient = Patient.query.get(int(id))
    db.session.delete(patient)
    db.session.commit()
    result = patient_schema.dump(patient)
    return jsonify(result)