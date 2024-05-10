from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin
from flask_login import login_required, current_user
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'e636e2911679fe705a768577428e36a740023d2502d9e610b155b895fe69'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/hiexy/PersonalProjects/websec/mydatabase.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

class Account(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)

    def __repr__(self):
        return '<User %r>' % self.username
    
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('account.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('account.id'))
    amount = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('Account', foreign_keys=[sender_id])
    recipient = db.relationship('Account', foreign_keys=[recipient_id])
    def __repr__(self):
        return '<Transaction %r>' % self.id

@app.before_first_request
def create_tables():
    db.create_all()


def get_db():
    conn = sqlite3.connect('bank.db')
    return conn

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = Account(username=username, password=hashed_password, balance=1000)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Account.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('balance'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/balance')
@login_required
def balance():
    return render_template('balance.html', balance=current_user.balance)

@app.route('/make_transfer')
@login_required
def make_transfer():
    users = Account.query.filter(Account.id != current_user.id).all()
    return render_template('transfer.html', users=users)

@app.route('/transfer', methods=['GET'])
@login_required
def transfer():
    recipient_username = request.args.get('recipient')
    amount = int(request.args.get('amount'))

    recipient = Account.query.filter_by(username=recipient_username).first()
    if not recipient:
        return "Recipient not found", 400

    if current_user.balance < amount:
        return "Insufficient balance", 400

    current_user.balance -= amount
    recipient.balance += amount

    transaction = Transaction(sender_id=current_user.id, recipient_id=recipient.id, amount=amount)
    db.session.add(transaction)

    db.session.commit()

    return redirect(url_for('balance'))

@app.route('/transactions')
@login_required
def view_transactions():
    sent_transactions = Transaction.query.filter_by(sender_id=current_user.id).all()
    received_transactions = Transaction.query.filter_by(recipient_id=current_user.id).all()
    return render_template('transactions.html', sent_transactions=sent_transactions, received_transactions=received_transactions)


if __name__ == '__main__':
    app.run(debug=True)