from flask import Flask, render_template, request, redirect, url_for,flash,abort,session
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime
from flask_migrate import Migrate  # Import Flask-Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField

from flask_wtf.csrf import generate_csrf


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SARVESH'  # Replace with a random secret key

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:/project/flask_blog-master/blog.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.secret_key = 'SARVESH'
app.config['SECRET_KEY'] = 'SARVESH'  # Set a secret key
csrf = CSRFProtect(app)





class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    posts = db.relationship('Blogpost', backref='author_of_post', lazy=True)

    
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=150)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=150)])

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    subtitle = db.Column(db.String(50), nullable=True)
    author = db.Column(db.String(20), nullable=True)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    views = db.Column(db.Integer, default=0)  # Default value for view count
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def index():
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()

    return render_template('index.html', posts=posts)

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Blogpost.query.filter_by(id=post_id).first()
    if post is None:
        abort(404)

    if post.views is None:
        post.views = 0  # Initialize views if it is None
    post.views += 1  # Increment the view count

    db.session.commit()

    return render_template('post.html', post=post)

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    subtitle = StringField('Subtitle', validators=[DataRequired()])
    content = TextAreaField('Blog Content', validators=[DataRequired()])
    submit = SubmitField('Publish Post')
@app.route('/add', methods=['GET', 'POST'])
def add():
    form = PostForm()
    if form.validate_on_submit():
        # Process the form data
        # e.g., save to database and redirect
        return redirect(url_for('index'))
    return render_template('add.html', form=form)


@app.route('/addpost', methods=['POST'])
@login_required
def addpost():
    title = request.form['title']
    subtitle = request.form['subtitle']
    content = request.form['content']

    # Create a new Blogpost instance
    post = Blogpost(
        title=title,
        subtitle=subtitle,
        content=content,
        date_posted=datetime.now(),
        views=0,  # Default value for views
        author=current_user.username,
        author_id=current_user.id , # Set author_id to the ID of the currently logged-in user
    )

    # Add the new post to the database
    db.session.add(post)
    db.session.commit()

    # Redirect to the index page after successful post addition
    return redirect(url_for('index'))

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Blogpost.query.get_or_404(post_id)
    
    if post.author != current_user.username:
        flash("You don't have permission to delete this post.", "danger")
        return redirect(url_for('index'))

    try:
        db.session.delete(post)
        db.session.commit()
        flash('Post has been deleted!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while trying to delete the post.', 'danger')
        print(e)

    return redirect(url_for('index'))




if __name__ == '__main__':
    app.run(debug=True)