import os
from datetime import timezone
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid # Adăugat pentru nume unice de fișiere

load_dotenv() #pentru .env
app = Flask(__name__)
# Configuratii
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '123456') # daca nu e in .env

# Pentru SQLite local
default_db_url = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'site.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', default_db_url)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Configurare pentru upload-uri
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'dwg', 'dxf', 'xml'}
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

#extensi
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # redirectioneaza user-ul la pagina de login
login_manager.login_message = "Trebuie să fii autentificat pentru a accesa această pagină."
login_manager.login_message_category = 'info'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    projects_created = db.relationship('Project', backref='creator', lazy=True, foreign_keys='Project.creator_id')
    files_uploaded = db.relationship('File', backref='uploader', lazy=True, foreign_keys='File.uploader_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    creation_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    files = db.relationship('File', backref='project', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Project {self.name}>'

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_type = db.Column(db.String(50), nullable=True)
    size = db.Column(db.Integer, nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    def __repr__(self):
        return f'<File {self.original_filename}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html', title='Acasă')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Parolele nu se potrivesc!', 'danger')
            return redirect(url_for('register'))

        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Numele de utilizator există deja.', 'danger')
            return redirect(url_for('register'))

        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Adresa de email este deja folosită.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password) # Parolele sunt hash-uite
        # primul utilizator il facem admin
        if User.query.count() == 0:
            new_user.role = 'admin'
            flash('Primul utilizator înregistrat a fost setat ca admin!', 'info')

        db.session.add(new_user)
        db.session.commit()
        flash('Contul tău a fost creat! Te poți autentifica acum.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Înregistrare')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user) # Flask-Login gestioneaza sesiunea
            flash('Autentificare reușită!', 'success')
            # Redirect la pagina solicitata inainte de login
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Autentificare eșuată. Verifică email-ul și parola.', 'danger')
    return render_template('login.html', title='Autentificare')

@app.route('/logout')
@login_required
def logout():
    logout_user() # Flask-Login sterge sesiunea
    flash('Ai fost deconectat.', 'info')
    return redirect(url_for('login'))

@app.route('/projects')
@login_required
def projects_list(): #placeholder
    projects = Project.query.order_by(Project.creation_date.desc()).all()
    return render_template('projects_list.html', title="Listă Proiecte", projects=projects)

@app.route('/project/create', methods=['GET', 'POST'])
@login_required
def create_project(): #placeholder
    if current_user.role != 'admin':
        flash('Doar administratorii pot crea proiecte.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if not name:
            flash('Numele proiectului este obligatoriu!', 'danger')
            return render_template('create_project.html', title="Creare Proiect Nou", description=description)

        new_project = Project(name=name, description=description, creator_id=current_user.id)
        db.session.add(new_project)
        db.session.commit()
        flash(f'Proiectul "{name}" a fost creat cu succes!', 'success')
        return redirect(url_for('projects_list'))

    return render_template('create_project.html', title="Creare Proiect Nou")

@app.route('/project/<int:project_id>')
@login_required
def view_project(project_id): #placeholder
    project = Project.query.get_or_404(project_id)
    return render_template('view_project.html', title=project.name, project=project)

@app.route('/project/<int:project_id>/upload', methods=['POST'])
@login_required
def upload_file(project_id):
    project = Project.query.get_or_404(project_id)

    if 'file' not in request.files:
        flash('Niciun fișier selectat.', 'danger')
        return redirect(url_for('view_project', project_id=project.id))

    file = request.files['file']

    if file.filename == '':
        flash('Niciun fișier selectat.', 'danger')
        return redirect(url_for('view_project', project_id=project.id))

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = str(uuid.uuid4()) + '.' + file_extension

        project_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(project.id))
        if not os.path.exists(project_upload_folder):
            os.makedirs(project_upload_folder)

        file_path = os.path.join(project_upload_folder, stored_filename)

        try:
            file.save(file_path)
            file_size = os.path.getsize(file_path)

            new_file_db = File(
                original_filename=original_filename,
                stored_filename=stored_filename,
                file_type=file_extension,
                size=file_size,
                uploader_id=current_user.id,
                project_id=project.id
            )
            db.session.add(new_file_db)
            db.session.commit()
            flash(f'Fișierul "{original_filename}" a fost încărcat cu succes.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'A apărut o eroare la încărcarea fișierului: {str(e)}', 'danger')
    else:
        flash('Tip de fișier nepermis.', 'danger')

    return redirect(url_for('view_project', project_id=project.id))

@app.route('/download_file/<int:file_id>')
@login_required
def download_file(file_id): #placeholder
    file_record = File.query.get_or_404(file_id)
    project_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(file_record.project_id))
    flash(f'Funcționalitatea de download pentru "{file_record.original_filename}" va fi implementată curând!', 'info')
    return redirect(url_for('view_project', project_id=file_record.project_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)