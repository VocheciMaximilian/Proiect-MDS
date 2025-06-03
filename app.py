# 1. IMPORTURI

from flask import Flask, render_template, url_for, flash, redirect, request, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed 
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.fields import DateTimeLocalField 
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from wtforms_sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField
from datetime import datetime, timezone 
from functools import wraps
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename 
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 


# 2. VARIABILE DE MEDIU 
load_dotenv()

# 3. CONFIGURARE APLICATIE FLASK
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dfg34g_DFG34_dfg34DFG_dfg34dfg3DFG34dfg') 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///../instance/site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'pptx', 'dwg', 'dxf', 'xml'}
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

os.makedirs(os.path.join(app.root_path, '..', 'instance'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 4. EXTENSII FLASK
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Te rog să te autentifici pentru a accesa această pagină."


# 5. BAZA DE DATE (SQLAlchemy)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

project_participants = db.Table('project_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(255), nullable=False) 
    role = db.Column(db.String(10), nullable=False, default='user') 
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    banned_until = db.Column(db.DateTime, nullable=True)
    projects_created = db.relationship('Project', backref='creator', lazy='dynamic', foreign_keys='Project.creator_id')
    files_uploaded = db.relationship('File', backref='uploader', lazy='dynamic', foreign_keys='File.uploader_id')
    def __repr__(self): return f"User('{self.username}', '{self.email}', '{self.role}')"

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    manager = db.relationship('User', foreign_keys=[manager_id], backref=db.backref('managed_projects', lazy='dynamic'))
    participants = db.relationship('User', secondary=project_participants, backref=db.backref('projects_participating', lazy='dynamic'), lazy='dynamic')
    files = db.relationship('File', backref='project_assoc', lazy='dynamic', cascade="all, delete-orphan")

    def add_participant(self, user):
        if not self.is_participant(user):
            self.participants.append(user)
    def remove_participant(self, user):
        if self.is_participant(user):
            self.participants.remove(user)
    def is_participant(self, user):
        return self.participants.filter(project_participants.c.user_id == user.id).count() > 0
    def can_user_upload(self, user):
        return user.id == self.manager_id or self.is_participant(user) or user.id == self.creator_id or user.role == 'admin'
    def can_user_manage_participants(self, user):
        return user.id == self.manager_id or user.role == 'admin'
    def __repr__(self): return f"Project('{self.name}', Manager ID: {self.manager_id if self.manager_id else 'None'})"


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_type = db.Column(db.String(50), nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    size = db.Column(db.Integer, nullable=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    def __repr__(self): return f"File('{self.original_filename}', Project ID: {self.project_id})"

# 6. DEFINITII FORMULARE 
class RegistrationForm(FlaskForm):
    username = StringField('Nume utilizator', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(message="Adresă de email invalidă.")])
    password = PasswordField('Parolă', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmă Parola', validators=[DataRequired(), EqualTo('password', message='Parolele trebuie să coincidă.')])
    submit = SubmitField('Înregistrează-te')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Acest nume de utilizator este deja luat.')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first(): raise ValidationError('Acest email este deja folosit.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message="Adresă de email invalidă.")])
    password = PasswordField('Parolă', validators=[DataRequired()])
    remember = BooleanField('Ține-mă minte')
    submit = SubmitField('Autentifică-te')

# helper pentru QuerySelectField
def get_all_users():
    return User.query.order_by(User.username).all()

class ProjectForm(FlaskForm):
    name = StringField('Nume Proiect', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descriere (Opțional)')
    manager = QuerySelectField('Manager Proiect', query_factory=get_all_users, get_label='username', allow_blank=True, blank_text='-- Fără Manager Asignat --')
    submit = SubmitField('Salvează Proiect')

def allowed_file_check(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class FileUploadForm(FlaskForm):
    file = FileField('Selectează fișier', validators=[DataRequired(message="Te rog selectează un fișier.")])
    submit = SubmitField('Încarcă')
    def validate_file(self, file_field):
        if file_field.data:
            filename = secure_filename(file_field.data.filename)
            if not allowed_file_check(filename):
                allowed_ext_str = ", ".join(app.config['ALLOWED_EXTENSIONS'])
                raise ValidationError(f'Tip fișier invalid. Permise: {allowed_ext_str}')

class AdminUserUpdateForm(FlaskForm):
    role = SelectField('Rol', choices=[('user', 'User'), ('manager', 'Manager'), ('admin', 'Admin')], validators=[DataRequired()])
    is_banned = BooleanField('Este Banat?')
    banned_until = DateTimeLocalField('Banat Până La (Opțional)', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    submit = SubmitField('Actualizează Utilizator')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message="Adresă de email invalidă.")])
    submit = SubmitField('Solicită Resetarea Parolei')
    def validate_email(self, email):
        if not User.query.filter_by(email=email.data).first(): raise ValidationError('Nu există cont cu acest email.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Parolă Nouă', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmă Parola Nouă', validators=[DataRequired(), EqualTo('password', message='Parolele trebuie să coincidă.')])
    submit = SubmitField('Resetează Parola')

class DeleteForm(FlaskForm):
    submit = SubmitField('Șterge') 

class ManageParticipantsForm(FlaskForm):
    participants_to_add = QuerySelectMultipleField('Adaugă Participanți Noi', query_factory=get_all_users, get_label='username', render_kw={'size': 5})
    submit_add_participants = SubmitField('Adaugă Participanți Selectați')


# 7. DECORATORI SI FUNCTII HELPER
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Nu ai permisiunea de a accesa această pagină.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def generate_unique_stored_filename(original_filename):
    ext = ''
    if '.' in original_filename: ext = original_filename.rsplit('.', 1)[1].lower()
    return f"{uuid.uuid4()}.{ext}" if ext else str(uuid.uuid4())


# 8. RUTE Flask @app.route

@app.route("/")
@app.route("/home")
def home():
    recent_projects = []
    if current_user.is_authenticated:
        recent_projects = Project.query.order_by(Project.date_created.desc()).limit(5).all()
    return render_template('home.html', title='Acasă', projects=recent_projects)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user_role = 'user' if User.query.count() > 0 else 'admin'
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=user_role)
        db.session.add(user)
        db.session.commit()
        flash(f'Cont creat pentru {form.username.data}! Rol: {user_role}. Te poți autentifica.', 'success')
        return redirect(url_for('login'))
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('register.html', title='Înregistrare', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(f"--- DEBUG LOGIN: Attempting login for email: {form.email.data} ---")
        if user:
            print(f"--- DEBUG LOGIN: User found: {user.username}, ID: {user.id} ---")
            print(f"--- DEBUG LOGIN: User.is_banned: {user.is_banned} (Type: {type(user.is_banned)}) ---")
            print(f"--- DEBUG LOGIN: User.banned_until: {user.banned_until} (Type: {type(user.banned_until)}) ---")
            if check_password_hash(user.password, form.password.data):
                print(f"--- DEBUG LOGIN: Password for {user.username} is correct. ---")
                if user.is_banned:
                    print(f"--- DEBUG LOGIN: User {user.username} IS FLAGGED AS BANNED. ---")
                    ban_message = 'Contul tău este momentan banat.'
                    current_time_utc = datetime.now(timezone.utc)
                    print(f"--- DEBUG LOGIN: Current UTC time: {current_time_utc} ---")
                    if user.banned_until:
                        banned_until_utc = user.banned_until
                        if banned_until_utc.tzinfo is None or banned_until_utc.tzinfo.utcoffset(banned_until_utc) is None:
                            banned_until_utc = banned_until_utc.replace(tzinfo=timezone.utc)
                        print(f"--- DEBUG LOGIN: Ban expires at (UTC): {banned_until_utc} ---")
                        if banned_until_utc > current_time_utc: 
                            print(f"--- DEBUG LOGIN: Ban is still active for {user.username}. ---")
                            ban_message += f' Accesul va fi restabilit după {banned_until_utc.strftime("%d-%m-%Y %H:%M UTC")}.'
                            flash(ban_message, 'danger')
                            return redirect(url_for('login'))
                        else: 
                            print(f"--- DEBUG LOGIN: Ban has expired for {user.username}. Lifting ban. ---")
                            user.is_banned = False
                            user.banned_until = None
                            db.session.commit()
                            flash('Perioada de ban a expirat. Te poți autentifica acum.', 'info')
                    else: 
                        print(f"--- DEBUG LOGIN: User {user.username} is permanently banned. ---")
                        flash(ban_message + ' Permanent.', 'danger')
                        return redirect(url_for('login'))
                else:
                    print(f"--- DEBUG LOGIN: User {user.username} is NOT flagged as banned. Proceeding to login. ---")
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Autentificare reușită!', 'success')
                print(f"--- DEBUG LOGIN: Login successful for {user.username}. Redirecting. ---")
                return redirect(next_page or url_for('home'))
            else:
                print(f"--- DEBUG LOGIN: Password for {user.username} is INCORRECT. ---")
                flash('Autentificare eșuată. Verifică email-ul și parola.', 'danger')
        else:
            print(f"--- DEBUG LOGIN: User with email {form.email.data} NOT FOUND. ---")
            flash('Autentificare eșuată. Verifică email-ul și parola.', 'danger')
    if request.method == 'POST' and not form.validate_on_submit():
        print(f"--- DEBUG LOGIN: Form validation failed. Errors: {form.errors} ---")
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('login.html', title='Autentificare', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('Ai fost deconectat.', 'info')
    return redirect(url_for('login'))

@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Contul Meu')

@app.route("/projects")
@login_required
def projects_list():
    page = request.args.get('page', 1, type=int)
    all_projects = Project.query.order_by(Project.date_created.desc()).paginate(page=page, per_page=10) 
    return render_template('projects_list.html', title='Toate Proiectele', projects=all_projects)

@app.route("/project/new", methods=['GET', 'POST'])
@login_required
def create_project():
    form = ProjectForm()
    if request.method == 'GET' and not form.manager.data : # Pre-selectează creatorul ca manager
         form.manager.data = current_user

    if form.validate_on_submit():
        try:
            project = Project(name=form.name.data, description=form.description.data, creator_id=current_user.id)
            if form.manager.data:
                project.manager_id = form.manager.data.id
            else: # Dac nu e selectat un manager, creatorul devine manager
                project.manager_id = current_user.id
            
            db.session.add(project)
            db.session.flush()
            
            project.add_participant(current_user) # Creatorul este participant
            if project.manager and project.manager != current_user: # Adauga managerul dacă e diferit
                project.add_participant(project.manager)
            
            db.session.commit()
            flash('Proiectul a fost creat cu succes!', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la crearea proiectului: {str(e)}', 'danger')
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('create_project.html', title='Proiect Nou', form=form, legend='Creează Proiect Nou')

@app.route("/project/<int:project_id>")
@login_required
def project_detail(project_id):
    project = db.session.get(Project, project_id) 
    if not project: abort(404)
    files = File.query.filter_by(project_id=project.id).order_by(File.upload_date.desc()).all()
    upload_form = FileUploadForm()
    delete_file_form = DeleteForm() 
    delete_project_form = DeleteForm()
    participants_form = ManageParticipantsForm()

    return render_template('view_project.html', title=project.name, project=project, files=files, upload_form=upload_form, delete_file_form=delete_file_form, delete_project_form=delete_project_form, participants_form=participants_form)

@app.route("/project/<int:project_id>/update", methods=['GET', 'POST'])
@login_required
def update_project(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    if not (current_user.id == project.creator_id or current_user.id == project.manager_id or current_user.role == 'admin'):
        abort(403) # Doar creator, manager sau admin pot edita

    form = ProjectForm(obj=project)
    participants_form = ManageParticipantsForm()

    if request.method == 'GET':
        if project.manager:
            form.manager.data = project.manager

    if form.validate_on_submit() and request.form.get('submit_project_details'): # Butonul principal de submit
        try:
            project.name = form.name.data
            project.description = form.description.data
            project.manager_id = form.manager.data.id if form.manager.data else project.creator_id 
            
            # Asigură-te că noul manager este și participant
            if project.manager:
                project.add_participant(project.manager)

            db.session.commit()
            flash('Detaliile proiectului au fost actualizate!', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la actualizarea proiectului: {str(e)}', 'danger')

    if participants_form.validate_on_submit() and request.form.get('submit_add_participants'):
        if project.can_user_manage_participants(current_user):
            for user_to_add in participants_form.participants_to_add.data:
                project.add_participant(user_to_add)
            db.session.commit()
            flash('Participanți adăugați cu succes!', 'success')
            return redirect(url_for('update_project', project_id=project.id))
        else:
            flash('Nu ai permisiunea de a gestiona participanții.', 'danger')

    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages: flash(f"Eroare (detalii proiect) în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    for fieldName, errorMessages in participants_form.errors.items():
        for err in errorMessages: flash(f"Eroare (participanți) în '{getattr(participants_form, fieldName).label.text}': {err}", 'danger')
        
    return render_template('edit_project.html', title='Actualizează Proiect', form=form, participants_form=participants_form, project=project, legend='Actualizează Proiect', delete_form=DeleteForm())

@app.route('/project/<int:project_id>/remove_participant/<int:user_id>', methods=['POST'])
@login_required
def remove_project_participant(project_id, user_id):
    project = db.session.get(Project, project_id)
    user_to_remove = db.session.get(User, user_id)
    form = DeleteForm() # Pentru CSRF

    if not project or not user_to_remove:
        flash('Proiect sau utilizator negăsit.', 'warning')
        return redirect(request.referrer or url_for('projects_list'))

    if not project.can_user_manage_participants(current_user):
        flash('Nu ai permisiunea de a șterge participanți.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    
    if user_to_remove.id == project.manager_id:
        flash('Nu poți elimina managerul proiectului. Schimbă mai întâi managerul.', 'warning')
        return redirect(url_for('update_project', project_id=project.id))
    
    if user_to_remove.id == project.creator_id:
        flash('Nu poți elimina creatorul proiectului din lista de participanți.', 'warning')
        return redirect(url_for('update_project', project_id=project.id))

    if form.validate_on_submit():
        try:
            project.remove_participant(user_to_remove)
            db.session.commit()
            flash(f'Utilizatorul {user_to_remove.username} a fost eliminat din proiect.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la eliminarea participantului: {str(e)}', 'danger')
    else:
        if 'csrf_token' in form.errors: flash('Eroare CSRF. Încearcă din nou.', 'danger')
        else: flash('A apărut o eroare la eliminarea participantului.', 'danger')
    return redirect(url_for('update_project', project_id=project.id))


@app.route("/project/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    if not (current_user.id == project.creator_id or current_user.role == 'admin'): abort(403)
    form = DeleteForm() 
    if form.validate_on_submit():
        try:
            for file_obj in project.files:
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                    if os.path.exists(file_path): os.remove(file_path)
                except Exception as e_file: print(f"Eroare ștergere fișier fizic {file_obj.stored_filename}: {e_file}")
            db.session.delete(project)
            db.session.commit()
            flash('Proiectul și fișierele asociate au fost șterse!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la ștergerea proiectului: {str(e)}', 'danger')
    else:
        if 'csrf_token' in form.errors: flash('Eroare CSRF la ștergerea proiectului. Încearcă din nou.', 'danger')
        else: flash('Eroare la ștergerea proiectului.', 'danger')
    return redirect(url_for('projects_list'))

@app.route("/project/<int:project_id>/upload_file", methods=['POST'])
@login_required
def upload_file(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    
    if not project.can_user_upload(current_user):
        flash('Nu ai permisiunea de a încărca fișiere în acest proiect.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
        
    form = FileUploadForm() 
    if form.validate_on_submit():
        file_data = form.file.data
        original_fn = secure_filename(file_data.filename)
        stored_fn = generate_unique_stored_filename(original_fn)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_fn)
        try:
            file_data.save(file_path)
            new_file = File(original_filename=original_fn, stored_filename=stored_fn, file_type=original_fn.rsplit('.', 1)[1].lower() if '.' in original_fn else '', size=os.path.getsize(file_path), uploader_id=current_user.id, project_id=project.id)
            db.session.add(new_file)
            db.session.commit()
            flash('Fișier încărcat cu succes!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la încărcarea fișierului: {e}', 'danger')
            if os.path.exists(file_path): os.remove(file_path)
    else: 
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route("/download_file/<int:file_id>")
@login_required
def download_file(file_id):
    file_obj = db.session.get(File, file_id)
    if not file_obj: abort(404)
    project = db.session.get(Project, file_obj.project_id)
    if not project: abort(404) 
    if not (current_user.id == project.creator_id or 
            current_user.id == project.manager_id or 
            project.is_participant(current_user) or 
            current_user.role == 'admin'):
        flash('Nu ai permisiunea de a descărca acest fișier.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_obj.stored_filename, as_attachment=True, download_name=file_obj.original_filename)
    except FileNotFoundError: abort(404, description="Fișierul nu a fost găsit pe server.")

@app.route("/delete_file/<int:file_id>", methods=['POST'])
@login_required
def delete_file(file_id):
    file_obj = db.session.get(File, file_id)
    if not file_obj: abort(404)
    project_id_redirect = file_obj.project_id 
    project = db.session.get(Project, project_id_redirect)
    if not project: abort(404)
    if not (current_user.id == file_obj.uploader_id or 
            current_user.id == project.manager_id or 
            current_user.id == project.creator_id or 
            current_user.role == 'admin'):
        abort(403)
    form = DeleteForm()
    if form.validate_on_submit():
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
            if os.path.exists(file_path): os.remove(file_path)
            db.session.delete(file_obj)
            db.session.commit()
            flash(f'Fișierul "{file_obj.original_filename}" a fost șters!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la ștergerea fișierului: {e}', 'danger')
    else:
        if 'csrf_token' in form.errors: flash('Eroare CSRF la ștergerea fișierului. Încearcă din nou.', 'danger')
        else: flash('Eroare la ștergerea fișierului.', 'danger')
    return redirect(url_for('project_detail', project_id=project_id_redirect))

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_users_list():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.role.desc(), User.id).paginate(page=page, per_page=10)
    delete_form = DeleteForm() 
    return render_template('admin_users_list.html', title='Administrare Utilizatori', users=users, delete_form=delete_form)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user_to_edit = db.session.get(User, user_id)
    if not user_to_edit: abort(404)
    form = AdminUserUpdateForm(obj=user_to_edit)
    if form.validate_on_submit():
        if user_to_edit.id == current_user.id and user_to_edit.role == 'admin' and form.role.data != 'admin' and User.query.filter_by(role='admin').count() <= 1:
            flash('Nu îți poți schimba rolul; ești singurul admin.', 'danger')
        else:
            user_to_edit.role = form.role.data
            user_to_edit.is_banned = form.is_banned.data
            if form.is_banned.data and form.banned_until.data:
                naive_dt_from_form = form.banned_until.data
                user_to_edit.banned_until = naive_dt_from_form.replace(tzinfo=timezone.utc)
            elif not form.is_banned.data: 
                user_to_edit.banned_until = None
            db.session.commit()
            flash(f'Utilizatorul {user_to_edit.username} a fost actualizat!', 'success')
        return redirect(url_for('admin_users_list'))
    for fieldName, errorMessages in form.errors.items(): 
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('admin_edit_user.html', title=f'Editează {user_to_edit.username}', form=form, user=user_to_edit)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete: flash('Utilizator negăsit.', 'warning'); return redirect(url_for('admin_users_list'))
    if user_to_delete.id == current_user.id: flash('Nu te poți șterge.', 'danger'); return redirect(url_for('admin_users_list'))
    if user_to_delete.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        flash('Nu poți șterge ultimul admin.', 'danger'); return redirect(url_for('admin_users_list'))
    form = DeleteForm()
    if form.validate_on_submit():
        try:
            projects_to_delete = Project.query.filter_by(creator_id=user_to_delete.id).all()
            for project in projects_to_delete:
                for file_obj in project.files:
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                        if os.path.exists(file_path): os.remove(file_path)
                    except Exception as e_file: print(f"Eroare ștergere fișier fizic {file_obj.stored_filename}: {e_file}")
                db.session.delete(project)
            
            for project_he_participates_in in user_to_delete.projects_participating:
                project_he_participates_in.remove_participant(user_to_delete)

            for project_he_manages in user_to_delete.managed_projects:
                project_he_manages.manager_id = project_he_manages.creator_id 
                project_he_manages.add_participant(project_he_manages.creator) 
                flash(f"Managerul proiectului '{project_he_manages.name}' a fost schimbat la creatorul proiectului.", "info")

            files_uploaded_by_user = File.query.filter_by(uploader_id=user_to_delete.id).all()
            for file_obj in files_uploaded_by_user:
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                    if os.path.exists(file_path): os.remove(file_path)
                    db.session.delete(file_obj)
                except Exception as e_file_other: print(f"Eroare ștergere fișier (alt proiect) {file_obj.stored_filename}: {e_file_other}")
            
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Utilizatorul {user_to_delete.username} și resursele asociate au fost gestionate/șterse.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la ștergerea utilizatorului: {str(e)}', 'danger')
    else:
        if 'csrf_token' in form.errors: flash('Eroare CSRF la ștergerea utilizatorului. Încearcă din nou.', 'danger')
        else: flash('Eroare la ștergerea utilizatorului.', 'danger')
    return redirect(url_for('admin_users_list'))

def send_reset_email(user): 
    flash(f"Email de resetare trimis (simulat) către {user.email}.", "info")

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first() 
        send_reset_email(user)
        flash('Instrucțiuni trimise dacă emailul există.', 'info')
        return redirect(url_for('login'))
    for fieldName, errorMessages in form.errors.items(): 
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('reset_request.html', title='Resetează Parola', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('home'))
    user_id_simulated = request.args.get('user_id_for_reset_simulation') 
    if not user_id_simulated:
        flash('Link de resetare invalid sau expirat (simulare necesită user_id).', 'warning')
        return redirect(url_for('reset_request'))
    try:
        user = db.session.get(User, int(user_id_simulated))
    except ValueError:
        user = None
    if not user:
        flash('Utilizator pentru resetare negăsit (simulare).', 'warning')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Parola actualizată! Te poți autentifica.', 'success')
        return redirect(url_for('login'))
    for fieldName, errorMessages in form.errors.items(): 
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('reset_token.html', title='Resetează Parola', form=form, token=token)

# 9. BLOC PENTRU RULARE DIRECTA SI CREARE DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        if User.query.count() == 0:
            print("Creare admin user implicit...")
            admin_pass = generate_password_hash('123456') 
            admin = User(username='admin', email='admin@test.com', password=admin_pass, role='admin')
            db.session.add(admin)
            db.session.commit()
            print("Admin user (admin@test.com / 123456) creat.")
    app.run(debug=True)