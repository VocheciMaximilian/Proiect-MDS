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
from flask_mail import Mail, Message 
from itsdangerous import URLSafeTimedSerializer as Serializer 

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

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_EMAIL_USER'))


os.makedirs(os.path.join(app.root_path, '..', 'instance'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 4. EXTENSII FLASK
db = SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app) 
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Te rog să te autentifici pentru a accesa această pagină."


# 5. BAZA DE DATE (SQLAlchemy)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

project_participants = db.Table('project_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', name='fk_project_participants_user_id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id', name='fk_project_participants_project_id'), primary_key=True)
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
    announcements = db.relationship('Announcement', backref='author', lazy='dynamic', foreign_keys='Announcement.user_id') 
    
    def get_reset_token(self, expires_sec=1800): 
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=expires_sec)['user_id']
        except: 
            return None
        return db.session.get(User, user_id)
        
    def __repr__(self): return f"User('{self.username}', '{self.email}', '{self.role}')"

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_project_creator_id'), nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_project_manager_id'), nullable=True)

    manager = db.relationship('User', foreign_keys=[manager_id], backref=db.backref('managed_projects', lazy='dynamic'))
    participants = db.relationship('User', secondary=project_participants,
                                   backref=db.backref('projects_participating', lazy='dynamic'),
                                   lazy='dynamic')
    files = db.relationship('File', backref='project_assoc', lazy='dynamic', cascade="all, delete-orphan")
    announcements = db.relationship('Announcement', backref='project', lazy='dynamic', cascade="all, delete-orphan") 

    def add_participant(self, user):
        if user and not self.is_participant(user): 
            self.participants.append(user)
    def remove_participant(self, user):
        if user and self.is_participant(user): 
            self.participants.remove(user)
    def is_participant(self, user):
        if not user: return False 
        return self.participants.filter(project_participants.c.user_id == user.id).count() > 0
    def can_user_upload(self, user):
        if not user or not user.is_authenticated: return False 
        return user.id == self.manager_id or self.is_participant(user) or user.id == self.creator_id or user.role == 'admin'
    def can_user_manage_participants(self, user):
        if not user or not user.is_authenticated: return False 
        return user.id == self.manager_id or user.role == 'admin'
    def can_user_post_announcement(self, user): 
        if not user or not user.is_authenticated: return False
        return (user.id == self.creator_id or
                user.id == self.manager_id or
                self.is_participant(user) or
                user.role == 'admin')
    def __repr__(self): return f"Project('{self.name}', Manager ID: {self.manager_id if self.manager_id else 'None'})"


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    file_type = db.Column(db.String(50), nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    size = db.Column(db.Integer, nullable=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_file_uploader_id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', name='fk_file_project_id'), nullable=False)
    def __repr__(self): return f"File('{self.original_filename}', Project ID: {self.project_id})"

class Announcement(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_announcement_user_id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id', name='fk_announcement_project_id'), nullable=False)
    def __repr__(self): return f"Announcement('{self.content[:30]}...', '{self.date_posted}')"

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

def get_all_users():
    return User.query.order_by(User.username).all()

class ProjectForm(FlaskForm):
    name = StringField('Nume Proiect', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descriere (Opțional)')
    manager = QuerySelectField('Manager Proiect', query_factory=get_all_users, 
                               get_label='username', allow_blank=True, blank_text='-- Fără Manager Asignat (Creatorul va fi Manager) --')
    submit_project_details = SubmitField('Salvează Detaliile Proiectului')

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
        user = User.query.filter_by(email=email.data).first()
        if not user: 
            raise ValidationError('Nu există cont cu acest email.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Parolă Nouă', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmă Parola Nouă', validators=[DataRequired(), EqualTo('password', message='Parolele trebuie să coincidă.')])
    submit = SubmitField('Resetează Parola')

class DeleteForm(FlaskForm):
    pass 

class ManageParticipantsForm(FlaskForm):
    participants_to_add = QuerySelectMultipleField('Adaugă Participanți Noi', 
                                                   query_factory=get_all_users, 
                                                   get_label='username',
                                                   render_kw={'size': 8, 'class': 'form-select'})
    submit_add_participants = SubmitField('Adaugă Participanții Selectați')

class AnnouncementForm(FlaskForm): 
    content = TextAreaField('Anunț', validators=[DataRequired(), Length(min=5, max=1000)])
    submit_announcement = SubmitField('Postează Anunțul')

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

def send_project_invitation_email(user_to_notify, project, added_by_user):
    """Trimite un email de notificare când un user este adăugat la un proiect."""
    try:
        msg = Message(f'Ai fost adăugat la proiectul: "{project.name}" - ColabConstruct',
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[user_to_notify.email])
        msg.body = f'''Salut {user_to_notify.username},

Ai fost adăugat ca participant la proiectul "{project.name}" de către utilizatorul {added_by_user.username}.

Poți vizualiza proiectul și colabora accesând următorul link:
{url_for('project_detail', project_id=project.id, _external=True)}

Spor la lucru!
Echipa ColabConstruct
'''
        mail.send(msg)
        print(f"--- DEBUG: Email de invitație la proiect trimis către {user_to_notify.email} pentru proiectul '{project.name}' ---")
        return True
    except Exception as e:
        print(f"--- DEBUG: EROARE la trimiterea email-ului de invitație către {user_to_notify.email}: {str(e)} ---")
        return False

def send_new_announcement_email(recipient_user, project, announcement_obj, posted_by_user): 
    """Trimite un email de notificare când un anunț nou este postat într-un proiect."""
    try:
        msg = Message(f'Anunț Nou: "{project.name}" - ColabConstruct',
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[recipient_user.email])
        msg.body = f'''Salut {recipient_user.username},

Un anunț nou a fost postat în proiectul "{project.name}" de către utilizatorul {posted_by_user.username}:

--------------------------------------------------
{announcement_obj.content}
--------------------------------------------------

Poți vizualiza proiectul și toate anunțurile aici:
{url_for('project_detail', project_id=project.id, _external=True)}

Echipa ColabConstruct
'''
        # Pentru email HTML:
        # msg.html = render_template('email/new_announcement_notification.html', 
        #                            user=recipient_user, project=project, 
        #                            announcement=announcement_obj, posted_by=posted_by_user)
        mail.send(msg)
        print(f"--- DEBUG: Email de anunț nou trimis către {recipient_user.email} pentru proiectul '{project.name}' ---")
        return True
    except Exception as e:
        print(f"--- DEBUG: EROARE la trimiterea email-ului de anunț nou către {recipient_user.email}: {str(e)} ---")
        return False

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
        if user and check_password_hash(user.password, form.password.data):
            if user.is_banned:
                current_time_utc = datetime.now(timezone.utc)
                if user.banned_until:
                    banned_until_utc = user.banned_until
                    if banned_until_utc.tzinfo is None: banned_until_utc = banned_until_utc.replace(tzinfo=timezone.utc)
                    if banned_until_utc > current_time_utc:
                        flash(f'Contul este banat până la {banned_until_utc.strftime("%d-%m-%Y %H:%M UTC")}.', 'danger')
                        return redirect(url_for('login'))
                    else:
                        user.is_banned = False
                        user.banned_until = None
                        db.session.commit()
                        flash('Perioada de ban a expirat.', 'info')
                else: 
                    flash('Contul este banat permanent.', 'danger')
                    return redirect(url_for('login'))
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Autentificare reușită!', 'success')
            return redirect(next_page or url_for('home'))
        else:
            flash('Autentificare eșuată. Verifică email și parolă.', 'danger')
    if request.method == 'POST' and not form.validate_on_submit():
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
    if request.method == 'GET' and not form.manager.data :
         form.manager.data = current_user 

    if form.validate_on_submit():
        try:
            project = Project(name=form.name.data, description=form.description.data, creator_id=current_user.id)
            if form.manager.data:
                project.manager_id = form.manager.data.id
            else: 
                project.manager_id = current_user.id
            
            db.session.add(project)
            db.session.flush() 
            
            project.add_participant(current_user) 
            if project.manager and project.manager != current_user: 
                project.add_participant(project.manager)
            
            db.session.commit()
            flash('Proiectul a fost creat cu succes!', 'success')
            return redirect(url_for('project_detail', project_id=project.id)) 
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la crearea proiectului: {str(e)}', 'danger')
            print(f"Error creating project: {e}")
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('create_project.html', title='Proiect Nou', form=form, legend='Creează Proiect Nou')

@app.route("/project/<int:project_id>")
@login_required
def project_detail(project_id):
    project = db.session.get(Project, project_id) 
    if not project: abort(404)
    if not (current_user.id == project.creator_id or 
            current_user.id == project.manager_id or 
            project.is_participant(current_user) or 
            current_user.role == 'admin'):
        flash('Nu ai permisiunea de a vizualiza acest proiect.', 'danger')
        return redirect(url_for('projects_list'))

    files = File.query.filter_by(project_id=project.id).order_by(File.upload_date.desc()).all()
    upload_form = FileUploadForm()
    delete_file_form = DeleteForm() 
    delete_project_form = DeleteForm()
    participants_form = ManageParticipantsForm()
    announcement_form = AnnouncementForm() 
    announcements = Announcement.query.filter_by(project_id=project.id).order_by(Announcement.date_posted.desc()).all() 
    
    return render_template('view_project.html', title=project.name, project=project, files=files, 
                           upload_form=upload_form, delete_file_form=delete_file_form, 
                           delete_project_form=delete_project_form, participants_form=participants_form,
                           announcement_form=announcement_form, announcements=announcements) 

@app.route("/project/<int:project_id>/update", methods=['GET', 'POST'])
@login_required
def update_project(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    if not (current_user.id == project.creator_id or current_user.id == project.manager_id or current_user.role == 'admin'):
        abort(403)

    form = ProjectForm(obj=project)
    participants_form = ManageParticipantsForm()
    delete_participant_form = DeleteForm() 

    if request.method == 'GET':
        if project.manager:
            form.manager.data = project.manager

    if form.validate_on_submit() and 'submit_project_details' in request.form:
        try:
            project.name = form.name.data
            project.description = form.description.data
            new_manager = form.manager.data
            
            if new_manager and new_manager.id != project.manager_id:
                if project.manager and project.manager_id != project.creator_id:
                    if project.manager_id != project.creator_id: 
                         project.remove_participant(project.manager)
                project.manager_id = new_manager.id
                project.add_participant(new_manager) 
            elif not new_manager and project.creator: 
                project.manager_id = project.creator_id 
                project.add_participant(project.creator) 

            db.session.commit()
            flash('Detaliile proiectului au fost actualizate!', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la actualizarea proiectului: {str(e)}', 'danger')
            print(f"Error updating project details: {e}")

    if participants_form.validate_on_submit() and 'submit_add_participants' in request.form:
        if project.can_user_manage_participants(current_user):
            users_actually_added = [] 
            for user_to_add in participants_form.participants_to_add.data:
                if not project.is_participant(user_to_add) and (not project.manager or user_to_add.id != project.manager.id):
                    project.add_participant(user_to_add)
                    users_actually_added.append(user_to_add) 
            
            if users_actually_added: 
                try:
                    db.session.commit()
                    flash(f'{len(users_actually_added)} participanți adăugați cu succes!', 'success')
                    for invited_user in users_actually_added:
                        send_project_invitation_email(invited_user, project, current_user) 
                except Exception as e:
                    db.session.rollback()
                    flash(f'Eroare la salvarea participanților sau la trimiterea notificărilor: {str(e)}', 'danger')
                    print(f"Error committing participants or sending emails: {e}")
            else:
                flash('Niciun participant nou de adăugat sau participanții selectați sunt deja în proiect/manager.', 'info')
            return redirect(url_for('update_project', project_id=project.id))
        else:
            flash('Nu ai permisiunea de a gestiona participanții.', 'danger')
            
    if request.method == 'POST':
        if 'submit_project_details' in request.form and not form.validate():
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages: flash(f"Eroare (detalii proiect) în '{getattr(form, fieldName).label.text}': {err}", 'danger')
        elif 'submit_add_participants' in request.form and not participants_form.validate():
            for fieldName, errorMessages in participants_form.errors.items():
                for err in errorMessages: flash(f"Eroare (participanți) în '{getattr(participants_form, fieldName).label.text}': {err}", 'danger')
        
    return render_template('edit_project.html', title='Actualizează Proiect', form=form, 
                           participants_form=participants_form, project=project, legend='Actualizează Proiect',
                           delete_form=delete_participant_form) 

@app.route('/project/<int:project_id>/remove_participant/<int:user_id>', methods=['POST'])
@login_required
def remove_project_participant(project_id, user_id):
    project = db.session.get(Project, project_id)
    user_to_remove = db.session.get(User, user_id)
    form = DeleteForm() 

    if not project or not user_to_remove:
        flash('Proiect sau utilizator negăsit.', 'warning')
        return redirect(request.referrer or url_for('projects_list'))

    if not project.can_user_manage_participants(current_user):
        flash('Nu ai permisiunea de a șterge participanți.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    
    if user_to_remove.id == project.manager_id:
        flash('Nu poți elimina managerul proiectului. Schimbă mai întâi managerul.', 'warning')
    elif user_to_remove.id == project.creator_id:
        flash('Nu poți elimina creatorul proiectului din lista de participanți.', 'warning')
    elif form.validate_on_submit(): 
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
    if not project:
        abort(404)
    if not (current_user.id == project.creator_id or current_user.role == 'admin'):
        flash('Nu ai permisiunea de a șterge acest proiect.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    form = DeleteForm() 
    if form.validate_on_submit():
        try:
            for file_obj in project.files:
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e_file:
                    print(f"Eroare la ștergerea fișierului fizic {file_obj.stored_filename}: {e_file}")
            db.session.delete(project)
            db.session.commit()
            flash('Proiectul și toate datele asociate au fost șterse cu succes!', 'success')
            return redirect(url_for('projects_list')) 
        except Exception as e:
            db.session.rollback()
            flash(f'A apărut o eroare la ștergerea proiectului: {str(e)}', 'danger')
            print(f"Error deleting project: {e}")
            return redirect(url_for('project_detail', project_id=project.id))
    else:
        if 'csrf_token' in form.errors:
            flash('Eroare de securitate la ștergerea proiectului (CSRF). Te rugăm să încerci din nou.', 'danger')
        else:
            flash('A apărut o eroare la validarea formularului de ștergere.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

@app.route("/project/<int:project_id>/new_announcement", methods=['POST']) 
@login_required
def new_announcement(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        abort(404)

    if not project.can_user_post_announcement(current_user):
        flash('Nu ai permisiunea de a posta anunțuri în acest proiect.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    form = AnnouncementForm() 
    if form.validate_on_submit():
        try:
            announcement = Announcement(content=form.content.data, 
                                        user_id=current_user.id, 
                                        project_id=project.id)
            db.session.add(announcement)
            db.session.commit() 
            flash('Anunțul tău a fost postat!', 'success')

            recipients_to_notify = set()
            if project.manager and project.manager != current_user:
                recipients_to_notify.add(project.manager)
            if project.creator and project.creator != current_user and (not project.manager or project.creator.id != project.manager.id):
                recipients_to_notify.add(project.creator)
            for participant in project.participants:
                if participant != current_user: 
                    recipients_to_notify.add(participant)
            
            print(f"--- DEBUG: Notifying users for new announcement in project '{project.name}': {[r.username for r in recipients_to_notify]} ---")
            for user_to_notify in recipients_to_notify:
                send_new_announcement_email(user_to_notify, project, announcement, current_user)

        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la postarea anunțului sau la trimiterea notificărilor: {str(e)}', 'danger')
            print(f"Error posting announcement or sending emails: {e}")
    else:
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"Eroare în câmpul '{getattr(form, fieldName).label.text}': {err}", 'danger')
    
    return redirect(url_for('project_detail', project_id=project.id))

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
            new_file = File(original_filename=original_fn, stored_filename=stored_fn,
                            file_type=original_fn.rsplit('.', 1)[1].lower() if '.' in original_fn else '',
                            size=os.path.getsize(file_path), uploader_id=current_user.id, project_id=project.id)
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
    return redirect(url_for('project_detail', project_id=project.id))

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
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_obj.stored_filename, 
                                   as_attachment=True, download_name=file_obj.original_filename)
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
            projects_created_by_user = Project.query.filter_by(creator_id=user_to_delete.id).all()
            for project in projects_created_by_user:
                for file_obj in project.files:
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                        if os.path.exists(file_path): os.remove(file_path)
                    except Exception as e_file: print(f"Eroare ștergere fișier fizic {file_obj.stored_filename}: {e_file}")
                db.session.delete(project)
            
            for project_he_participates_in in list(user_to_delete.projects_participating):
                project_he_participates_in.remove_participant(user_to_delete)

            for project_he_manages in list(user_to_delete.managed_projects):
                if project_he_manages.creator: 
                    project_he_manages.manager_id = project_he_manages.creator_id 
                    project_he_manages.add_participant(project_he_manages.creator) 
                    flash(f"Managerul proiectului '{project_he_manages.name}' a fost schimbat la creator ({project_he_manages.creator.username}).", "info")
                else: 
                    project_he_manages.manager_id = None 
                    flash(f"Managerul proiectului '{project_he_manages.name}' a fost eliminat (creatorul nu mai există).", "warning")

            files_uploaded_by_user = File.query.filter_by(uploader_id=user_to_delete.id).all()
            for file_obj in files_uploaded_by_user:
                if db.session.get(Project, file_obj.project_id):
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                        if os.path.exists(file_path): os.remove(file_path)
                        db.session.delete(file_obj)
                    except Exception as e_file_other: print(f"Eroare ștergere fișier {file_obj.stored_filename}: {e_file_other}")
            
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Utilizatorul {user_to_delete.username} și resursele asociate au fost gestionate/șterse.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la ștergerea utilizatorului: {str(e)}', 'danger')
            print(f"Error deleting user: {e}") 
    else:
        if 'csrf_token' in form.errors: flash('Eroare CSRF la ștergerea utilizatorului. Încearcă din nou.', 'danger')
        else: flash('Eroare la ștergerea utilizatorului (validare eșuată).', 'danger')
    return redirect(url_for('admin_users_list'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Cerere Resetare Parolă - ColabConstruct',
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    msg.body = f'''Pentru a reseta parola, accesează următorul link:
{url_for('reset_token', token=token, _external=True)}

Dacă nu ai făcut tu această cerere, te rugăm să ignori acest email.
Link-ul este valid pentru 30 de minute.
'''
    try:
        mail.send(msg)
        print(f"--- DEBUG: Email de resetare trimis REAL către {user.email} ---")
        return True
    except Exception as e:
        print(f"--- DEBUG: EROARE la trimiterea email-ului REAL: {str(e)} ---")
        return False

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first() 
        if send_reset_email(user): 
            flash('Un email cu instrucțiuni pentru resetarea parolei a fost trimis (dacă emailul există).', 'info')
        else:
            flash('A apărut o problemă la trimiterea email-ului. Te rugăm să încerci mai târziu.', 'danger')
        return redirect(url_for('login')) 
    for fieldName, errorMessages in form.errors.items(): 
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('reset_request.html', title='Resetează Parola', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('home'))
    user = User.verify_reset_token(token) 
    if user is None:
        flash('Tokenul este invalid sau a expirat.', 'warning')
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