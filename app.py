# 1. IMPORTURI
from flask import Flask, render_template, url_for, flash, redirect, request, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed 
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.fields import DateTimeLocalField 
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
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

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(255), nullable=False) 
    role = db.Column(db.String(10), nullable=False, default='user') 
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    banned_until = db.Column(db.DateTime, nullable=True)
    projects_created = db.relationship('Project', backref='creator', lazy=True, foreign_keys='Project.creator_id')
    files_uploaded = db.relationship('File', backref='uploader', lazy=True, foreign_keys='File.uploader_id')
    def __repr__(self): return f"User('{self.username}', '{self.email}', '{self.role}')"

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    files = db.relationship('File', backref='project_assoc', lazy=True, cascade="all, delete-orphan")
    def __repr__(self): return f"Project('{self.name}', '{self.date_created}')"

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

class ProjectForm(FlaskForm):
    name = StringField('Nume Proiect', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descriere (Opțional)')
    submit = SubmitField('Salvează Proiect')

def allowed_file_check(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class FileUploadForm(FlaskForm):
    file = FileField('Selectează fișier', validators=[DataRequired(message="Te rog selectează un fișier.")])
    submit = SubmitField('Încarcă')
    def validate_file(self, file):
        if file.data:
            filename = secure_filename(file.data.filename)
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
        
        if user and check_password_hash(user.password, form.password.data):
            if user.is_banned:
                ban_message = 'Contul tău este banat.'
                if user.banned_until and user.banned_until > datetime.now(timezone.utc):
                    ban_message += f' Până la {user.banned_until.strftime("%Y-%m-%d %H:%M UTC")}.'
                flash(ban_message, 'danger')
                return redirect(url_for('login'))
            elif user.is_banned and not user.banned_until: # Ban permanent
                flash('Contul tău este banat permanent.', 'danger')
                return redirect(url_for('login'))
            else: 
                if user.is_banned and user.banned_until and user.banned_until <= datetime.now(timezone.utc):
                    user.is_banned = False
                    user.banned_until = None
                    db.session.commit()
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Autentificare reușită!', 'success')
            return redirect(next_page or url_for('home'))
        else:
            flash('Autentificare eșuată. Verifică email și parolă.', 'danger')
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
    if form.validate_on_submit():
        try:
            project = Project(name=form.name.data, description=form.description.data, creator_id=current_user.id)
            db.session.add(project)
            db.session.commit()
            flash('Proiectul a fost creat cu succes!', 'success')
            return redirect(url_for('projects_list'))
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
    return render_template('view_project.html', title=project.name, project=project, files=files, 
                           upload_form=upload_form, delete_file_form=delete_file_form, delete_project_form=delete_project_form)

@app.route("/project/<int:project_id>/update", methods=['GET', 'POST'])
@login_required
def update_project(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    if project.creator_id != current_user.id and current_user.role != 'admin': abort(403)
    form = ProjectForm(obj=project)
    if form.validate_on_submit():
        try:
            project.name = form.name.data
            project.description = form.description.data
            db.session.commit()
            flash('Proiectul a fost actualizat!', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Eroare la actualizarea proiectului: {str(e)}', 'danger')
    for fieldName, errorMessages in form.errors.items():
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('edit_project.html', title='Actualizează Proiect', form=form, legend='Actualizează Proiect', project=project)

@app.route("/project/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project: abort(404)
    if project.creator_id != current_user.id and current_user.role != 'admin': abort(403)
    
    form = DeleteForm() 
    if form.validate_on_submit(): # Va valida doar token-ul CSRF
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
    return redirect(url_for('project_detail', project_id=project_id))

@app.route("/download_file/<int:file_id>")
@login_required
def download_file(file_id):
    file_obj = db.session.get(File, file_id)
    if not file_obj: abort(404)
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
    if not (current_user.id == file_obj.uploader_id or current_user.id == project.creator_id or current_user.role == 'admin'):
        abort(403)
    
    form = DeleteForm() # Pentru validare CSRF
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
            return redirect(url_for('admin_edit_user', user_id=user_id))
        user_to_edit.role = form.role.data
        user_to_edit.is_banned = form.is_banned.data
        user_to_edit.banned_until = form.banned_until.data if form.is_banned.data and form.banned_until.data else None
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
    
    form = DeleteForm() # Pentru validare CSRF
    if form.validate_on_submit():
        try:
            for project in Project.query.filter_by(creator_id=user_to_delete.id).all():
                for file_obj in project.files: 
                    try:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                        if os.path.exists(file_path): os.remove(file_path)
                    except Exception as e_file: print(f"Eroare ștergere fișier fizic {file_obj.stored_filename}: {e_file}")
                db.session.delete(project) 

            files_as_uploader = File.query.filter(File.uploader_id == user_to_delete.id, 
                                                  File.project_assoc.has(Project.creator_id != user_to_delete.id)).all()
            for file_obj in files_as_uploader:
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_obj.stored_filename)
                    if os.path.exists(file_path): os.remove(file_path)
                    db.session.delete(file_obj)
                except Exception as e_file_other: print(f"Eroare ștergere fișier (alt proiect) {file_obj.stored_filename}: {e_file_other}")
            
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Utilizatorul {user_to_delete.username} și resursele asociate au fost șterse.', 'success')
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
        flash('Instrucțiuni trimise dacă emailul există.', 'info') # Mesaj generic
        return redirect(url_for('login'))
    for fieldName, errorMessages in form.errors.items(): 
        for err in errorMessages: flash(f"Eroare în '{getattr(form, fieldName).label.text}': {err}", 'danger')
    return render_template('reset_request.html', title='Resetează Parola', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST']) # Token-ul nu e folosit
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('home'))
    user_id_simulated = request.args.get('user_id_for_reset_simulation') 
    if not user_id_simulated:
        flash('Link de resetare invalid sau expirat (simulare necesită user_id).', 'warning')
        return redirect(url_for('reset_request'))
    user = db.session.get(User, int(user_id_simulated))
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
    return render_template('reset_token.html', title='Resetează Parola', form=form, token=token) # Paseaza token-ul la template

# 9. BLOC PENTRU RULARE DIRECTA SI CREARE DB

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
        if User.query.count() == 0:
            print("Creare admin user implicit...")
            admin_pass = generate_password_hash('adminpassword')
            admin = User(username='admin', email='admin@example.com', password=admin_pass, role='admin')
            db.session.add(admin)
            db.session.commit()
            print("Admin user (admin@example.com / adminpassword) creat.")
    app.run(debug=True)