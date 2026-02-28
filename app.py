import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from models import db, User, Event, Registration
from forms import LoginForm, UserCreateForm, EventForm, RegisterForEventForm
from datetime import datetime
from wtforms.validators import Optional
# Создаём приложение
app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'  # измените на случайную строку в продакшене
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализируем расширения
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # имя функции для входа

# Загружаем пользователя по id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Создаём таблицы при первом запуске (если не существуют)
with app.app_context():
    db.create_all()
    # Создадим первого администратора, если нет ни одного пользователя
    if not User.query.first():
        admin = User(
            username='admin',
            role='admin',
            full_name='Administrator',
            contact=''
        )
        admin.set_password('admin123')  # измените пароль!
        db.session.add(admin)
        db.session.commit()
        print('Создан пользователь admin с паролем admin123')

# Подключаем формы (будем создавать позже)

# --- Вспомогательные функции для проверки ролей ---
def admin_required(func):
    from functools import wraps
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('У вас нет прав доступа к этой странице.', 'danger')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return decorated_view

def organizer_required(func):
    from functools import wraps
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_organizer() and not current_user.is_admin()):
            flash('У вас нет прав доступа к этой странице.', 'danger')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return decorated_view

# --- Маршруты ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Вы успешно вошли в систему.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

# --- Маршруты для администратора ---

@app.route('/users')
@login_required
@admin_required
def users_list():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def user_create():
    form = UserCreateForm()
    if form.validate_on_submit():
        # Проверяем, что username уникален
        if User.query.filter_by(username=form.username.data).first():
            flash('Пользователь с таким логином уже существует.', 'danger')
            return render_template('user_create.html', form=form)
        user = User(
            username=form.username.data,
            role=form.role.data,
            full_name=form.full_name.data,
            contact=form.contact.data
        )
        # Генерируем пароль, если поле не заполнено (можно оставить пустым для автогенерации)
        password = form.password.data
        if not password:
            import secrets
            password = secrets.token_urlsafe(8)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'Пользователь {user.full_name} создан. Пароль: {password}', 'success')
        return redirect(url_for('users_list'))
    return render_template('user_create.html', form=form)

@app.route('/events/create', methods=['GET', 'POST'])
@login_required
@admin_required
def event_create():
    form = EventForm()
    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            date=form.date.data,
            location=form.location.data,
            max_participants=form.max_participants.data,
            created_by=current_user.id
        )
        db.session.add(event)
        db.session.commit()
        flash('Мероприятие создано.', 'success')
        return redirect(url_for('events_list'))
    return render_template('create_event.html', form=form, title='Создать мероприятие')

@app.route('/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def event_edit(event_id):
    event = Event.query.get_or_404(event_id)
    form = EventForm(obj=event)
    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        event.date = form.date.data
        event.location = form.location.data
        event.max_participants = form.max_participants.data
        db.session.commit()
        flash('Мероприятие обновлено.', 'success')
        return redirect(url_for('events_list'))
    return render_template('create_event.html', form=form, title='Редактировать мероприятие')

@app.route('/events/<int:event_id>/delete')
@login_required
@admin_required
def event_delete(event_id):
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Мероприятие удалено.', 'success')
    return redirect(url_for('events_list'))

# --- Маршруты для всех пользователей (список мероприятий) ---

@app.route('/event/<int:event_id>')
@login_required
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    # Проверяем, зарегистрирован ли текущий пользователь
    registration = Registration.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    # Для организатора и админа - полная информация о регистрациях
    if current_user.is_admin() or current_user.is_organizer():
        registrations = Registration.query.filter_by(event_id=event.id).all()
        return render_template('event_organizer.html', event=event, registrations=registrations, registration=registration)
    else:
        # Участник видит только информацию о мероприятии и статус своей записи
        return render_template('event_participant.html', event=event, registration=registration)

# --- Участник: запись на мероприятие ---

@app.route('/event/<int:event_id>/register', methods=['POST'])
@login_required
def event_register(event_id):
    event = Event.query.get_or_404(event_id)

    # Проверяем, не прошло ли уже мероприятие
    if event.date < datetime.utcnow():
        flash('Нельзя записаться на прошедшее мероприятие.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))

    # Проверяем, не записан ли уже
    existing = Registration.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    if existing:
        flash('Вы уже записаны на это мероприятие.', 'warning')
        return redirect(url_for('event_detail', event_id=event.id))

    # Проверяем лимит
    if event.max_participants > 0:
        registered_count = Registration.query.filter_by(event_id=event.id, status='registered').count()
        if registered_count >= event.max_participants:
            flash('Достигнут лимит участников. Обратитесь к организатору.', 'danger')
            return redirect(url_for('event_detail', event_id=event.id))

    reg = Registration(user_id=current_user.id, event_id=event.id, status='registered')
    db.session.add(reg)
    db.session.commit()
    flash('Вы успешно записаны на мероприятие.', 'success')
    return redirect(url_for('event_detail', event_id=event.id))

@app.route('/event/<int:event_id>/mark/<int:reg_id>')
@login_required
@organizer_required
def mark_attendance(event_id, reg_id):
    reg = Registration.query.get_or_404(reg_id)
    if reg.event_id != event_id:
        flash('Неверная регистрация.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))

    if reg.status == 'attended':
        flash('Участник уже отмечен.', 'info')
    else:
        reg.status = 'attended'
        reg.attended_at = datetime.utcnow()
        reg.marked_by = current_user.id
        db.session.commit()
        flash('Участник отмечен.', 'success')
    return redirect(url_for('event_detail', event_id=event_id))

# --- Организатор: добавление участника сверх лимита ---

@app.route('/event/<int:event_id>/add_participant', methods=['GET', 'POST'])
@login_required
@organizer_required
def add_participant(event_id):
    event = Event.query.get_or_404(event_id)
    if request.method == 'POST':
        # Ищем пользователя по username (или можно по email)
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Пользователь с таким логином не найден.', 'danger')
            return redirect(url_for('add_participant', event_id=event_id))

        # Проверяем, не записан ли уже
        existing = Registration.query.filter_by(user_id=user.id, event_id=event.id).first()
        if existing:
            flash('Этот пользователь уже записан на мероприятие.', 'warning')
            return redirect(url_for('event_detail', event_id=event_id))

        # Добавляем регистрацию с флагом added_by_organizer
        reg = Registration(user_id=user.id, event_id=event.id, status='registered', added_by_organizer=True)
        db.session.add(reg)
        db.session.commit()
        flash(f'Участник {user.full_name} добавлен.', 'success')
        return redirect(url_for('event_detail', event_id=event_id))

    return render_template('add_participant.html', event=event)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UserCreateForm(obj=current_user)
    # Убираем поле роли и логина для редактирования (логин менять нельзя)
    del form.role
    del form.username
    # Пароль делаем необязательным для заполнения
    form.password.validators = [Optional()]

    if form.validate_on_submit():
        current_user.full_name = form.full_name.data
        current_user.contact = form.contact.data
        if form.password.data:  # если ввели новый пароль
            current_user.set_password(form.password.data)
        db.session.commit()
        flash('Профиль обновлён.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)


@app.route('/profile/<int:user_id>')
@login_required
@admin_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)


@app.route('/generate_credentials/<int:user_id>')
@login_required
@admin_required
def generate_credentials(user_id):
    user = User.query.get_or_404(user_id)
    import secrets
    import string

    # Генерируем новый пароль (8 символов, буквы и цифры)
    alphabet = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(alphabet) for _ in range(8))

    user.set_password(new_password)
    db.session.commit()

    flash(f'Для пользователя {user.full_name} сгенерирован новый пароль: {new_password}', 'success')
    return redirect(url_for('user_profile', user_id=user.id))


@app.route('/events')
@login_required
def events_list():
    # Получаем параметры фильтрации из запроса
    filter_type = request.args.get('filter', 'all')  # all, upcoming, past
    search = request.args.get('search', '')

    query = Event.query

    # Фильтр по дате
    now = datetime.utcnow()
    if filter_type == 'upcoming':
        query = query.filter(Event.date >= now)
    elif filter_type == 'past':
        query = query.filter(Event.date < now)

    # Поиск по названию
    if search:
        query = query.filter(Event.title.ilike(f'%{search}%'))

    events = query.order_by(Event.date).all()
    return render_template('events.html', events=events, filter_type=filter_type, search=search)

# --- Запуск ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)