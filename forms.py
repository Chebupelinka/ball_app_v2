from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, IntegerField, DateTimeField
from wtforms.validators import DataRequired, Email, Optional, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')

class UserCreateForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=80)])
    full_name = StringField('Полное имя', validators=[DataRequired(), Length(max=100)])
    contact = StringField('Контакт (телефон/email)', validators=[Optional(), Length(max=100)])
    role = SelectField('Роль', choices=[('participant', 'Участник'), ('organizer', 'Организатор'), ('admin', 'Администратор')], validators=[DataRequired()])
    password = PasswordField('Пароль (оставьте пустым для автоматической генерации)', validators=[Optional(), Length(min=4)])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Пользователь с таким логином уже существует.')

class EventForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание', validators=[Optional()])
    date = DateTimeField('Дата и время', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])  # для поля datetime-local
    location = StringField('Место проведения', validators=[DataRequired(), Length(max=200)])
    max_participants = IntegerField('Максимальное количество участников (0 - без лимита)', default=0, validators=[Optional()])

class RegisterForEventForm(FlaskForm):
    # Форма для записи участника (может быть пустой, просто кнопка)
    pass