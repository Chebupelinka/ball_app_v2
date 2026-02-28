from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='participant')  # admin, organizer, participant
    full_name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_organizer(self):
        return self.role == 'organizer'

    def is_participant(self):
        return self.role == 'participant'


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    max_participants = db.Column(db.Integer, default=0)  # 0 = без лимита
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Связь с регистрациями
    registrations = db.relationship('Registration', backref='event', lazy=True, cascade='all, delete-orphan')


class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.String(20), default='registered')  # registered, attended, cancelled
    added_by_organizer = db.Column(db.Boolean, default=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    attended_at = db.Column(db.DateTime, nullable=True)
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # организатор, который отметил

    # Уникальность пары user-event (чтобы участник не мог записаться дважды)
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_registration'),)

    user = db.relationship('User', foreign_keys=[user_id])
    marker = db.relationship('User', foreign_keys=[marked_by])