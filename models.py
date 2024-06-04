from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Admins(db.Model):
    id = db.Column(db.Integer,primary_key=True)

class Competitions(db.Model):
    id = db.Column(db.String(32),primary_key=True)
    name = db.Column(db.String(50))
    start_date = db.Column(db.Date())
    registration_open = db.Column(db.DateTime())
    registration_close = db.Column(db.DateTime())

    def __repr__(self):
        return self.name

class Users(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(100))
    wca_id = db.Column(db.String(10),unique=True, nullable=True)
    email = db.Column(db.String(100),nullable=False)
    delegate_status = db.Column(db.String(30),nullable=True)

    def __repr__(self):
        return f"{self.name}"

class Venues(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    address = db.Column(db.String(100))
    competitor_limit = db.Column(db.Integer)
    accept_registrations_automatically = db.Column(db.Boolean)
    timezone = db.Column(db.String(10))
    registration_fee_text = db.Column(db.String(1000))

    competitions = db.relationship('Competitions', backref=db.backref('venues', lazy=True))
    competition_id = db.Column(db.Integer, db.ForeignKey('competitions.id'), nullable=False)

    def __str__(self):
        return f"{self.city}, {self.country}"

class VenueManagers(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    venues = db.relationship('Venues', backref=db.backref('venueManagers', lazy=True))
    venue_id = db.Column(db.Integer, db.ForeignKey('venues.id'), nullable=False)

    users = db.relationship('Users', backref=db.backref('venueManagers', lazy=True))
    manager_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class Registrations(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    venues = db.relationship('Venues', backref=db.backref('registrations', lazy=True))
    venue_id = db.Column(db.Integer, db.ForeignKey('venues.id'), nullable=False)
    created_at = db.Column(db.DateTime())

    users = db.relationship('Users', backref=db.backref('registrations', lazy=True))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    status = db.Column(db.String(20),nullable=False)

def init_db(app):
    db.init_app(app)