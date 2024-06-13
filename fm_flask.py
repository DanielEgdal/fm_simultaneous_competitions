from flask import session, Flask, render_template,request,redirect,url_for,jsonify,Response,send_file,make_response,send_file, flash
import requests
import json
from markupsafe import escape
from functools import wraps
from pandas import Timestamp
import datetime
import re

from secret import secret_key,mysql_code
from models import * 


app = Flask(__name__,template_folder='static/templates')

app.config.update(
    SECRET_KEY = secret_key,
    SESSION_COOKIE_SECURE = True,
    PERMANENT_SESSION_LIFETIME = 7200,
    SQLALCHEMY_DATABASE_URI = mysql_code,
    SQLAlCHEMY_TRACK_MODIFICATIONS = False
)

init_db(app)

# TODO admin button to check if every user account got a wcaid before import
# TODO export registrations to wca
# TODO some check that if venue limit is increased, or a reg is deleted, such that the waiting list is handled.

with app.app_context():
    db.create_all()
    if not Admins.query.all():
        db.session.add(Admins(id=6777))
        db.session.commit()

def is_admin():
    if session['id'] in set([admin.id for admin in Admins.query.all()]):
        return True
    else:
        return False
    
def is_organiser(competition_id):
    return (session['id'] in CompetitionOrganizers.query.filter_by(competition_id=competition_id)) or is_admin()
    
def is_manager(venue_id):
    venue_manager_query = VenueManagers.query.filter_by(venue_id=venue_id)
    if venue_manager_query.first():
        is_manager_bool = venue_manager_query.filter_by(manager_id=session['id']).first()
    else:
        is_manager_bool = False
    is_organiser_bool = is_organiser(Venues.query.filter_by(id=venue_id).first().competitions.id)

    return is_manager_bool or is_organiser_bool or is_admin()

def get_manager_for_venue(compid):
    manager_for_any_venue = VenueManagers.query.filter_by(manager_id=session['id'])\
        .join(VenueManagers.venues).join(Venues.competitions).filter_by(id=compid)
    return manager_for_any_venue.first()

def get_comp_registration(compid):
    registration = Registrations.query.filter_by(user_id=session['id'])\
        .join(Registrations.venues).join(Venues.competitions).filter_by(id=compid)
    return registration.first()

def is_any_manager_for_venue(compid):
    manager_for_any_venue = get_manager_for_venue(compid)
    return manager_for_any_venue or is_admin()
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return render_template("error_page.html", user_name=session['name'],error_str="You need to be an admin to access this page.")
        return f(*args, **kwargs)
    return decorated_function

def delegate_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session['delegate']:
            return render_template("error_page.html", user_name=session['name'],error_str="You need to be a (non Trainee) Delegate")
        return f(*args, **kwargs)
    return decorated_function

def is_logged_in():
    return not (not session['id']) # If the value is set, turning into bool

def logged_in_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return render_template("error_page.html",error_str="You need to be logged in to access this page.")
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def give_name():
    if 'name' not in session:
        session['name'] = None
    if 'id' not in session:
        session['id'] = None
    if 'delegate' not in session:
        session['delegate'] = None

@app.route('/')
def home():
    if not is_logged_in():
        return render_template('index.html',user_name=session['name'])
    else:
        return redirect(url_for('competitions'))

def get_me(header):
    return requests.get("https://api.worldcubeassociation.org/me",headers=header)

def is_non_trainee_delegate(user):
    return user.delegate_status and user.delegate_status != 'trainee_delegate'


@app.route("/localhost")
def localhost_login():
    return redirect("https://www.worldcubeassociation.org/oauth/authorize?client_id=BI5F06shcLg2tNPbVJ431p3XLGlqzRcBYsDT6flLg2I&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fshow_token&response_type=token&scope=manage_competitions+public+email+dob")

@app.route('/logout',methods=['GET','POST'])
def logout():
    keys = [key for key in session.keys()]
    for key in keys:
        session.pop(key)
    return redirect(url_for('home'))

@app.route('/show_token') 
def show_token():
    return render_template('show_token.html',user_name=session['name'])

@app.route('/process_token',methods=['POST'])
def process_token():
    access_token_temp = escape(request.form['access_token'])
    access_token= access_token_temp.split('access_token=')[1].split('&')[0]
    session['token'] = {'Authorization':f"Bearer {access_token}"}
    me = get_me(session['token'])
    if me.status_code == 200:
        cont = json.loads(me.content)
        user_name = cont['me']['name']
        user_id = int(cont['me']['id'])
        user_wcaid = cont['me']['wca_id']
        user_mail = cont['me']['email']
        delegate_status = cont['me']['delegate_status']
        gender = cont['me']['gender']
        dob = Timestamp(cont['me']['dob'])

        user = Users(
                id=user_id,
                name=user_name,
                wca_id=user_wcaid,
                email=user_mail,
                delegate_status=delegate_status,
                gender=gender,
                dob=dob
            )
        entry = Users.query.filter_by(id=user_id).first()
        if entry: # Retuner
            entry = user # update their info
            db.session.commit()
        else: # This is someone who is new to the website
        
            db.session.add(user)
            db.session.commit()
        
        session['name'] = user_name
        session['id'] = user_id
        session['delegate'] = True if delegate_status and delegate_status != 'trainee_delegate' else False
    return "Du bliver omstillet til din konto."

def get_organisers_wcif(wcif):
    organisers = []
    for person in wcif['persons']:
        for role in person['roles']:
            if role == 'organizer':
                organisers.append({'id':person['wcaUserId']})
    return organisers

@app.route("/competitions/<comp>/admin",methods=['GET','POST'])
def manage_competition(comp):
    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).')
    
    venues = Venues.query.filter_by(competition_id=comp).all()
    competition = Competitions.query.filter_by(id=comp).first()

    if request.method == 'GET':
        return render_template('admin_venue_overview.html',user_name=session['name'],competition = competition, venues=venues)

    if request.method == 'POST':
        # This toogles the auto accept of venues
        competition = Competitions.query.filter_by(id=comp).first()
        competition.accepts_new_venues_automatically ^= 1 # Flip the booleean
        db.session.commit()
        return redirect(url_for('manage_competition',comp=comp))


@app.route("/competitions/<comp>/venues/<venue_id>/toggle_visability",methods=['POST'])
def toogle_venue_visibility(comp,venue_id):
    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).')
    venue = Venues.query.filter_by(id=venue_id).first()
    venue.is_visible ^= 1 # Flip the boolean
    db.session.commit()
    return redirect(url_for('manage_competition',comp=comp))

@app.route("/competitions/<comp>/admin/import")
def import_comp(comp):
    escapedCompid = escape(comp)
    if not re.match('^[a-zA-Z\d]{5,32}$',escapedCompid):
        return render_template('error_page.html',error_str='Invalid compid format.')

    if not is_organiser(escapedCompid):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).')

    existing_comp = Competitions.query.filter_by(id=escapedCompid).first()

    comp = json.loads(requests.get(f"https://api.worldcubeassociation.org/competitions/{escapedCompid}").content)
    if 'error' in comp: # Comp is not yet announced. Use the WCIF
        comp = json.loads(requests.get(f"https://api.worldcubeassociation.org/competitions/{escapedCompid}/wcif",headers=session['token']).content)
        reg_open = Timestamp(comp['registrationInfo']['openTime'])
        reg_close = Timestamp(comp['registrationInfo']['closeTime'])
        start_date = Timestamp(comp['schedule']['startDate'])
        organisers = get_organisers_wcif(comp)
    else: # format for these fields is annoyingly different
        reg_open = Timestamp(comp['registration_open'])
        reg_close = Timestamp(comp['registration_close'])
        start_date = Timestamp(comp['start_date'])
        organisers = comp['organizers']

    name = comp['name']
    id = comp['id']
    
    if not existing_comp:
        db.session.add(Competitions(id=id,
                        name=name,registration_open=reg_open,registration_close=reg_close,
                        start_date=start_date,accepts_new_venues_automatically=True))
        for organiser in organisers:
            orga_id = organiser['id']
            db.session.add(CompetitionOrganizers(user_id=orga_id,competition_id=id))
    else:
        existing_comp.registration_open = reg_open
        existing_comp.registration_close = reg_close
        existing_comp.start_date = start_date
        for organiser in organisers:
            orga_id = organiser['id']
            if CompetitionOrganizers.query.filter_by(user_id=orga_id).first():
                continue
            db.session.add(CompetitionOrganizers(user_id=orga_id,competition_id=id))
    db.session.commit()
    return redirect(url_for('manage_competition',comp=id))



@app.route('/competitions')
def competitions():
    comps = Competitions.query.all()
    return render_template('upcoming_comps.html',user_name=session['name'],comps=comps)

@app.route('/competitions/<comp>')
def competition_view(comp):
    competition = Competitions.query.filter_by(id=comp).first()
    if competition:
        venue_count = len(Venues.query.filter_by(competition_id=comp,is_visible=True).all())
        manager_venue = get_manager_for_venue(comp)
        registration = None
        if session['id']:
            registration = get_comp_registration(comp)
        

        return render_template('competition_view.html',user_name=session['name'],competition=competition,venue_count=venue_count,delegate=session['delegate'],registration=registration,manager_venue=manager_venue, admin=is_organiser(comp))
    else:
        return "Invalid competition ID"
    
@app.route('/competitions/<comp>/venues/new',methods=['GET','POST'])
@delegate_required
def competition_new(comp):
    competition = Competitions.query.filter_by(id=comp).first()
    if not competition:
        return render_template('error_page.html',error_str='This competition does not appear in the database of this website.')
    
    if request.method == 'GET':
        return render_template('new_venue.html',user_name=session['name'],competition=competition)
    elif request.method == 'POST':
        curdate = datetime.datetime.utcnow().date()
        days_until = (competition.start_date-curdate).days -1
        if days_until >= 14:
            form_data = request.form
            country = escape(form_data["country"])
            city = escape(form_data["city"])
            address = escape(form_data["address"])
            limit = int(escape(form_data["limit"]))
            timezone = escape(form_data['timezone'])
            reg_fee_txt = escape(form_data['reg_fee'])
            auto_accept = True if request.form.getlist("auto_accept") else False
            new_venue_id = len(Venues.query.all())+1
            venue = Venues(id=new_venue_id,competition_id=comp,country=country,city=city,
                address=address,competitor_limit=limit,
                accept_registrations_automatically=auto_accept,
                timezone=timezone, registration_fee_text=reg_fee_txt, is_visible=competition.accepts_new_venues_automatically)
            db.session.add(venue)

            manager = VenueManagers(manager_id=session['id'],venue_id=new_venue_id)
            db.session.add(manager)

            db.session.commit()

            return redirect(url_for('comp_manager_view',comp=comp,venue_id=new_venue_id))
        else:
            return render_template('error_page.html',error_str='You are past the deadline for submitting a new venue for this competition.')

@app.route('/competitions/<comp>/venues/<int:venue_id>/registrations')
def venue_registration_overview(comp,venue_id):
    venue = Venues.query.filter_by(id=venue_id).first()
    registrations = Registrations.query.filter_by(venue_id=venue_id).all()
    am_accepted = len([registration for registration in registrations if registration.status=='accepted'])
    return render_template("venue_registration_overview.html",registrations=registrations,competition=venue.competitions, venue=venue,am_accepted=am_accepted,user_name=session['name'])

@app.route('/competitions/<comp>/venues/<int:venue_id>/registrations/<int:rid>',methods=['POST'])
def edit_registration_status(comp,venue_id,rid):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.')
    registration = Registrations.query.filter_by(id=rid).first()
    new_status = request.form['new_status']
    if new_status == 'accepted':
        registrations = Registrations.query.filter_by(venue_id=venue_id).all()
        am_accepted = len([registration for registration in registrations if registration.status=='accepted'])
        if am_accepted >= Venues.query.filter_by(id=venue_id).first().competitor_limit:
            return render_template('error_page.html',error_str='You cannot accept more registrations because you are over your limit. Go to increase your limit first.')
    registration.status = new_status
    db.session.commit()
    return redirect(url_for('venue_registration_overview',comp=comp,venue_id=venue_id))

@app.route('/competitions/<comp>/venues')
def comp_venues(comp):
    # TODO allow for multi lines in the payment box
    competition = Competitions.query.filter_by(id=comp).first()

    venues = Venues.query.filter_by(competition_id=comp,is_visible=True).order_by(Venues.country).all()
    registrations = [Registrations.query.filter_by(venue_id=venue.id,status='accepted').order_by(Registrations.created_at) for venue in venues]
    delegates = []

    for venue in venues:
        tmp_delegates = []
        for manager in VenueManagers.query.filter_by(venue_id=venue.id).all():
            if manager.users.delegate_status:
                tmp_delegates.append(manager.users.name)
        delegates.append(tmp_delegates)
    return render_template('venues.html',user_name=session['name'],venues=venues,competition=competition, registrations=registrations, delegates=delegates,admin=is_organiser(comp))

@app.route('/competitions/<comp>/venues/<int:venue_id>/manager',methods=['GET','POST'])
def comp_manager_view(comp,venue_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.')
    competition = Competitions.query.filter_by(id=comp).first()
    venue = Venues.query.filter_by(id=venue_id).first()
    if request.method == 'GET':
        venue_managers = VenueManagers.query.filter_by(venue_id=venue_id).all()
        return render_template('manager_view.html',competition=competition,venue=venue,venue_managers=venue_managers)
    elif request.method == 'POST':
        wcaid = escape(request.form.get('wcaid'))
        pattern = re.compile("^[A-Z\d]+$")
        if not (pattern.match(wcaid) and len(wcaid) == 10):
            return render_template('error_page.html',error_str='You supplied a WCAID of wrong format.')
        
        user = Users.query.filter_by(wca_id=wcaid).first()
        if user:
            manager = VenueManagers(
                manager_id = user.id,
                venue_id = venue_id
            )
            db.session.add(manager)
            db.session.commit()
        return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

@app.route('/competitions/<comp>/venues/<int:venue_id>/manager/delete/<int:manager_id>',methods=['POST'])
def delete_manager(comp,venue_id,manager_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.')
    managers = VenueManagers.query.filter_by(venue_id=venue_id).all()
    am_delegates = len([manager for manager in managers if is_non_trainee_delegate(manager.users)])
    user_to_remove = VenueManagers.query.filter_by(manager_id=manager_id,venue_id=venue_id)
    if am_delegates > 1 or not is_non_trainee_delegate(user_to_remove.first().users) or is_admin(): # ensure you are only deleting a delegate if there is more than one
        user_to_remove.delete()
        db.session.commit()
    else:
        return render_template('error_page.html',error_str='Error: You tried to remove the only delegate for the competition')
    return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

@app.route('/competitions/<comp>/venues/<int:venue_id>/edit',methods=['GET','POST'])
def edit_venue(comp,venue_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.')
    competition = Competitions.query.filter_by(id=comp).first()
    venue = Venues.query.filter_by(id=venue_id).first()
    if request.method == 'GET':
        return render_template('edit_venue.html',competition=competition,venue=venue)
    elif request.method == 'POST':
        form_data = request.form
        venue.country = escape(form_data["country"])
        venue.city = escape(form_data["city"])
        venue.address = escape(form_data["address"])
        venue.competitor_limit = int(escape(form_data["limit"]))
        venue.timezone = escape(form_data['timezone'])
        venue.registration_fee_text = escape(form_data['reg_fee'])
        venue.accept_registrations_automatically = True if request.form.getlist("auto_accept") else False
        db.session.commit()
        return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

# TODO add button for delete own registration
@app.route('/competitions/<comp>/register', methods=['GET','POST'])
@logged_in_required
def register(comp):
    timestamp = datetime.datetime.utcnow()
    competition = Competitions.query.filter_by(id=comp).first()
    if not competition:
        return render_template('error_page.html',error_str='Invalid competition id')
    
    registration = get_comp_registration(comp)
    opens_in = round((competition.registration_open - timestamp).total_seconds())
    closes_in = round((competition.registration_close - timestamp).total_seconds())
    venues = Venues.query.filter_by(competition_id=comp,is_visible=True).all()
    if request.method == 'GET':
        print(registration)
        return render_template('register.html',user_name=session['name'],competition=competition,venues=venues,opens_in=opens_in,closes_in=closes_in,registration=registration)
    elif request.method == 'POST':

        if not(opens_in <= 0 and closes_in >= 0):
            return render_template('error_page.html',error_str='Your registration is not valid as registration is not open.')
        
        form_data = request.form
        venue_id = int(escape(form_data["venues"]))
        venue = Venues.query.filter_by(id=venue_id).first()
        if venue.competition_id != comp:
            return render_template('error_page.html',error_str='You did something weird in the form. The venue ID did not match the competition you are at.')
        if venue.accept_registrations_automatically:
            limit = venue.competitor_limit
            reg_count = len(Registrations.query.filter_by(venue_id=venue_id).filter(Registrations.status!="deleted").all())
            if reg_count < limit:
                status = 'accepted'
            else:
                status = 'pending'
        else:
            status = 'pending'

        if not registration:
            reg = Registrations(venue_id=venue_id,user_id=session['id'],created_at=timestamp,status=status)
            db.session.add(reg)
        else:
            reg = registration
            reg.venue_id = venue_id
            reg.created_at = timestamp
            reg.status = status
        db.session.commit()
        flash(f'You have submitted your registration. The current status is {status}')
        return redirect(url_for('comp_venues',comp=comp))


if __name__ == '__main__':
    app.run(port=5000,debug=True)

