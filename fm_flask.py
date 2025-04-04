from flask import session, Flask, render_template,request,redirect,url_for,jsonify,Response,send_file,make_response,send_file, flash
import requests
from time import sleep
from geopy.geocoders import Nominatim
from timezonefinder import TimezoneFinder
from geopy.exc import GeocoderUnavailable, GeocoderServiceError
import pycountry
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

# TODO call for generating all content for a locations tab on wca.
# TODO admin button to check if every user account got a wcaid before import
# TODO some check that if venue limit is increased, or a reg is deleted, such that the waiting list is handled.
# TODO add back link to WCA website

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
    organizer_tuples = CompetitionOrganizers.query.filter_by(competition_id=competition_id).with_entities(CompetitionOrganizers.user_id).all()
    organizers = set([orga[0] for orga in organizer_tuples])
    return (session['id'] in organizers) or is_admin()
    
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
            return render_template("error_page.html",error_str="You need to be logged in to access this page.", user_name=session['name'])
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

@app.route('/login')
def login():
    return redirect("https://www.worldcubeassociation.org/oauth/authorize?client_id=BI5F06shcLg2tNPbVJ431p3XLGlqzRcBYsDT6flLg2I&redirect_uri=https%3A%2F%2Ffm.danskspeedcubingforening.dk%2Fshow_token&response_type=token&scope=manage_competitions+public+email+dob")

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
        country = cont['me']['country']['id']

        user = Users(
                id=user_id,
                name=user_name,
                wca_id=user_wcaid,
                email=user_mail,
                delegate_status=delegate_status,
                gender=gender,
                dob=dob,
                country = country
            )
        entry = Users.query.filter_by(id=user_id).first()
        if entry: # Retuner, update their info
                entry.name = user_name
                entry.wca_id = user_wcaid
                entry.email = user_mail
                entry.delegate_status = delegate_status
                entry.gender = gender
                entry.dob = dob
                entry.country = country
        else: # This is someone who is new to the website
        
            db.session.add(user)
        db.session.commit()
        
        session['name'] = user_name
        session['id'] = user_id
        session['delegate'] = True if delegate_status and delegate_status != 'trainee_delegate' else False
    return "You are being redirected."

def get_organisers_wcif(wcif):
    organisers = []
    for person in wcif['persons']:
        for role in person['roles']:
            if role == 'organizer':
                organisers.append({'id':person['wcaUserId']})
    return organisers

@app.route('/competitions')
def competitions():
    one_day_ago = datetime.datetime.today() - datetime.timedelta(days=1)
    comps = Competitions.query.filter(Competitions.start_date>one_day_ago)
    return render_template('upcoming_comps.html',user_name=session['name'],comps=comps)

@app.route("/competitions/<comp>/admin",methods=['GET','POST'])
def manage_competition(comp):
    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).', user_name=session['name'])
    
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

@app.route("/competitions/<comp>/admin/export",methods=['GET'])
def export_registrations(comp):
    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).', user_name=session['name'])
    
    registrations = Registrations.query.join(Venues,Registrations.venue_id == Venues.id)\
            .filter(Venues.competition_id==comp).filter(Venues.is_visible==True).all()
    csv = "Status,Name,Country,WCA ID,Birth Date,Gender,333fm,Email"
    for registrant in registrations:
        status = registrant.status[0] # Get the first char, per WCA structure
        line = f"\n{status},{registrant.users.name},{registrant.users.country},{registrant.users.wca_id if registrant.users.wca_id else ''},{registrant.users.dob},{registrant.users.gender},1,{registrant.users.email}"
        csv += line
    return Response(csv,mimetype="application/csv",headers={'Content-Disposition': f'attachment;filename={comp}_reg_export.csv'})

@app.route("/competitions/<comp>/venues/<venue_id>/toggle_visability",methods=['POST'])
def toogle_venue_visibility(comp,venue_id):
    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).', user_name=session['name'])
    venue = Venues.query.filter_by(id=venue_id).first()
    venue.is_visible ^= 1 # Flip the boolean
    db.session.commit()
    return redirect(url_for('manage_competition',comp=comp))

@app.route("/competitions/<comp>/admin/import")
@logged_in_required
def import_comp(comp):
    escapedCompid = escape(comp)
    if not re.match('^[a-zA-Z\d]{5,32}$',escapedCompid):
        return render_template('error_page.html',error_str='Invalid compid format.', user_name=session['name'])

    if not is_organiser(comp):
        return render_template('error_page.html',error_str='You are not an organiser of the competition, or the competition has not been imported yet (contact admin).', user_name=session['name'])

    existing_comp = Competitions.query.filter_by(id=comp).first()

    comp_json = json.loads(requests.get(f"https://api.worldcubeassociation.org/competitions/{comp}").content)
    if 'error' in comp_json: # Comp is not yet announced. Use the WCIF
        comp_json = json.loads(requests.get(f"https://www.worldcubeassociation.org/api/v0/competitions/{comp}/wcif",headers=session['token']).content)
        if 'error' in comp_json:
            return render_template('error_page.html',error_str='The WCA website responded with an error when trying to get the WCIF. Potentially not a valid token.', user_name=session['name'])
        reg_open = Timestamp(comp_json['registrationInfo']['openTime']).strftime('%Y-%m-%d %H:%M:%S')
        reg_close = Timestamp(comp_json['registrationInfo']['closeTime']).strftime('%Y-%m-%d %H:%M:%S')
        start_date = Timestamp(comp_json['schedule']['startDate'])
        organisers = get_organisers_wcif(comp_json)
    else: # format for these fields is annoyingly different
        reg_open = Timestamp(comp_json['registration_open']).strftime('%Y-%m-%d %H:%M:%S')
        reg_close = Timestamp(comp_json['registration_close']).strftime('%Y-%m-%d %H:%M:%S')
        start_date = Timestamp(comp_json['start_date'])
        organisers = comp_json['organizers']

    name = comp_json['name']
    id = comp_json['id']
    
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
        return render_template('error_page.html',error_str='This competition does not appear in the database of this website.', user_name=session['name'])
    
    if request.method == 'GET':
        return render_template('new_venue.html',user_name=session['name'],competition=competition)
    elif request.method == 'POST':
        curdate = datetime.datetime.utcnow().date()
        days_until = (competition.start_date-curdate).days -1
        if days_until >= 14:
            form_data = request.form
            country = form_data["country"]
            city = form_data["city"]
            address = form_data["address"]
            limit = int(escape(form_data["limit"]))
            timezone = form_data['timezone']
            reg_fee_txt = form_data['reg_fee']
            auto_accept = True if request.form.getlist("auto_accept") else False
            new_venue_id = max([venue.id for venue in Venues.query.all()])+1
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
            return render_template('error_page.html',error_str='You are past the deadline for submitting a new venue for this competition.', user_name=session['name'])

@app.route('/competitions/<comp>/venues/<int:venue_id>/registrations')
@logged_in_required
def venue_registration_overview(comp,venue_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.', user_name=session['name'])
    venue = Venues.query.filter_by(id=venue_id).first()
    registrations = Registrations.query.filter_by(venue_id=venue_id).all()
    am_accepted = len([registration for registration in registrations if registration.status=='accepted'])
    return render_template("venue_registration_overview.html",registrations=registrations,competition=venue.competitions, venue=venue,am_accepted=am_accepted,user_name=session['name'])

@app.route('/competitions/<comp>/venues/<int:venue_id>/registrations/<int:rid>',methods=['POST'])
@logged_in_required
def edit_registration_status(comp,venue_id,rid):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.', user_name=session['name'])
    registration = Registrations.query.filter_by(id=rid).first()
    new_status = request.form['new_status']
    if new_status == 'accepted':
        registrations = Registrations.query.filter_by(venue_id=venue_id).all()
        am_accepted = len([registration for registration in registrations if registration.status=='accepted'])
        if am_accepted >= Venues.query.filter_by(id=venue_id).first().competitor_limit:
            return render_template('error_page.html',error_str='You cannot accept more registrations because you are over your limit. Go to increase your limit first.', user_name=session['name'])
    registration.status = new_status
    db.session.commit()
    return redirect(url_for('venue_registration_overview',comp=comp,venue_id=venue_id))

@app.route('/competitions/<comp>/venues')
def comp_venues(comp):
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
@logged_in_required
def comp_manager_view(comp,venue_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.')
    competition = Competitions.query.filter_by(id=comp).first()
    venue = Venues.query.filter_by(id=venue_id).first()
    if request.method == 'GET':
        venue_managers = VenueManagers.query.filter_by(venue_id=venue_id).all()
        return render_template('manager_view.html',competition=competition,venue=venue,venue_managers=venue_managers, user_name=session['name'])
    elif request.method == 'POST':
        wcaid = request.form.get('wcaid')
        pattern = re.compile("^[A-Z\d]+$")
        if not (pattern.match(escape(wcaid)) and len(wcaid) == 10):
            return render_template('error_page.html',error_str='You supplied a WCAID of wrong format.', user_name=session['name'])
        
        user = Users.query.filter_by(wca_id=wcaid).first()
        if not user:
            success, user = get_user_data_wca(wcaid)
            if not success:
                return render_template('error_page.html',error_str='This WCA ID does not exist or the WCA website is bad.', user_name=session['name'])
            db.session.add(user)

        manager = VenueManagers(
            manager_id = user.id,
            venue_id = venue_id
        )
        db.session.add(manager)
        db.session.commit()

        return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

def get_user_data_wca(wcaid):
    response = requests.get(f'https://api.worldcubeassociation.org/users/{wcaid}')
    if (not response.status_code == 200):
        return False, None
    content_json = json.loads(response.content)
    if 'user' not in content_json:
        return False, None
    content = content_json['user']
    email = content['email'] if 'email' in content else None
    user = Users(id=content['id'],name=content['name'],dob=None,gender=content['gender'],
          wca_id=content['wca_id'],delegate_status=content['delegate_status'], email=email,country=content['country']['id'])
    return True,user


@app.route('/competitions/<comp>/venues/<int:venue_id>/manager/delete/<int:manager_id>',methods=['POST'])
@logged_in_required
def delete_manager(comp,venue_id,manager_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.', user_name=session['name'])
    managers = VenueManagers.query.filter_by(venue_id=venue_id).all()
    am_delegates = len([manager for manager in managers if is_non_trainee_delegate(manager.users)])
    user_to_remove = VenueManagers.query.filter_by(manager_id=manager_id,venue_id=venue_id)
    if am_delegates > 1 or not is_non_trainee_delegate(user_to_remove.first().users) or is_admin(): # ensure you are only deleting a delegate if there is more than one
        user_to_remove.delete()
        db.session.commit()
    else:
        return render_template('error_page.html',error_str='Error: You tried to remove the only delegate for the competition', user_name=session['name'])
    return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

@app.route('/competitions/<comp>/venues/<int:venue_id>/edit',methods=['GET','POST'])
@logged_in_required
def edit_venue(comp,venue_id):
    if not is_manager(venue_id):
        return render_template('error_page.html',error_str='You are not a manager of this venue.', user_name=session['name'])
    competition = Competitions.query.filter_by(id=comp).first()
    venue = Venues.query.filter_by(id=venue_id).first()
    if request.method == 'GET':
        return render_template('edit_venue.html',competition=competition,venue=venue, user_name=session['name'])
    elif request.method == 'POST':
        form_data = request.form
        venue.country = form_data["country"]
        venue.city = form_data["city"]
        venue.address = form_data["address"]
        venue.competitor_limit = int(escape(form_data["limit"]))
        venue.timezone = form_data['timezone']
        venue.registration_fee_text = form_data['reg_fee']
        venue.accept_registrations_automatically = True if request.form.getlist("auto_accept") else False
        db.session.commit()
        return redirect(url_for('comp_manager_view',comp=comp,venue_id=venue_id))

def format_seconds(seconds):
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    seconds = int(seconds)
    return f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"

def get_coordinates_for_venues(compid, venues):
    geolocator = Nominatim(user_agent="fm_venue_application")
    time_zone_finder = TimezoneFinder() 
    locations = []
    timezones = []
    for venue in venues:
        print("starting ", venue)
        while True:
            try:
                sleep(0.5)
                address = f"{venue.address.split('-')[0]}, {venue.city}, {venue.country}"
                print(f"address: {address}")
                location = geolocator.geocode(address,timeout=5)
                # print(venue,location)
                if not location:
                    print("didnt find location")
                    address = f"{venue.city}, {venue.country}"
                    location = geolocator.geocode(address)
                if location:
                    locations.append((location.latitude, location.longitude))
                    timezone = time_zone_finder.timezone_at(lat=location.latitude, lng=location.longitude)
                    timezones.append(timezone)
                    print(f"Finished {venue}, {len(locations)}")
                    break
            except (requests.exceptions.ConnectionError,GeocoderUnavailable,GeocoderServiceError) as e:
                print(f"hitting the except, {e}")
                geolocator = Nominatim(user_agent="fm_venue_application")
                continue
    return locations, timezones

@app.route('/competitions/<compid>/admin/schedule_update')
@admin_required
def update_schedule_wca(compid):
    venues = Venues.query.filter_by(competition_id=compid).filter_by(is_visible=True).all()
    locations,timezones = get_coordinates_for_venues(compid=compid,venues=venues)
    # print(len(venues),len(locations),len(timezones))
    wcif = comp_json = json.loads(requests.get(f"https://www.worldcubeassociation.org/api/v0/competitions/{compid}/wcif",headers=session['token']).content)
    schedule = wcif['schedule']

    current_venues = set([extension['data']['venue_id'] for schedule_venue in schedule['venues'] for extension in schedule_venue['extensions']])
    for idx,venue in enumerate(venues):
        name = f"{venue.city}, {venue.country}"
        if venue.id in current_venues: # TODO something for updating exisiting venues
            continue
        new_venue = {"id":len(schedule['venues'])+1,
                     "name": name, 
                     "latitudeMicrodegrees": int(locations[idx][0]*1_000_000),
                     "longitudeMicrodegrees": int(locations[idx][1]*1_000_000),
                     "countryIso2": pycountry.countries.search_fuzzy(venue.country)[0].alpha_2,
                     "timezone":timezones[idx],
                     "rooms":[],
                     "extensions":[
                         {"id":"FM_simul_comps", "specUrl": "https://fm.danskspeedcubingforening.dk/", "data":{"venue_id":venue.id}}
                     ]}
        schedule['venues'].append(new_venue)
    wcif['schedule'] = schedule
    r = requests.patch(f"https://www.worldcubeassociation.org/api/v0/competitions/{compid}/wcif", json=wcif,headers=session['token'])
    print("This was the request: ",r,r.content)
    return wcif

@app.route('/competitions/<comp>/register', methods=['GET','POST'])
@logged_in_required
def register(comp):
    timestamp = datetime.datetime.utcnow()
    competition = Competitions.query.filter_by(id=comp).first()
    if not competition:
        return render_template('error_page.html',error_str='Invalid competition id', user_name=session['name'])
    
    registration = get_comp_registration(comp)
    opens_in = round((competition.registration_open - timestamp).total_seconds())
    closes_in = round((competition.registration_close - timestamp).total_seconds())
    venues = Venues.query.filter_by(competition_id=comp,is_visible=True).all()
    opens_in_formatted = format_seconds(opens_in)
    closes_in_formatted = format_seconds(closes_in)
    if request.method == 'GET':
        return render_template('register.html',user_name=session['name'],competition=competition,
                               venues=venues,opens_in=opens_in,closes_in=closes_in,registration=registration,
                               opens_in_formatted=opens_in_formatted, closes_in_formatted=closes_in_formatted)
    elif request.method == 'POST':

        if not(opens_in <= 0 and closes_in >= 0):
            return render_template('error_page.html',error_str='Your registration is not valid as registration is not open.', user_name=session['name'])
        
        form_data = request.form
        venue_id = int(escape(form_data["venues"]))
        venue = Venues.query.filter_by(id=venue_id).first()
        if venue.competition_id != comp:
            return render_template('error_page.html',error_str='You did something weird in the form. The venue ID did not match the competition you are at.', user_name=session['name'])
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

@app.route('/competitions/<comp>/register/delete', methods=['POST'])
@logged_in_required
def delete_own_registration(comp):
    registration = get_comp_registration(comp)
    registration.status = 'deleted'
    db.session.commit()
    flash(f'You have now deleted your own registration.')
    return redirect(url_for('comp_venues',comp=comp))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html',user_name=session['name'])

if __name__ == '__main__':
    app.run(port=5000,debug=True)

