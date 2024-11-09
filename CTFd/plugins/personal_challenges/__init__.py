import json
import os
import datetime

from flask import Blueprint, request, render_template, url_for, redirect

from CTFd.models import Challenges, Flags, db, Users
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.plugins.migrations import upgrade
from CTFd.utils.user import get_current_user
from CTFd.utils.user import get_ip
from CTFd.utils.decorators import admins_only

CHALLENGE_TYPE = "personal"
OLD_FLAG_GETTER = None

class PersonalChallenge(Challenges):
    """
        A class to represent a personal challenges model in database.
        ...

            Attributes
            ----------
            __mapper_args__ : dict
                what type of flag is this class for

            Methods
            -------
    """
    __mapper_args__ = {"polymorphic_identity": "personal"}

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.initial = kwargs["value"]

class PersonalValueChallenge(BaseChallenge):
    """
        A class to represent a personal challenges model in database.
        ...

            Attributes
            ----------
            id : String
                Unique identifier used to register challenges

            name : String
                Name of a challenge type

            templates : dict
                Handlebars templates used for each aspect of challenge editing & viewing

            scripts : dict
                Scripts that are loaded when a template is loaded

            route : String
                Route at which files are accessible. This must be registered using
                register_plugin_assets_directory()

            blueprint : Blueprint
                blueprint used to access the static_folder directory

            challenge_model : PersonalValueChallenge
                reference on class type

            cheaters_log_file : String
                name of log file containing potential cheaters players

            upload_log_file : String
                name of log file containing all attempts to upload flag

            Methods
            -------
    """
    id = CHALLENGE_TYPE
    name = CHALLENGE_TYPE
    templates = {
        "create": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/create.html",
        "update": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/update.html",
        "view": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/view.html",
    }
    scripts = {
        "create": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/create.js",
        "update": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/update.js",
        "view": "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/view.js",
    }
    route = "/plugins/" + CHALLENGE_TYPE + "_challenges/assets/"
    blueprint = Blueprint(
        CHALLENGE_TYPE + "_challenges",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )
    challenge_model = PersonalChallenge

    cheaters_log_file = "cheaters"
    upload_log_file = "uploaded"

    @classmethod
    def attempt(cls, challenge, submission):
        """
        This method is used to check whether a given input is right or wrong.
        It does not make any changes and should return a boolean for correctness
        and a string to be shown to the user. It is also in charge of parsing the
        user's input from the request itself.
        ...
             Parameters
                ----------
                challenge : Challenge
                    The Challenge object from the database
                submission : request
                    The submitted request by player

            Returns
                -------
                (boolean, String)
                    (is flag correct, message to show)
        """
        if challenge.type.lower() != 'personal' and challenge.type.lower() != 'standard':
            return False, "Challenge type isn't standard or personal, flag cannot be submitted, contact the administrator."

        allPersonalFlags = PersonalFlag.query.all()
        if len(allPersonalFlags) == 0:
            return False, "There are no personal flags in the database, contact the administrator."

        currentUserId = get_current_user().id
        currentUserFlags = PersonalFlag.query.filter_by(user_id=currentUserId).all()

        if len(currentUserFlags) == 0:
            return False, "Your user has no flags assigned, contact the administrator."

        if submission.content_type != "application/json":
            submission = submission.form
        else:
            submission = submission.get_json()
        
        correctFlag = Flags.query.filter_by(challenge_id=challenge.id).first()
        correct = False
        if challenge.type.lower() == 'standard':
            if correctFlag == submission['submission']:
                correct = True
        elif challenge.type.lower() == 'personal':
            for flag in currentUserFlags:
                if flag.variable == correctFlag.content and flag.contents == submission['submission']:
                    correct = True
                    break

        if not correct:
            return False, "Wrong flag."
        else:
            return True, "Congrats!"

class PersonalFlag(db.Model):
        __tablename__ = 'personal_flags'

        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False) 
        variable = db.Column(db.String(128), primary_key=True, nullable=False)
        contents = db.Column(db.String(128), nullable=False)

        def __init__(self, user_id, variable, flag_contents):
            self.user_id = user_id
            self.variable = variable
            self.contents = flag_contents

def log(submission, origin, challenge):
    """
        Function to log suspicious activity that may reveal cheating.

            Parameters
                ----------
                submission : dict
                    submission data

                origin : int
                    player ID

                challenge : int
                    challenge ID

            Returns
                -------
                None
    """
    filename = "/var/log/CTFd/" + PersonalValueChallenge.cheaters_log_file + ".log"
    with open(filename, 'a') as file:
        who = get_user_mail(submission["user_id"])
        from_whom = get_user_mail(origin)
        file.write(str(who) + ";" + str(from_whom) + ";" + str(submission["submission"]) + ";"
            + str(challenge) + ";" + str(datetime.datetime.now().strftime("[%d/%m/%Y %H:%M:%S]"))
            + ";" + get_ip() + ";\n")

def log_received_flag(sender_mail, sender_ip, flag, challenge):
    """
        Function to log received flags post request trying to upload flag.

            Parameters
                ----------
                sender_mail : String
                    Email address of player who sent post request

                sender_ip : String
                    IP address of player who sent post request

                flag : int
                    flag content

                challenge : int
                    challenge ID

            Returns
                -------
                None
    """
    string_log = str(sender_mail) + ";" + str(sender_ip) + ";" \
                 + str(flag) + ";" + str(challenge) + ";" \
                 + str(datetime.datetime.now().strftime("[%d/%m/%Y %H:%M:%S]")) + ";\n"

    if os.path.isfile("/var/log/CTFd/.recent_" + PersonalValueChallenge.upload_log_file
                      + "_log.log"):
        with open("/var/log/CTFd/.recent_" + PersonalValueChallenge.upload_log_file
                  + "_log.log", 'r') as last_log:
            if last_log.readline() == string_log:
                return
    with open("/var/log/CTFd/.recent_" + PersonalValueChallenge.upload_log_file
              + "_log.log", 'w') as last_log:
        last_log.write(string_log)
    with open("/var/log/CTFd/" + PersonalValueChallenge.upload_log_file + ".log", 'a') as log_file:
        log_file.write(string_log)

def get_user_id(mail):
    """
        Function to get user ID from mail.
            Parameters
                ----------
                mail : String
                    email

            Returns
                -------
                int :
                    user ID


    """
    user = Users.query.filter_by(email=mail).first()
    if user:
        return user.id
    return 0

def get_user_id_by_name(username):
    user = Users.query.filter_by(name=username).first()
    if user:
        return user.id
    return 0

def get_user_mail(user_id):
    """
         Function to get user mail from ID.

            Parameters
                ----------
                user_id : int
                    user ID

            Returns
                -------
                dict
                    String :
                    user email
    """
    user = Users.query.filter_by(id=user_id).first()
    return user.email

def get_challenges():
    return Challenges.query.all()

def get_personal_flags():
    return PersonalFlag.query.all()

def validate_uploaded_json(data):
    if 'flag_data' not in data or not isinstance(data['flag_data'], list):
        return False

    for entry in data['flag_data']:
        if not isinstance(entry, dict) or 'user' not in entry or 'flags' not in entry:
            return False
        if not isinstance(entry['user'], str) or not isinstance(entry['flags'], list):
            return False

        for flag in entry['flags']:
            if not isinstance(flag, dict) or 'variable' not in flag or 'contents' not in flag:
                return False
            if not isinstance(flag['variable'], str) or not isinstance(flag['contents'], str):
                return False

    return True

def load(app):
    """
        Function to load this script into app.

            Parameters
                ----------
                app : Flask
                    a CTFd application

            Returns
                -------
                None
    """
    upgrade()
    
    CHALLENGE_CLASSES[CHALLENGE_TYPE] = PersonalValueChallenge
    register_plugin_assets_directory(
         app, base_path="/plugins/" + CHALLENGE_TYPE + "_challenges/assets/"
    )

    individual_flag_importer = Blueprint('individual_flag_importer', __name__, template_folder='assets')
    @individual_flag_importer.route('/admin/plugins/flag_importer/import', methods=['GET', 'POST'])
    @admins_only
    @bypass_csrf_protection #TEMP
    def individual_flag_importer_handler():
        if request.method == 'GET':
            blockUploadFlagsButton = True
            for challenge in get_challenges():
                if challenge.type == 'personal' and len(challenge.flags) > 0:
                    blockUploadFlagsButton = False
                    break

            return render_template('individual_flag_importer.html', blockUploadFlagsButton=blockUploadFlagsButton)
        
        if request.method == 'POST':
            if 'jsonFile' not in request.files:
                return render_template('individual_flag_importer.html', errMsg='Missing JSON file.'), 400
            
            file = request.files['jsonFile']

            if file.filename.split('.')[-1].lower() != 'json':
                return render_template('individual_flag_importer.html', errMsg='Must be JSON file.'), 400

            try:
                flagData = json.load(file)
                if not validate_uploaded_json(flagData):
                    return render_template('individual_flag_importer.html', errMsg='Invalid JSON file uploaded (unknown structure).'), 400

                nonExistingUsers = []
                existingUsers = []
                importedFlagInformation = []
                importedFlagVariables = []
                for userData in flagData['flag_data']:
                    user_id = get_user_id_by_name(userData['user'])
                    if user_id == 0:
                        nonExistingUsers.append(userData['user'])
                        continue
                    
                    req = json.loads("{}")
                    req["user_id"] = user_id
                    req['flag_data'] = []
                    for flag in userData['flags']:
                        req['flag_data'].append({
                            "variable": flag['variable'],
                            "contents": flag['contents']
                        })
                        importedFlagVariables.append(flag['variable'])

                    # req["flag_data"] = [
                    #     {
                    #         "variable": flag['variable'],
                    #         "contents": flag['contents']
                    #     } for flag in userData['flags']
                    # ]

                    importedFlagInformation.append(req)
                    existingUsers.append(userData['user'])
                

                if len(existingUsers) == 0:
                    return render_template('individual_flag_importer.html', errMsg='None of the imported users exist in CTFd.')

                ##############################
                challengePersonalFlagVariables = [] 
                for challenge in get_challenges():
                    if challenge.type == 'personal':
                        for flag in challenge.flags:
                            print(flag)
                            challengePersonalFlagVariables.append(flag.content)
                
                # Find the flags that are required but not imported
                notImportedButRequired = list(set(challengePersonalFlagVariables) - set(importedFlagVariables))
                # Find the flags that are imported but not required
                importedButNotRequiredFlags = list(set(importedFlagVariables) - set(challengePersonalFlagVariables))
                
                # Delete uneeded flags so they dont get plopped into the db
                for entry in importedFlagInformation:
                    entry['flag_data'] = [
                        flag for flag in entry['flag_data'] 
                        if flag['variable'] not in importedButNotRequiredFlags
                    ]

                print(notImportedButRequired)
                if len(notImportedButRequired) > 0:
                    return render_template('individual_flag_importer.html', notImportedButRequired=notImportedButRequired)

                try:
                    flag_models = []
                    for impfi in importedFlagInformation:
                        for flag in impfi['flag_data']:
                            flag_models.append(PersonalFlag(impfi['user_id'], flag['variable'], flag['contents']))
                    
                    for model in flag_models:
                        db.session.merge(model)

                    db.session.commit()
                    db.session.close()
                except Exception as e:
                    print('ERR' + str(e))
                    return render_template('individual_flag_importer.html', errMsg=str(e)), 500


                return render_template('individual_flag_importer.html', uploadSuccessMsg='Flags uploaded!', nonExistingUsers=nonExistingUsers, importedButNotRequiredFlags=importedButNotRequiredFlags)

            except Exception as e:
                return render_template('individual_flag_importer.html', errMsg=str(e)), 400

    @individual_flag_importer.route('/admin/plugins/flag_importer/users', methods=['GET', 'POST'])
    @admins_only
    @bypass_csrf_protection #TODO
    def individual_flag_importer_users_handler():
        # TODO: handle exceptions
        allPersonalFlags = PersonalFlag.query.all()
        allUsersMap = {user.id: user for user in Users.query.all()}

        usersWithFlags = {}
        for flag in allPersonalFlags:
            user_id = flag.user_id
            if user_id not in usersWithFlags:
                usersWithFlags[user_id] = {
                    'user_id': user_id,
                    'user_name': allUsersMap[flag.user_id].name,
                    'user_email': allUsersMap[flag.user_id].email,
                    'user_flags': []
                }
            usersWithFlags[user_id]['user_flags'].append({'solved': False, 'contents': flag.contents})

        print(list(usersWithFlags.values()))
        # TODO
        aaa = {flag.user_id for flag in allPersonalFlags}
        bbb = [user for user in allUsersMap.values() if user.id not in aaa]

        return render_template('individual_flag_users.html', usersWithFlagsList=list(usersWithFlags.values()), usersWithoutFlagsList=bbb)
    
    @individual_flag_importer.route('/admin/plugins/flag_importer/users/delete', methods=['POST'])
    @admins_only
    @bypass_csrf_protection #TODO
    def individual_flag_importer_users_delete_handler():
        # TODO: handle exceptions
        PersonalFlag.query.delete()
        db.session.commit()
        db.session.close()
        
        return redirect(url_for('individual_flag_importer.individual_flag_importer_users_handler'))

    @individual_flag_importer.route('/admin/plugins/flag_importer/cheaters', methods=['GET'])
    @admins_only
    def individual_flag_importer_cheaters_handler():
        return render_template('individual_flag_importer.html')    

    app.register_blueprint(individual_flag_importer)
