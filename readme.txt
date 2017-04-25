# Multi-User Blog

The goal of this project is to create a simple multi-user blog. 

Users should be able to create an account with login/logout functionality.
Users can post an article and comment on other user posts.
They can manage their posts and their post comments.

The application is created for the Google Cloud Platform using the Google App Engine as part of the Udacity Full Stack Web Developer Nanod Project 3: Multi-User Blog

Checkout the [live](https://xxx.appspot.com/) version of this project.

### Frameworks/technologies used
- [Google App Engine](https://cloud.google.com/appengine/docs)
- [PureCSS](http://purecss.io/)
- [FontAwesome](http://fontawesome.io)

### Project specifications

Blog features:
- Front page lists blog posts. Public page allows targetted optomisations for non-logged in users.
- Auto-authorise comments (OFF by default - comments are hidden until author checks them)
- Close comments (OFF by default - users can comment)
- Hide comments (OFF by default - show comments)
- Users can vote for blog and comments.
- Blog comments are sorted by vote (showing the best comments at the top).

Registration/Login features:
- A registration form that validates user input, and displays the error(s) when necessary.
- Cookie is set on succesful authorisation and login.
- Unauthorised access is redirected to home page.

Users features:
- Users should only be able to edit/delete their own posts and their post comments.
- Users can like/unlike posts or comments, but not their own.
- Users can comment on any posts.

Code conforms to the [Python Style Guide](https://www.python.org/dev/peps/pep-0008/)

### Setting up the project

1. [Clone](https://github.com/screamingjungle/xxx.git) this repo.

2. Install [pip](https://pip.pypa.io/en/stable/installing/) and [virtualenv](https://virtualenv.pypa.io/)

3. Create a virtualenv. App is compatible with Python 2.7.
        $ virtualenv env

        $ source env/bin/activate
        or on Windows:
        > env\Scripts\activate

4. Install the dependencies needed to run the app.
        $ pip install -r requirements.txt

5. In the *app.yaml* file, modify *env_variables* section to suit your needs. Change the SECRET key.

6. Follow instructions below for installing and setting up Google App Engine with the project.

### Setting up your environment

1. [Install Python](https://www.python.org/downloads/).
2. [Install Google App Engine SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python).
3. Open GoogleAppEngineLauncher.
4. [Sign Up for a Google App Engine Account](https://appengine.google.com/).
5. Create a new project in [Google’s Developer Console](https://console.cloud.google.com/) using a unique name.
6. Create a new project from the file menu and choose this project's folder.
7. Deploy this project by pressing deploy in GoogleAppEngineLauncher.

### Local testing
To run a new instance of the application. Application canbe viewd at localhost:8181
        $ dev_appserver.py app.yaml --port=8181 --clear_datastore

To run an instance of the application based on the recently run instance (omit clear_datastore switch).
        $ dev_appserver.py app.yaml --port=8181

Datastore storage can be viewed on localhost:8000

### Localhost Testing
Incomplete Unit tests are available. Public pages have simple webpage tests.
        $ python runner.py "location_of_your_Google_Cloud_SDK/google-cloud-sdk"

### TODO

- DB to NDB
- Pagination
- Search keyword
- Implement [GAE Boilerplate] (https://github.com/coto/gae-boilerplate)
- Watch post so users can be notified (auto enable for author with auto-comments disabled?)
- Track searches (log missed searches)
- Sort options: by votes, date
- Better Error Handling
- More Tests


### Bugs

- SignupHandler: errors not ordered in template error summary

