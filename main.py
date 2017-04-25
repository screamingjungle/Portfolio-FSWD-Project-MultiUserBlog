#
# main.py -- implementation of a multi-user blog.
#
import os
import jinja2
import webapp2

import re
import hashlib
import hmac
import random
import string
import urllib
import yaml

import logging

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
                               autoescape = True)

# Global constants
DEBUG = os.environ.get('DEBUG', False)
DEFAULT_BLOG_NAME = os.environ.get('DEFAULT_BLOG_NAME', 'default_blog')
ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', 10))
POSTCHAR_CUTOFF_MAIN_PAGE = int(os.environ.get('POSTCHAR_CUTOFF_MAIN_PAGE', 20))
SECRET = os.environ.get('SECRET', 'UdacityProject3SecretKey')

ERRLIST = {
                "username_invalid": "That's not a valid username.",
                "username_exists": "That user already exists.",
                "password_invalid": "This password isn't valid.",
                "password_mismatch": "Your passwords don't match.",
                "email_invalid": "Your email isn't valid.",
                "login_invalid": "Login failed.",
                "login_password_invalid": "Password incorrect.",

                "CANT_DELETE_POST": "Only author of post can delete it.",
                "CANT_EDIT_POST": "Only author of post can edit it.",
                "CANT_LIKE_OWN_POST": "Author of a post can't like it.",
                "CANT_LIKE_SAME_POST": "You have already liked this post.",
                "CANT_DISLIKE_OWN_POST": "Author of a post can't dislike it.",
                "CANT_DISLIKE_SAME_POST": "You have already disliked this post.",
                "CANT_COMMENT_OWN_POST": "Can't comment on your own post.",
                "CANT_MODIFY_OWN_POST": "Can't modify your own post.",

                "error_unknown": "Oops, something went wrong.",
                "no_post_found": "No blog entry found",
                "no_comment_found": "No comment entry found",
          }

REGEXLIST = {
                "username_regex": re.compile(r"^[a-zA-Z0-9_-]{3,20}$"),
                "password_regex": re.compile(r"^.{3,20}$"),
                "email_regex": re.compile(r"^[\S]+@[\S]+.[\S]+$"),
                "cookie_regex": re.compile(r'.+=;\s*Path=/'),
            }

def blog_key(name=DEFAULT_BLOG_NAME):
    """Constructs a Datastore key for a BlogEntry entity.
    
    This helps in showing recently updated info on screen. 
    Without stale info is seen shortly after an update.
    """
    return db.Key.from_path('blogs', name)

class User(db.Model):
    ''' User Account datastore model.

        Attributes:
            username: A unique user name.
            pwd_hash: A hash of the username + password + salt.
            email:    User's email address.
    '''
    username = db.StringProperty(required=True)
    pwd_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=blog_key())

class BlogEntry(db.Model):
    ''' Blog post datastore model.

        Includes totals for likes, dislikes to decrease datastore queries to 
        Likes model (e.g. on blog index pages with many blog scores).

        Attributes:
            subject:  Subject of the post.
            content:  Content of the post.
            tags:     keywords to describe comment
            created:  Automatically generated DateTime when the post was submitted.
            last_modified:  Automatically generated DateTime when the post was updated.
            author:   User name of the author of the post.
            author_id:   User id of the author of the post.
            close_comments:  no new comments allowed
            hide_comments:   do not show comments to the public
            auth_comments:   if True, no need to authorise each comment.
            sum_comments: Number of comments submitted for this post.
            sum_unauth_comments: Number of unauthorised comments submitted for this post.
            sum_likes:    Number of likes submitted for this post.
            sum_dislikes: Number of dislikes submitted for this post.
    '''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    tags = db.StringListProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    author = db.StringProperty(required=True)
    author_id = db.IntegerProperty(required=True)

    close_comments = db.BooleanProperty(default=False)
    hide_comments = db.BooleanProperty(default=False)
    auth_comments = db.BooleanProperty(default=False)

    sum_comments = db.IntegerProperty(default=0)
    sum_unauth_comments = db.IntegerProperty(default=0)
    sum_likes = db.IntegerProperty(default=0)
    sum_dislikes = db.IntegerProperty(default=0)

    @classmethod
    def by_id(cls, pid):
        return BlogEntry.get_by_id(int(pid), parent=blog_key())

    def add_comment(self, userName, uid, comment):
        k = self.key()
        new_comment = Comment(
            parent=blog_key(),
            commenter_username=userName,
            commenter_userid=uid,
            comment=comment,
            authorised = self.auth_comments,
            post_id = k.id()
        )
        c = new_comment.put()

        if self.auth_comments == True:
            self.sum_comments += 1
        else:
            self.sum_unauth_comments += 1

        k = self.put()
        return k.id()

    def get_comments(self, cid=None):
        if cid:
            q = Comment.by_id(cid)
        else:
            q = Comment.all()
            q.ancestor(blog_key())
            q.fetch(ITEMS_PER_PAGE)
        return q

class Comment(db.Model):
    ''' Comments datastore model.

        Includes totals for likes, dislikes to decrease datastore calls to 
        Likes model (e.g. on blog entry page with many comments).

        Attributes:
            commenter_username: User name of the user who submitted the comment.
            commenter_userid:   ID of author.
            authorised:         can comment be shown to public
            post_id:   Unique ID number of the post that has been commented on.
            comment:   Content of the comment.
            sum_likes:    Number of likes submitted for this post.
            sum_dislikes: Number of dislikes submitted for this post.
            created:   Automatically generated DateTime when the comment was submitted.
    '''
    commenter_username = db.StringProperty(required=True)
    commenter_userid = db.IntegerProperty(required=True)
    authorised = db.BooleanProperty(default=False)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    sum_likes = db.IntegerProperty(default=0)
    sum_dislikes = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(int(pid), parent=blog_key())

class Likes(db.Model):
    ''' Voting (Like/Dislike) dayastore model.

        Attributes:
            liker_username:  User name of the user who submitted the like.
            liker_userid:    User ID of the user who submitted the like.
            post_id:         Unique ID number of the post that has been liked.
            post_type:       Post or Comment
            score:           +1 for like|upvote; -1 for dislike|downvote
            created:         Automatically generated DateTime.
            last_modified:   Automatically generated DateTime when the post 
                             was updated.
    '''
    liker_username = db.StringProperty(required=True)
    liker_userid = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    post_type = db.StringProperty(required=True)
    score = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, pid):
        return Likes.get_by_id(int(pid), parent=blog_key())


class Handler(webapp2.RequestHandler):
    ''' This webapp2.RequestHandler class serves as the base Handler class 
        for classes in this application.
        
        Included are methods for:
        - Datastore Queries
        - Error Handling
        - Rendering
        - Security
        - Validation
    '''

    # RENDERING
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template, None, {'DEBUG': DEBUG})
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # VALIDATIONS
    def valid_username(self, username):
        return REGEXLIST["username_regex"].match(username)

    def valid_password(self, password):
        return REGEXLIST["password_regex"].match(password)

    def valid_email(self, email):
        valid = True
        if email:
            valid = REGEXLIST["password_regex"].match(email)
        return valid

    def valid_pw(self, name, pw, h):
        salt = h.split(',')[1]
        newpw = self.make_pw_hash(name, pw, salt)
        return h == newpw

    def validate_password(self, name, pwd, pwd_hash):
        return self.valid_pw(name, pwd, pwd_hash)

    def clean_tags(self, kw_str=None, return_string=False):
        # returns a List for input into BlogEntry datastore model
        if kw_str:
            l = re.split(r'[\n.()!,; ""/]', kw_str)
            res = [x for x in l if len(x) > 0]

            if return_string:
                return ",".join(res)
            else:
                return res

        return []

    def get_vote_score(self, vote=None):
        if re.match("like|upvote", vote):
            return 1
        elif re.match("dislike|downvote", vote):
            return -1
        return 0


    # ERROR HANDLING
    def error_hard(self, message = "Unknown error occured", status=404):
        logging.exception(message)
        self.error(status)

    # QUERIES
    def comments_by_pid(self, post_id, allcomments=False):
        q = Comment.all()
        q.filter("post_id =", int(post_id))
        if not allcomments:
            q.filter("authorised =", True)
        q.ancestor(blog_key())
        q.order("-sum_likes")
        q.order("-sum_dislikes")
        q.order("-created")
        return q.fetch(ITEMS_PER_PAGE)

    def post_scores_by_user(self, pid=None):
        results = {'likes':[], 'dislikes':[]}

        if not self.loggedIn:
            return results

        q = Likes.all()
        if pid:
            q.filter("post_id =", int(pid))
        elif self.uid:
            q.filter("liker_userid =", self.uid)
        q.ancestor(blog_key())
        q.order("-created")
        r = q.fetch(ITEMS_PER_PAGE)

        for l in r:
            if l.score > 0:
                results['likes'].append(l.post_id)
            elif l.score < 0:
                results['dislikes'].append(l.post_id)

        return results

    def has_user_liked(self, userid=None, pid=None, posttype="post"):
        if userid and pid:
          q = Likes.all()
          q.filter('liker_userid =', int(userid))
          q.filter('post_type =', str(posttype))
          q.filter('post_id =', int(pid))
          q.ancestor(blog_key())
          l = q.fetch(1)
          if l:
              return l[0]
        return None

    # SECURITY
    def validate_user(self):
        cookie_val = self.read_secure_cookie("user_id")

        if cookie_val:
            ID = int(cookie_val)
            acc = User.by_id(ID)

            if acc:
                return True, acc.username, ID

        return False, None, None

    def hash_str(self, s):
        return hmac.new(SECRET, str(s)).hexdigest()

    def make_salt(self):
        return ''.join(random.choice(string.letters) for i in range(0, 5))

    def make_pw_hash(self, name, pw, salt=None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name+pw+salt).hexdigest()
        return "%s,%s" % (h, salt)

    def register_user(self, name, pwd, eml):
        h = self.make_pw_hash(name, pwd)

        a = User(parent=blog_key(),
                     username=name,
                     pwd_hash=h,
                     email=eml)
        k = a.put()
        self.set_user_cookie(a)
        return k

    def set_user_cookie(self, a):
        self.set_secure_cookie('user_id', a.key().id())

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """read the cookie"""
        cookie_val = self.request.cookies.get(name)
        if self.check_secure_val(cookie_val):
            return cookie_val.split('|')[0]

    def make_secure_val(self, val):
        """create secure cookie values"""
        return '%s|%s' % (str(val), self.hash_str(val))

    def check_secure_val(self, secure_val):
        """check secure cookie values"""
        if secure_val:
          val = secure_val.split('|')[0]
          return secure_val == self.make_secure_val(val)

    def initialize(self, *a, **kw):
        """get the user from secure cookie when we initialize"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.loggedIn, self.userName, self.uid = self.validate_user()

class BlogHandler(Handler):

    def initialize(self, *a, **kw):
        """auto redirect if not logged in"""
        Handler.initialize(self, *a, **kw)

        if not (self.loggedIn and self.userName and self.uid):
            self.logout()
            self.redirect("/login")

class SignupHandler(Handler):
    ''' User User registration requires the following:
        username: unique
        password: with matching password form field
        email: optional
    '''
    def get(self):
        self.render("signup.html",
                    errors = {},
                    email_value = "",
                    loggedIn = self.loggedIn,
                    userName = self.userName)

    def post(self):
        exists = False
        name = self.request.get("username")
        pwd = self.request.get("password")
        ver = self.request.get("verify")
        eml = self.request.get("email")

        errors = {}

        if not self.valid_username(name):
            errors["username_invalid"] = ERRLIST["username_invalid"]
        if not self.valid_password(pwd):
            errors["password_invalid"] = ERRLIST["password_invalid"]
        if not pwd == ver:
            errors["password_mismatch"] = ERRLIST["password_mismatch"]
        if not self.valid_email(eml):
            errors["email_invalid"] = ERRLIST["email_invalid"]

        if not errors:
            # Check if user is already in db
            q = User.all()
            q.filter("username =", name)
            q.ancestor(blog_key())
            r = q.fetch(1)

            if not r:
                k = self.register_user(name, pwd, eml)
                self.redirect("/")
                return
            else:
                errors["username_exists"] = ERRLIST["username_exists"]

        self.render(
            "signup.html",
            user_value = name,
            email_value = eml,
            errors = errors,
        )


class LoginHandler(Handler):
    ''' This class handles the request for the Login page.
    '''
    def get(self):
        self.render(
            "login.html",
            login_error = ""
        )

    def post(self):
        error = ""
        name = self.request.get("username")
        passwd = self.request.get("password")

        q = User.all()
        q.filter('username =', name)
        q.ancestor(blog_key())
        r = q.fetch(1)

        if r and r[0]:
            if self.validate_password(name, passwd, r[0].pwd_hash):
                self.set_user_cookie(r[0])
                self.redirect("/")
                return
            else:
                error = ERRLIST["login_password_invalid"]
        else:
            error = ERRLIST["login_invalid"]

        self.render(
            "login.html",
            login_error = error,
            userName = name,
        )


class LogoutHandler(Handler):
    ''' This class handles the request for the Logout page.
    '''
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/")


class DeleteBlogHandler(Handler):
    ''' This class handles the request to delete a post.
    '''
    def get(self, ID):
        if self.userName:
            be = BlogEntry.by_id(ID)

            if be:
                if be.author == self.userName:
                    be.delete()
                    self.redirect("/")
                    return
                else:
                    self.redirect("/error/CANT_DELETE_POST")
                    return
            else:
                self.error_hard(ERRLIST['no_post_found'])
        else:
            self.redirect("/login")


class LikeBlogHandler(BlogHandler):
    ''' This class handles the request to like a post.
    '''
    def get(self, ID, vote):
        score = self.get_vote_score(vote)
        be = BlogEntry.by_id(ID)

        if not be:
            self.error_hard(ERRLIST['no_post_found'])

        if be.author != self.userName:
            redir = int(ID)

            # Check if this user has already liked this post.
            like = self.has_user_liked(self.uid, ID, "post")

            if not like:
                logging.info("LikeBlogHandler count = 0, ID = %s, score = %d" 
                      % (ID, score))
                le = Likes( parent=blog_key(),
                            liker_username = self.userName,
                            liker_userid = self.uid,
                            post_id = int(ID),
                            post_type = "post",
                            score = score)
                le.put()

                be.sum_likes += score
                k = be.put()

                self.redirect("/blog/%d?view=me" % k.id())
                return

            else:
                if not like.score:
                    like.score = 0

                if score > int(like.score):  # Dislike to Like
                    logging.info("UPDATING LIKE %d, score = %d  like = %d" 
                        % (like.key().id(), score, like.score))

                    be.sum_dislikes -= 1
                    be.sum_likes += 1
                    k = be.put()

                    like.score = score
                    like.put()

                    self.redirect("/blog/%d" % k.id())
                    return

                elif score < int(like.score):  # Like to Dislike
                    logging.warning("UPDATING DISLIKE %d, score = %d  like = %d" 
                        % (like.key().id(), score, like.score))

                    be.sum_dislikes += 1
                    be.sum_likes -= 1
                    k = be.put()

                    like.score = score
                    like.put()

                    self.redirect("/blog/%d" % k.id())
                    return

                else:
                    logging.warning("NO LIKE CHANGE %d, score = %d  like = %d" 
                        % (like.key().id(), score, like.score))

            self.redirect("/blog/%d?view=me" % redir)
            return

        else:
            self.redirect("/error/CANT_LIKE_OWN_POST")


class LikeCommentHandler(Handler):
    ''' This class handles the request to like a comment.
        ID:     comment ID
        vote:   like, dislike, upvote, downvote
    '''
    def get(self, ID, vote):
        score = self.get_vote_score(vote)
        c = Comment.by_id(ID)

        if not c:
            self.error_hard(ERRLIST['no_comment_found'])
            return

        redir = int(c.post_id)

        # Check if this user has already liked this comment.
        like = self.has_user_liked(self.uid, ID, "comment")
        '''
        q = Likes.all()
        q.filter('liker_userid =', self.uid)
        q.filter('post_type =', "comment")
        q.filter('post_id =', int(ID))
        q.ancestor(blog_key())
        like = q.fetch(1)
        '''

        if not like:
            logging.warning("LikeCommentHandler new like, ID = %s, score = %d" % (ID, score))

            le = Likes(
                parent=blog_key(),
                liker_username = self.userName,
                liker_userid = self.uid,
                post_id = int(ID),
                post_type = "comment",
                score = score)
            le.put()

            c.sum_likes += score
            k = c.put()
        else:
            if not like.score:
                like.score = 0

            if score > int(like.score):  # Dislike to Like
                logging.info("UPDATING LIKE %d, score = %d  like = %d" 
                    % (like.key().id(), score, like.score))

                c.sum_dislikes -= 1
                c.sum_likes += 1
                k = c.put()

                like.score = score
                like.put()

            elif score < int(like.score):  # Like to Dislike
                logging.info("UPDATING DISLIKE %d, score = %d  like = %d" 
                    % (like.key().id(), score, like.score))

                c.sum_dislikes += 1
                c.sum_likes -= 1
                k = c.put()

                like.score = score
                like.put()

            else:
                logging.info("NO LIKE CHANGE %d, score = %d  like = %d" 
                    % (like.key().id(), score, like.score))

        self.redirect("/blog/%d?view=me" % redir)
        return


class AuthoriseCommentHandler(Handler):

    def get(self, CID):
        c = Comment.by_id(CID)

        if c:
            be = BlogEntry.by_id(int(c.post_id))

            if be and self.userName == be.author:
                logging.info("AuthoriseCommentHandler: authorising comment %s" % CID)

                c.authorised = True
                ck = c.put()

                if ck:
                    be.sum_comments += 1
                    be.sum_unauth_comments -= 1
                    k = be.put()

                    self.redirect("/blog/%d?view=me" % k.id())
                    return

            else:
                logging.warning("NOT authorising comment %s: not author" % (CID))

        else:
            logging.warning("NOT authorising comment %s" % (CID))

        if self.request.referer:
            self.redirect(self.request.referer)
        else:
            self.redirect('/')


class DeleteCommentHandler(Handler):

    def get(self, CID):
        c = Comment.by_id(CID)

        if c:
            be = BlogEntry.by_id(c.post_id)

            if be and (self.userName == c.commenter_userid or self.userName == be.author):

                logging.info("deleting comment %s '%s'" % (CID, c.comment))

                if c.authorised:
                    be.sum_comments -= 1
                else:
                    be.sum_unauth_comments -= 1

                k = be.put()

                c.delete()

                self.redirect("/blog/%d?view=me" % k.id())
                return

            else:
                logging.warning("NOT deleting comment %s: not commenter or author" % (CID))

        else:
            logging.warning("NOT deleting comment %s: unknown comment" % (CID))

        if self.request.referer:
            self.redirect(self.request.referer)
        else:
            self.redirect('/')


class ErrorHandler(Handler):
    ''' This class handles requests for the error page.
    '''
    def get(self, ErrNo):

        try:
            errorMessage = ERRLIST[ErrNo]
            self.render(
                "error.html",
                error = errorMessage
            )
            return
        except:
            self.error_hard(ERRLIST['error_unknown'], 500)


class BlogEntryHandler(Handler):
    ''' This class handles the request for a blog post page.
    '''
    def get(self, ID=0, error=None):
        if self.loggedIn:
            editable = False
            allcomments = False

            if int(ID) > 0:
                be = BlogEntry.by_id(ID)

                if be:
                    if be.author == self.userName:
                        allcomments = True
                        if not self.request.get('view'):
                            editable = True

                    user_comments = self.comments_by_pid(ID, allcomments)
                    r = self.post_scores_by_user(ID)

                    self.render(
                        "blog_entry.html",
                        userName = self.userName,
                        loggedIn = self.loggedIn,
                        entry = be,
                        error = self.request.get("error"),
                        edit = editable,
                        score = r,
                        comments = user_comments
                    )
                else:
                    logging.warning("Blog Entry %s NOT FOUND" % str(ID))

                    self.error_hard(ERRLIST['no_post_found'])
                    return

            # new post
            else:
                self.render(
                    "edit_post.html",
                    entry = '',
                    error = error,
                    userName = self.userName,
                    loggedIn = self.loggedIn
                )

            return

        else: 
            # public view - static cacheable content
            be = BlogEntry.by_id(int(ID))

            if be:
              user_comments = self.comments_by_pid(ID)
              self.render(
                  "blog_publicview.html",
                  loggedIn = self.loggedIn,
                  entry=be,
                  comments = user_comments
              )
            else:
                self.error_hard(ERRLIST['no_post_found'])
                return

    def post(self, ID):
        comment = self.request.get("comment")
        subject = self.request.get("subject")
        content = self.request.get("content")

        error = self.request.get("error")

        if comment:
            be = BlogEntry.by_id(int(ID))
            k = be.add_comment(self.userName, self.uid, comment)

            if k:
                self.redirect("/blog/%d?view=me" % k)
            return

        elif subject and content:

            tags = self.clean_tags(self.request.get("tags"))
            closecomments = self.request.get("closecomments") == "1"
            hidecomments = self.request.get("hidecomments") == "1"
            authcomments = self.request.get("authcomments") == "1"

            if int(ID) > 0:
                be = BlogEntry.by_id(int(ID))
                be.subject = subject
                be.content = content
                be.tags = tags
                be.close_comments = closecomments
                be.hide_comments = hidecomments
                be.auth_comments = authcomments
                k = be.put()

                self.redirect("/blog/%d?view=me" % k.id())
                return
            else:
                be = BlogEntry(
                    parent = blog_key(),
                    author = self.userName,
                    author_id = self.uid,
                    subject = subject,
                    content = content,
                    tags = tags,
                    error = error,
                    close_comments = closecomments,
                    hide_comments = hidecomments,
                    auth_comments = authcomments
                )
                k = be.put()

                self.redirect("/blog/%d?view=me" % k.id())
                return
        else:
            if self.request.get("submitcomment"):
                error = "comment required!"
                logging.warning("ERROR: %s REDIRECT to blog entry %s" % (error, ID))
                self.redirect("/blog/%s?view=1&error=%s" % (ID, urllib.quote_plus(error)))
            else:
                error = "subject and content required!"
                logging.warning("ERROR: %s REDIRECT to blog entry %s" % (error, ID))
                self.redirect("/blog/%s?error=%s" % (ID, urllib.quote_plus(error)))


class SearchEntryHandler(Handler):
    ''' This class handles the search request for tags and authors.
    
        Keyword search is not yet supported, only fulltext on BlogEntry.tags and BlogEntry.author
    '''
    def get(self, srch_kw=None):
        tag = self.request.get('tag')
        author = self.request.get('author')

        if tag or author: # cannot search LIKE
            q = BlogEntry.all()
            if author:
                q.filter("author =", author)

            if tag:
                q.filter("tags", self.clean_tags(tag, True))
            q.ancestor(blog_key())
            #q.order("-sum_likes")
            #q.order("-sum_dislikes")
            q.order("-created")
            entries = q.fetch(ITEMS_PER_PAGE)

            r = self.post_scores_by_user()

            self.render(
                "blog.html",
                userName = self.userName,
                loggedIn = self.loggedIn,
                entries = entries,
                score = r,
                trunc = POSTCHAR_CUTOFF_MAIN_PAGE
            )

        else:
            #show empty search form
            logging.warning("SearchEntryHandler NOTHING TO SHOW")
            return


class BlogHandler(Handler):
    ''' This class handles the request for the blog home page.
    '''
    def get(self):
        q = BlogEntry.all()
        #q.order("-sum_likes")
        #q.order("-sum_dislikes")
        q.ancestor(blog_key())
        q.order("-created")
        entries = q.fetch(ITEMS_PER_PAGE)

        r = self.post_scores_by_user()

        self.render(
            "blog.html",
            userName = self.userName,
            loggedIn = self.loggedIn,
            entries = entries,
            score = r,
            trunc = POSTCHAR_CUTOFF_MAIN_PAGE
        )

app = webapp2.WSGIApplication([
    ('/', BlogHandler),

    ('/blog/(\d+)/?', BlogEntryHandler),
    ('/blog/?', BlogEntryHandler),
    ('/blog/(\d+)/delete/?', DeleteBlogHandler),

    ('/comment/(\d+)/delete/?', DeleteCommentHandler),
    ('/comment/(\d+)/authorise/?', AuthoriseCommentHandler),

    ('/comment/(\d+)/(like)/?', LikeCommentHandler),
    ('/comment/(\d+)/(upvote)/?', LikeCommentHandler),
    ('/comment/(\d+)/(dislike)/?', LikeCommentHandler),
    ('/comment/(\d+)/(downvote)/?', LikeCommentHandler),

    ('/blog/(\d+)/(like)/?', LikeBlogHandler),
    ('/blog/(\d+)/(upvote)/?', LikeBlogHandler),
    ('/blog/(\d+)/(dislike)/?', LikeBlogHandler),
    ('/blog/(\d+)/(downvote)/?', LikeBlogHandler),

    ('/search/?', SearchEntryHandler),
    ('/search/(\s+)', SearchEntryHandler),

    ('/login/?', LoginHandler),
    ('/signup/?', SignupHandler),
    ('/logout/?', LogoutHandler),

    ('/error/(\s*)', ErrorHandler),
], debug=True)
