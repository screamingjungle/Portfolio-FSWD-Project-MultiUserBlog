import unittest
import webapp2
import os
import webtest

from google.appengine.ext import db
from google.appengine.ext import testbed

import main

class MainTest(unittest.TestCase):

    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()

    def tearDown(self):
        self.testbed.deactivate()

    def testIndexPageView(self):
        """Tests that the home page for the application

        The body content should contain the string: Recent Posts
        """
        request = webapp2.Request.blank('/')
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIn('Recent Posts', response.body)

    def testIndexPageViewSidebar(self):
        """Tests that the sidebar on the home page for the application

        The body content should contain the string: Multi-User Blog
        """
        request = webapp2.Request.blank('/')
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIn('Multi-User Blog', response.body)

    def testSignupPageView(self):
        """Tests that the signup page for the application

        The body content should contain the string: <h2>Signup</h2>
        """
        request = webapp2.Request.blank('/signup')
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIn('<h2>Signup</h2>', response.body)

    def testLoginPageViewWithTrailingSlash(self):
        """Tests that the login page for the application

        The body content should contain the string: M<h2>Login</h2>
        """
        request = webapp2.Request.blank('/login/')
        response = request.get_response(main.app)

        self.assertEqual(response.status_int, 200)
        self.assertIn('<h2>Login</h2>', response.body)

class AppTest(unittest.TestCase):
    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()

        app = webapp2.WSGIApplication([('/', main.BlogHandler)])
        self.testapp = webtest.TestApp(app)

    def tearDown(self):
        self.testbed.deactivate()


    # Test the handler.
    def testBlogHandler(self):
        response = self.testapp.get('/')
        self.assertEqual(response.status_int, 200)
        self.assertIn('Recent Posts', response.normal_body)

if __name__ == '__main__':
    unittest.main()