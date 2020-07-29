# authentication-whisperapp

Login and register form with authentication. Users can login with Google, Facebook or with their email. User information is saved into MongoDB and user password is hashed, salted and authenticated with [passport](http://www.passportjs.org/)
to add cookies and sessions. When the user logs out, session cookies are destroyed.


