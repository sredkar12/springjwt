# springjwt

This project is a basic example of a spring boot based security with JWT authentication . It shows how a resource server is configured to generate a JWT and returned on the first 
  basic authurization call to a controller . The first POST is a call to a controller in which spring passes the Authentication object which has the username and password . It then converts 
  that to a JWT token using all the existing configuration in the class SecurityConfig.
