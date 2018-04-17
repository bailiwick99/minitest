#Minitest
##A simple app with some vulnerabilities

The goal is to have a very small app to make scans fast while including more than one vulnerability and a potential fix.

Recommended use:
Maven phases for build:
clean compile test package source:jar

Maven phases for interactive test:
tomcat7:run

Assuming the defaults for running with the Tomcat plugin, here are some test URLs:

Happy path
http://localhost:8080/minitest/login?userId=1

Increasing Trouble
http://localhost:8081/minitest/login?userId=-1

http://localhost:8081/minitest/login?userId='

http://localhost:8081/minitest/login?userId=1%20OR%201=1

http://localhost:8081/minitest/login?userId=</h1>%20<br/><img%20src="http://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"/>
