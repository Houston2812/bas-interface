# Interface of BAS
This is the user interface of Breach and Attack Simulation tool.  
The interface is a monolith web application used to perform scans of the Web Application Firewalls and check the results.  

## Tech stack
The application is written using following technologies:
* Front end - Bulma.js in combination with Jinja2 templating
* Back end - Python Flask framework
* Databse - SQlite (in order to keep the infrastructure simple. However, the plan is to move it to the PosgreSQL)

## Flow
To start a scan following actions should be performed:
* Register and log in to the application
* Run the sensor on the local machine - Refer to the Readme of BAS Sensor
* Create *new scanner* on the user interface 
* Obtain *authentication key* from the user interface 
* Run the scanner on the same subnet and provide authentication key - Refer to the Readme of BAS Scanner
* Check the status of scanner (Connected or not Connected)
* Add scan by providing following information
    * Scan category : __Directory Traversal__, __SQL Injection__, __XSS__ 
    * Scan type: __Basic__, __Short__, __Full__
    * Scan speed: __Normal__, __Slow__, __Fast__
* View the results of the scan from user interface
      
## Set-up
To set up the application perform following operations:  
* Pull the project from the git
* Create virtual environment:
    * python3 -m venv venv
* Installe all requirements
    * pip install -r requirements.txt
* Run following commands (modify):
    * export FLASK_APP=flaskr
    * flask init_db
    * python run.py