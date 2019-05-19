import peeweedbevolve # new; must be imported before models
from flask import Flask, render_template, request
from models import db

app = Flask(__name__)

@app.before_request
def before_request():
   db.connect()

@app.after_request
def after_request(response):
   db.close()
   return response

@app.cli.command() # new
def migrate(): # new 
   db.evolve(ignore_tables={'base_model'}) # new

@app.route("/")
def index():
   return render_template('index.html')

if __name__ == '__main__':
   app.run()

