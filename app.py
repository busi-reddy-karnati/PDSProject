import sqlite3

from flask import Flask,render_template,url_for
from flask_mysqldb import MySQL
app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pds_project'
my_sql = MySQL(app)


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


# This if for the landing page
@app.route('/')
def hello_world():
    connection = get_db_connection()
    posts = connection.execute('SELECT * from test').fetchall()
    connection.close()
    return render_template('index.html', data=posts)
#     It knows to look at templates


if __name__ == '__main__':
    app.run(debug=True)
