# Configuration settings for the Flask application
class Config:
    SECRET_KEY = 'shreya'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/parna_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False