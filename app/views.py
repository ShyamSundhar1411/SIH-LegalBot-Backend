from app import app,db #noqa


@app.route('/')
def home():
    return "Hello World"
