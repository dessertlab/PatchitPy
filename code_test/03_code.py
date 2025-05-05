from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, Flask for Academic Purposes!'

if __name__ == '__main__':
    app.run(debug=True)
