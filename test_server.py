from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return 'Flask is working!'

if __name__ == '__main__':
    print('Starting test server on http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=True)
