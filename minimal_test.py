# minimal_test.py
from flask import Flask
import time

app = Flask(__name__)

@app.route('/')
def home():
    return '<h1>CyberAI Test Server</h1><p>Server is running!</p>'

@app.route('/api/test')
def test():
    return {'status': 'ok'}

if __name__ == '__main__':
    print("Starting test server...")
    print("Server will run until you press Ctrl+C")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)