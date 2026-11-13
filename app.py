from flask import Flask, request

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    return f"Results for: {query}"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return "invalid credentials"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
