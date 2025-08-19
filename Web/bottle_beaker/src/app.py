# app.py

from bottle import Bottle, request, redirect, static_file, template
from beaker.middleware import SessionMiddleware
from db import init_db, register_user, authenticate_user
import os, re
from html import escape

_filename_strip_re = re.compile(r'[^A-Za-z0-9_.-]')

def secure_filename(filename):
    filename = os.path.basename(filename)
    filename = filename.strip().replace(' ', '_')
    filename = _filename_strip_re.sub('', filename)
    return filename

BASE_DIR = './data'
VIEW_PATH = './views'
SESSION_OPTS = {
    'session.type': 'file',
    'session.data_dir': BASE_DIR,
    'session.auto': True
}

os.makedirs(BASE_DIR, exist_ok=True)
init_db()

app = Bottle()
application = SessionMiddleware(app, SESSION_OPTS)

def get_session(request):
    return request.environ.get('beaker.session')

@app.route('/')
def index():
    session = get_session(request)
    if 'username' not in session:
        return template('login', template_lookup=[VIEW_PATH])

    username = secure_filename(session['username'])
    all_files = os.listdir(BASE_DIR)
    files = [
        f for f in all_files
        if f.endswith(f"-{username}{os.path.splitext(f)[1]}")
    ]

    return template('dashboard', username=username, files=files, template_lookup=[VIEW_PATH])


@app.post('/login')
def login():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if authenticate_user(username, password):
        session = get_session(request)
        session['username'] = username
        session.save()
        redirect('/')
    return "Login failed. <a href='/'>Try again</a>"

@app.post('/register')
def register():
    username = request.forms.get('username')
    password = request.forms.get('password')
    if register_user(username, password):
        return "Registered successfully. <a href='/'>Login</a>"
    else:
        return "Username already exists. <a href='/'>Try again</a>"

@app.post('/logout')
def logout():
    session = get_session(request)
    session.delete()
    redirect('/')

@app.post('/upload')
def upload():
    session = get_session(request)
    if 'username' not in session:
        redirect('/')

    username = secure_filename(session['username'])
    upload = request.files.get('upload')
    if not upload:
        return "No file uploaded."

    original_filename = secure_filename(upload.raw_filename)
    name, ext = os.path.splitext(original_filename)
    final_filename = f"{name}-{username}{ext}"
    save_path = os.path.join(BASE_DIR, final_filename)

    if not os.path.abspath(save_path).startswith(os.path.abspath(BASE_DIR)):
        return "Invalid file path."

    upload.save(save_path)
    redirect('/')

@app.route('/files/<filename:path>')
def serve_file(filename):
    safe_filename = secure_filename(filename)
    return static_file(safe_filename, root=BASE_DIR)


if __name__ == '__main__':
    from bottle import run
    run(app=application, host='0.0.0.0', port=5000)
