import subprocess
import sys
import random
import string
import mariadb

def install_mariadb():
    subprocess.run(["apt", "update"])
    subprocess.run(["apt", "install", "mariadb-server", "-y"])

def random_password(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

try:
    conn = mariadb.connect(user="root")
except mariadb.Error:
    print("Root access failed, enter credentials:")
    user = input("Username: ")
    passwd = input("Password: ")
    try:
        conn = mariadb.connect(user=user, password=passwd)
    except mariadb.Error as e:
        print("Connection failed:", e)
        sys.exit(1)

cursor = conn.cursor()
cursor.execute("SHOW DATABASES LIKE 'openpagingserver'")
if cursor.fetchone():
    overwrite = input("Database exists. Overwrite? (y/n): ")
    if overwrite.lower() != "y":
        print("Exiting.")
        sys.exit(0)
    cursor.execute("DROP DATABASE openpagingserver")

cursor.execute("CREATE DATABASE openpagingserver")
cursor.execute("USE openpagingserver")

password = random_password()
cursor.execute(f"CREATE USER 'openpagingserver'@'localhost' IDENTIFIED BY '{password}'")
cursor.execute("GRANT ALL PRIVILEGES ON openpagingserver.* TO 'openpagingserver'@'localhost'")
cursor.execute("FLUSH PRIVILEGES")

cursor.execute("""
CREATE TABLE messages (
    type ENUM('liveaudio','liveaudio+text','text','text+audio','audio','record','record+text','text+audio+live'),
    messageid INT,
    name VARCHAR(255),
    shortmessage TEXT,
    longmessage TEXT,
    audio VARCHAR(255),
    image VARCHAR(255) DEFAULT '',
    color VARCHAR(7),
    icon VARCHAR(255) DEFAULT ''
)
""")

cursor.execute("""
INSERT INTO messages (type,messageid,name,shortmessage,longmessage,audio,color,icon)
VALUES (
'text+audio',1,'Testing Message',
'This is a test of Open Paging Server!',
'This is a test of the Open Paging Server open-source MNS system. No action is required.',
'openpagingservertest.wav','#00ff84','')
""")

conn.commit()
conn.close()
print("Database created. User: openpagingserver Password:", password)
