import requests
import time
import json
print("""  SPAMER By Ahmed V1 """)
username = input("[+] Enter username:")
pasword = input("[+] Enter Pasword:")
Target = input("[+] Enter Target:")
print("""[+] Mode:
[1] - Spam
""")
mode = input(" Presse  Number 1 :")
print("i well Fuck ",Target )
time.sleep(5)
print(" Wait For A Few Sec Please  ")
time.sleep(2)

def exit():
  print('Fuck You Wrong Number ')
  print("[x] Enter To exit")
  ssssss = input("")
  out2 = exit()
  print("[x] Enter To exit")
  sssss = input("")
  out = exit()

def spam():
    spam_data = {"source_name":"","reason_id":"1","frx_context":""}
    error_spam = 0
    done_spam = 0
    while True:
        url_spam = "https://www.instagram.com/users/"+idinsta+"/report/"
        do = r.post(url_spam,data=spam_data)
        time.sleep(3)
        if do.text.find("Your reports help keep our community free of spam.") >=0:
            done_spam +=1
            print("[+] Done Spam:",done_spam ,Target)
        else:
            error_spam +=1
            print("[-] Error Spam:",error_spam ,Target)
            time.sleep(20)

def self():
    url_self = "https://www.instagram.com/users/"+idinsta+"/report/inappropriate"
    self_data = {"source_name":"","reason_id":"2","frx_context":""}
    error_self +=1
    done_self +=1
    while True:
        do = r.post(url_self,data=self_data)
        time.sleep(2)
        if do.text.find("We take your reports seriously. We look into every issue, and take action when people violate our Community Guidelines") >=0:
            done_self +=1
            print("[+] Done Self injury:",done_self ,Target)
        else:
            error_self +=1
            print("[-] Error Self injury:",error_self ,Target)
            time.sleep(20)
r = requests.session()
url = "https://www.instagram.com/accounts/login/ajax/"
headers = {
"accept":"*/*",
"accept-encoding":"gzip, deflate,br",
"accept-language": "ar,en-US;q=0.9,en;q=0.8",
"content-length": "279",
"content-type": "application/x-www-form-urlencoded",
"origin": "https://www.instagram.com",
"referer": "https://www.instagram.com/",
"sec-fetch-dest":"empty",
"sec-fetch-site":"same-origin",
"user-agent":"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36",
"x-csrftoken": "lih2ypMfhzdqwMbm5jIILqxZDj4zLeCW",
"x-ig-app-id": "936619743392459",
"x-ig-www-claim": "hmac.AR1_p9SjMFQF73bcZgzygDgxb9yBZUn83e69xoDD2qpSdmtW",
"x-instagram-ajax":"901e37113a69",
"x-requested-with":"XMLHttpRequest"
}
data = {"username":username,"enc_password":"#PWD_INSTAGRAM_BROWSER:0:1589682409:"+pasword,"queryParams":"{}","optIntoOneTap":"false"}
login = r.post(url,headers=headers,data=data,allow_redirects=True)
if login.text.find("userId") >= 0 :
    print('[√] Done Login:',username)
    s = requests.get("https://instagram.com/"+Target+"/?__a=1")
    idinsta =str(s.json()["graphql"]["user"]["id"])
    print("[√] id Target:",idinsta)
    r.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
    if mode == "1":
        spam()
    if mode == "2":
        exit()
 

else:
    print('[-] Error Password or secure account')
    print("[x] Enter To exit")
    ssssss = input("")
    out2 = exit()
print("[x] Enter To exit")
sssss = input("")
out = exit()
