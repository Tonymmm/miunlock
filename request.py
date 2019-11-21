#!/usr/bin/env python3.7
# Python 3.7+ only.

import requests, webbrowser, json, logging, hmac, random, binascii, hashlib, urllib, uuid
import http.cookiejar as cookielib
import hashlib 
from urllib3.util.url import Url
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from strings import STRINGS

class XiaomiError(RuntimeError):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code
class UserError(XiaomiError):
    pass

pad = lambda s: s + (16 - len(s) % 16) * bytes([16 - len(s) % 16])
unpad = lambda s: s[:-s[-1]]
class Auth():
    LOGIN_URL="https://account.xiaomi.com/pass/serviceLogin?sid={}&_json=true&passive=true&hidden=false"
    START="&&&START&&&"
    def login_tui(self, sid):
        self.login()
    def login(self):
        session = requests.Session()
        session.get("https://account.xiaomi.com/pass/serviceLogin?sid=passport&json=false&passive=true&hidden=false&_snsDefault=facebook&_locale=en")
        session.get("https://account.xiaomi.com/pass/js/info?type=notice&_locale=en")
        us = input("Insert xiaomi account user (if you have concern on how it's used please read the source code): ")
        ps = hashlib.md5(input("Insert xiaomi account password (same as above): ").encode("utf-8")).hexdigest().upper()
        loginData = {
            '_json': 'true',
            'callback':     'https://account.xiaomi.com',
            'sid':          'passport',
            'qs':           '%3Fsid%3Dpassport%26json%3Dfalse%26passive%3Dtrue%26hidden%3Dfalse%26_snsDefault%3Dfacebook%26_locale%3Den',
            '_sign':        '2&V1_passport&O3CI2mWi6BiCSNAR7hRK9CatpIw=',
            'serviceParam': "{'checkSafePhone':'false'}",
            'user':         us,
            'hash':         ps,
            'cc':           '+39',
            'log':          '{"title":"dataCenterZone","message":"Singapore"}{"title":"locale","message":"en"}{"title":"env","message":"release"}{"title":"browser","message":{"name":"miNative/1.0","version":0}}{"title":"search","message":"?sid=passport&json=false&passive=true&hidden=false&_snsDefault=facebook&_locale=en"}{"title":"DefaultRegion","message":{"B":"IT","C":"Italy","N":"+39"}}{"title":"outerlinkDone","message":"done"}{"title":"addInputChange","message":"userName"}'
        }
        res = session.post("https://account.xiaomi.com/pass/serviceLoginAuth2", loginData)
        
        data = res.text
        if data[:len(self.START)] != self.START:
            raise UserError("invalid data (missing or invalid &&& section)", 1)
        try:
            data = json.loads(data[len(self.START):])
        except:
            raise XiaomiError("invalid json but valid &&& start, probably internal error or changed format", 2)
        logging.debug(data)
        if data["code"] != 0:
            if data["code"] == 70016:
                raise UserError("Not signed in.", 3)
            else:
                raise XiaomiError("Account server gave unknown code {}, chinese desc is {}".format(data["code"], data["desc"]), 4)
        self.ssecurity = data["ssecurity"]
        self.psecurity = data["psecurity"]
        self.userid = data["userId"]
        self.c_userid = data["cUserId"]
        self.code = data["code"]
        self.nonce = str(data["nonce"]).encode("utf-8")
        self.location = data["location"]
        sign = urllib.parse.quote_plus(b64encode(hashlib.sha1(b"nonce="+str(self.nonce).encode("utf-8")+b"&"+self.ssecurity.encode("utf-8")).digest()))
        response = session.get(self.location + "&clientSign=" + sign)
        self.cookies = session.cookies
        logging.debug("got cookies from auth redir %s", self.cookies)
        if response.status_code == 401:
            raise UserException("Sign in failed, nonce reuse", 4)
        response.raise_for_status()
        logging.debug("auth redir head %s", response.headers)
        logging.debug("auth redir text %s", response.text)
        logging.debug("auth data %s", self.__dict__)
        self.pcid = "wb_" + str(uuid.uuid4())
        return True

class UnlockRequest:
    IV=b"0102030405060708"
    DEFAULT_KEY=bytes.fromhex("327442656f45794a54756e6d57554771376251483241626e306b324e686875724f61714266797843754c56676e3441566a3773776361776535337544556e6f")
    def __init__(self, auth, host, path, params, method="POST"):
        self.auth = auth
        self.host = host
        self.path = path
        self.params = {}
        for k,v in params.items():
            if isinstance(v, str):
                v = v.encode("utf-8")
            elif not isinstance(v, bytes):
                v = b64encode(json.dumps(v).encode("utf-8"))
            if isinstance(k, str):
                k = k.encode("utf-8")
            self.params[k] = v
        self.method = method
        logging.debug(self.params)
        self.cipher = AES.new(b64decode(self.auth.ssecurity), AES.MODE_CBC, iv=self.IV)
    def get_params(self, sep):
        logging.debug(self.method.encode("utf-8")+sep+self.path.encode("utf-8")+sep+b"&".join([k+b"="+v for k,v in self.params.items()]))
        return self.method.encode("utf-8")+sep+self.path.encode("utf-8")+sep+b"&".join([k+b"="+v for k,v in self.params.items()])
    def add_sign(self):
        self.params[b"sign"] = binascii.hexlify(hmac.digest(self.DEFAULT_KEY, self.get_params(b"\n"), "sha1"))
    def _encrypt(self, value):
        return b64encode(AES.new(b64decode(self.auth.ssecurity), AES.MODE_CBC, iv=self.IV).encrypt(pad(value)))
    def encrypt(self):
        for k,v in self.params.items():
            logging.debug(k)
            logging.debug(v)
            self.params[k] = self._encrypt(v)
    def add_signature(self):
        self.params[b"signature"] = b64encode(hashlib.sha1(self.get_params(b"&")+b"&"+self.auth.ssecurity.encode("utf-8")).digest())
    def add_nonce(self):
        r = UnlockRequest(self.auth, self.host, "/api/v2/nonce", {"r":''.join(random.choices(list("abcdefghijklmnopqrstuvwxyz"), k=16)), "sid":"miui_unlocktool_client"}).run()
        logging.debug("nonce is "+r["nonce"])
        self.params[b"nonce"] = r["nonce"].encode("utf-8")
        self.params[b"sid"] = b"miui_unlocktool_client"
    def _decrypt(self, value):
        # Decrypt is only called once, but we can't do decryption after encryption on a cipher object. So remake it. Not too much overhead I hope.
        ret = b64decode(unpad(AES.new(b64decode(self.auth.ssecurity), AES.MODE_CBC, iv=self.IV).decrypt(b64decode(value))))
        logging.debug("query returned %s", ret)
        return ret
    def run(self):
        
        headers = {'clientId': 'MITUNES','User-Agent': 'MITUNES;Windows-6.2/3.5.1030.37','Accept' : '*/*','Content-Type' : 'application/x-www-form-urlencoded'}
        self.session = requests.session()
        self.session.cookies.set_cookie(self.auth.cookies._cookies[".account.xiaomi.com"]["/"]["passToken"])
        self.session.cookies.set_cookie(self.auth.cookies._cookies[".account.xiaomi.com"]["/"]["deviceId"])
        self.session.cookies.set_cookie(self.auth.cookies._cookies[".account.xiaomi.com"]["/"]["userId"]) 
        r1 = self.session.get("https://account.xiaomi.com/pass/serviceLogin?sid=unlockApi&_json=true&passive=true&hidden=false", headers=headers)
        data = r1.text
        if data[:len(self.auth.START)] != self.auth.START:
            raise UserError("invalid data (missing or invalid &&& section)", 1)
        try:
            data = json.loads(data[len(self.auth.START):])
        except:
            raise XiaomiError("invalid json but valid &&& start, probably internal error or changed format", 2)
        ssecurity = data["ssecurity"]
        self.auth.ssecurity = ssecurity
        nonce = data["nonce"]
        location = data["location"]
        sign = urllib.parse.quote_plus(b64encode(hashlib.sha1(b"nonce="+str(nonce).encode("utf-8")+b"&"+ssecurity.encode("utf-8")).digest()))
        response = self.session.get(location.replace("https://unlock.update.miui.com/", "https://unlock.update.intl.miui.com/") + "&clientSign=" + sign, headers=headers)

        self.add_sign()
        self.encrypt()
        self.add_signature()
        logging.debug(self.params)
        data = json.loads(self.send())
        if data.get("code", 0) != 0:
            logging.error("invalid code != 0: %s", data)
            raise XiaomiError(STRINGS["en"].get(data.get("code", -1), STRINGS["en"][-1]).format(**data), data.get("code", 6))
#            raise XiaomiError("Invalid code {}".format(data.get("code", None)), 6)
        return data

    def send(self):         
        response = self.session.request(self.method, Url(scheme="https", host=self.host, path=self.path).url, data=self.params, headers={"User-Agent":"XiaomiPCSuite"})
        logging.debug(response)
        logging.debug(response.headers)
        response.raise_for_status()
        logging.debug(response.text)
        data = self._decrypt(response.text)
        logging.debug("query returned %s", data.decode("utf-8"))
        return data
