import re
import hmac
import hashlib
import base64
import binascii
import json


from loguru import logger
from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response
from typing import Optional

import os
from dotenv import load_dotenv


dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

app = FastAPI()


users = {
    "one@mail.ru" : {
        "name": "Lexa",
        "password": "92f24001e40017ad805a117a4e7990443e273b914be8e7fd4833cc2500406955",
        "balance": 1234567
    },

    "two@mail.ru" : {
        "name": "Paxa",
        "password": "e594b9a7148cf88a4a45dff4c71885277e7d61eca975c6a6cda035ec096f19cf",
        "balance": 765432
    },
}

#add autorization form SECRET_KEY and PASSWORD_SALT
SECRET_KEY = os.environ['SECRET_KEY']
PASSWORD_SALT = os.environ['PASSWORD_SALT']


#data verification check
def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password']
    return  password_hash == stored_password_hash


#data signature
def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

#getting username from signed string
def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    if "." not in username_signed:
        return None
    username_base64, sign = username_signed.split(".")
    try:
        username = base64.b64decode(username_base64.encode(), validate=True).decode()
    except binascii.Error:
        return None
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username
    else:
        return None


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("./templates/login.html", "r") as f:
        login_page = f.read()
    if username is None:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Hey, {users[valid_username]['name']}", media_type="text/html")


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    print(data)
    username = data['username']
    password = data['password']

    user = users.get(username)

    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")
    response = Response(json.dumps({
                        "success": True,
                        "message" : f"Ваше имя {user['name']} <br> Ваш пароль {password}<br> Ваш баланс {user['balance']}"}),
                        media_type="application/json")
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)

    return response


@app.get("/unify_phone_from_cookies")
def unify_phone_from_json(phone: Optional[str] = Cookie(default=None)):
    
    number_phone = phone
    
    digits = ''.join(re.findall(r'\d+', number_phone))
    digits = re.sub(r'^7', '8', digits)
    if digits[0] == '9':
        digits = '8'+digits
    list_number = ['7', '8', '9']
    if digits[0] not in list_number or len(digits)>11:
        logger.info("Run first condition")
        return digits
    else:
        return Response(f"{digits[0]} ({digits[1:4]}) {digits[4:7]}-{digits[7:9]}-{digits[9:11]}", media_type="application/json")
    
