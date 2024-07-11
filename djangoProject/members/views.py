from django.http import JsonResponse
from django.http import HttpResponse
from rest_framework.decorators import api_view

import datetime
import json
import re
import bcrypt
import pytz
import traceback

from .models import Members

from utils import jwt as def_jwt
from utils import jwt_auth as def_jwt_auth
from utils.jwt_auth import check_access_jwt_decorator
from utils.error_info import error_info



@api_view(['GET', 'POST', 'PUT', 'DELETE'])
def signup_views(request):
    if request.method == 'GET':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)
    elif request.method == 'POST':
        return signup(request)
    elif request.method == 'PUT':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)
    elif request.method == 'DELETE':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@check_access_jwt_decorator
def members_views(request):
    if request.method == 'GET':
        return get_member(request)
    elif request.method == 'POST':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return signup(request)
    elif request.method == 'PUT':
        return update_member(request)
    elif request.method == 'DELETE':
        return delete_member(request)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
def user_password(request):
    if request.method == 'GET':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)
    elif request.method == 'POST':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)
    elif request.method == 'PUT':
        return change_password(request)
    elif request.method == 'DELETE':
        ret_data = {}
        ret_data["status"] = "false"
        ret_data["code"] = "1050"
        ret_data["message"] = error_info["1050"]
        return JsonResponse(ret_data)


"""
FUNCTION : signup
DESCRIPTION : 회원 가입
"""
def signup(request):
    ret_data = {}
    ret_data["status"] = "true"

    try:
        seoul_timezone = pytz.timezone("Asia/Seoul")
        now_date = datetime.datetime.now(tz=seoul_timezone).strftime('%Y-%m-%d %H:%M:%S')

        request_data = json.loads(request.body)

        user_id = request_data['user_id']
        user_pw = request_data['user_pw']
        user_pw_check = request_data['user_pw_check']
        user_name = request_data['user_name']

        if not user_pw or not user_pw_check:
            ret_data["status"] = "false"
            ret_data["code"] = "2011"
            ret_data["message"] = error_info["2011"]
            return JsonResponse(ret_data)

        if not user_id or not user_name:
            ret_data["status"] = "false"
            ret_data["code"] = "1013"
            ret_data["message"] = error_info["1013"]
            return JsonResponse(ret_data)

        # 아이디 유효성 검사 : 이메일 형식
        func_ret_data = id_valid_check(user_id)
        print(user_id)
        if func_ret_data["status"] == "false":
            return JsonResponse(func_ret_data)

        if user_pw != user_pw_check:
            ret_data["status"] = "false"
            ret_data["code"] = "2010"
            ret_data["message"] = error_info["2010"]
            return JsonResponse(ret_data)

        # 비밀번호 유효성 검사
        func_ret_data = pw_valid_check(user_pw)
        if func_ret_data["status"] == "false":
            return JsonResponse(func_ret_data)

        # 비밀번호 암호화 : bcrypt / salt추가하여 n번 hash
        key_stretching = def_config.KEY_STRETCHING
        bytes_password = user_pw.encode()
        hash_str = bcrypt.hashpw(password=bytes_password, salt=bcrypt.gensalt(key_stretching))
        hash_str = hash_str.decode('utf-8')  # bytes to string (bytes로 DB저장 시도시 오류발생함)
        request.session['user_pw'] = hash_str
        request.session['user_pw_check'] = hash_str   # required_key_list, session_key_list 에서 회원가입에 필요한 데이터의 개수를 체크하기 위해 user_pw_check도 세션에 저장해둔다.

        # 회원가입
        model_instance = Members(
                                    created_at=now_date,
                                    updated_at=now_date,
                                    user_id=user_id,
                                    user_pw=hash_str,
                                    user_name=user_name
                                )
        model_instance.save()

        members = list(Members.objects.filter(created_at=now_date, user_id=user_id).values())
        members_id = members[0]['id']

        print("회원가입(" + str(members_id) + ")")

        # JWT 세팅 및 발행
        param_info = {
            "members_id": members_id,
            "now_date": now_date
        }

        func_ret_data = def_jwt.get_jwt_access_token(param_info)
        if func_ret_data['status'] == 'false':
            return JsonResponse(func_ret_data)
        access_token = func_ret_data['data']

        func_ret_data = def_jwt.get_jwt_refresh_token(param_info)
        if func_ret_data['status'] == 'false':
            return JsonResponse(func_ret_data)
        refresh_token = func_ret_data['data']

        print("refresh_toke :: " + str(refresh_token))

        # redis에 token 저장
        token_data = {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

        param_info = {
            "members_id":members_id,
            "token_data": json.dumps(token_data)
        }
        func_ret_data = def_jwt.put_jwt(param_info)
        if func_ret_data['status'] == 'false':
            return JsonResponse(func_ret_data)

        # response setting
        response_data = json.dumps(ret_data)

        response = HttpResponse(response_data, content_type='application/json')

        # 쿠키의 만료 시간을 현재 시간에서 7일 후로 설정
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=7)

        # Access Token을 HTTP Only 쿠키로 설정하여 클라이언트에게 전달
        response.set_cookie('access_token', access_token, httponly=True, expires=expiration_time)

        # Refresh Token을 HTTP Only 쿠키로 설정하여 클라이언트에게 전달
        response.set_cookie('refresh_token', refresh_token, httponly=True, expires=expiration_time)

        return JsonResponse(ret_data)

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = error_info["1000"]
        return JsonResponse(ret_data)


"""
FUNCTION : get_member
DESCRIPTION : 회원 정보 조회
"""
def get_member(request):
    ret_data = {}
    ret_data["status"] = "true"

    try:

        func_ret_data = def_jwt_auth.get_members_id_in_access_token(request)
        if func_ret_data["status"] == "false":
            return JsonResponse(func_ret_data)
        members_id = func_ret_data["data"]





        return JsonResponse(ret_data)

    except:
        # def_log_trace(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = "오류가 발생했습니다."
        return JsonResponse(ret_data)


"""
FUNCTION : update_member
DESCRIPTION : 회원 정보 수정
"""
def update_member(request):
    ret_data = {}
    ret_data["status"] = "true"

    try:





        return JsonResponse(ret_data)

    except Exception as e:
        # def_log_trace(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = "오류가 발생했습니다."
        return JsonResponse(ret_data)

    return JsonResponse(ret_data)


"""
FUNCTION : delete_member
DESCRIPTION : 회원 탈퇴
"""
def delete_member(request):
    ret_data = {}
    ret_data["status"] = "true"

    try:



        return JsonResponse(ret_data)

    except:
        # def_log_trace(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = "오류가 발생했습니다."
        return JsonResponse(ret_data)



@api_view(['POST'])
@check_access_jwt_decorator
def password_check(request):

    ret_data = {}
    ret_data["status"] = "true"

    try:




            return JsonResponse(ret_data)

    except:
        # def_log_trace(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = "오류가 발생했습니다."
        return JsonResponse(ret_data)

    return JsonResponse(ret_data)



"""
FUNCTION : id_valid_check
DESCRIPTION : 아이디(이메일) 유효성 검사
"""
def id_valid_check(user_id):
    print("id_valid_check :: " + str(user_id))
    ret_data = {}
    ret_data["status"] = "true"

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not (re.match(email_regex, user_id)):
        ret_data["status"] = "false"
        ret_data["code"] = "2009"
        ret_data["message"] = error_info["2009"]

    return ret_data


"""
FUNCTION : pw_valid_check
DESCRIPTION : 비밀번호 유효성 검사
"""
def pw_valid_check(user_pw):
    ret_data = {}
    ret_data["status"] = "true"

    if len(user_pw) < 8\
        or (re.search('[a-z]+', user_pw) is None) \
        or (re.search('[A-Z]+', user_pw) is None) \
        or (re.search('[`~!@#$%^&*(),<.>/?]+', user_pw) is None):
        ret_data["status"] = "false"
        ret_data["code"] = "2012"
        ret_data["message"] = error_info["2012"]

    return ret_data