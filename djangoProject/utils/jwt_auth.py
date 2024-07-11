from django.http import JsonResponse
from django.http import HttpResponse

import traceback
import jwt
import time
import json
import datetime

from utils import jwt as def_jwt
from utils import config as def_config
from utils.common_util import get_cookie as def_get_cookie
from utils.log_util import log_trace as def_log_trace


# decorator
def check_access_jwt_decorator(func):
    def check_jwt_exp(request):
        ret_data = {}
        ret_data["status"] = "true"
        try:

            key = def_config.JWT_SECRET_KEY

            func_ret_data = def_get_cookie(request.META, "access_token")
            if func_ret_data["status"] == "false":
                return JsonResponse(func_ret_data)

            access_token = func_ret_data["data"]

            try:
                decoded_token = jwt.decode(access_token, key, algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                ret_data["status"] = "false"
                ret_data["code"] = "2014"
                ret_data["message"] = "Access Token이 만료되었습니다."
                return JsonResponse(ret_data)

            token_exp = decoded_token["exp"]
            now_timestamp = time.time()

            members_id = str(decoded_token['members_id'])

            # check exp
            if now_timestamp > token_exp:
                ret_data["status"] = "false"
                ret_data["code"] = "2014"
                ret_data["message"] = "Access Token이 만료되었습니다."
                return JsonResponse(ret_data)

            # check valid
            param_info = {
                "members_id": members_id
            }
            func_ret_data = def_jwt.get_jwt(param_info)
            if func_ret_data['status'] == "false":
                return JsonResponse(func_ret_data)

            saved_access_token = func_ret_data['data']['access_token']
            print("access_token :: " + access_token)
            print("saved_access_token :: " + saved_access_token)
            if access_token != saved_access_token:
                # 비정상적인 접근으로 간주하여 access token, refresh token 폐기
                param_info = {
                    "members_id": members_id
                }
                func_ret_data = def_jwt.delete_jwt(param_info)
                if func_ret_data['status'] == "false":
                    return JsonResponse(ret_data)
                ret_data["status"] = "false"
                ret_data["code"] = "2019"
                ret_data["message"] = "비정상적인 접근입니다. 다시 로그인 해주세요.(1)"
                return JsonResponse(ret_data)
        except:
            def_log_trace(str(traceback.format_exc()))
            ret_data["status"] = "false"
            ret_data["code"] = "2017"
            ret_data["message"] = "access token을 확인할 수 없습니다."
            return JsonResponse(ret_data)

        return func(request)
    return check_jwt_exp


def get_new_access_token(request):

    ret_data = {}
    ret_data["status"] = "true"

    try:
        key = def_config.JWT_SECRET_KEY

        func_ret_data = def_get_cookie(request.META, "access_token")
        if func_ret_data["status"] == "false":
            return JsonResponse(func_ret_data)
        access_token = func_ret_data["data"]
        print("access token :: " + str(access_token))
        func_ret_data = def_get_cookie(request.META, "refresh_token")
        if func_ret_data["status"] == "false":
            return JsonResponse(func_ret_data)
        refresh_token = func_ret_data["data"]
        print("refresh token :: " + str(refresh_token))

        try:
            # access token은 이미 만료되어 exception 발생하여 refresh token으로 payload 정보 가져온다.
            decoded_token = jwt.decode(refresh_token, key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            # refresh token 만료시 로그아웃
            ret_data["status"] = "false"
            ret_data["code"] = "2015"
            ret_data["message"] = "로그인 정보가 만료되었습니다. 다시 로그인 해주세요."
            return JsonResponse(ret_data)

        members_id = str(decoded_token['members_id'])
        # check valid 1 : 요청한 access token, refresh token이 동일한지 체크.
        param_info = {
            "members_id": members_id
        }
        func_ret_data = def_jwt.get_jwt(param_info)
        if func_ret_data['status'] == "false":
            return JsonResponse(func_ret_data)

        saved_access_token = func_ret_data['data']['access_token']
        saved_refresh_token = func_ret_data['data']['refresh_token']

        print("저장되어 있는 토큰과 비교")
        if access_token != saved_access_token or refresh_token != saved_refresh_token:
            print("저장된 퇴근과 값이 다름")
            # 비정상적인 접근으로 간주하여 access token, refresh token 폐기
            param_info = {
                "members_id": members_id
            }
            func_ret_data = def_jwt.delete_jwt(param_info)
            if func_ret_data['status'] == "false":
                return JsonResponse(func_ret_data)

            ret_data["status"] = "false"
            ret_data["code"] = "2022"
            ret_data["message"] = "비정상적인 접근입니다. 다시 로그인 해주세요.(3)"
            return JsonResponse(ret_data)

        # check valid 2 : access token 만료 전 토큰 재발급 요청이 올 경우 refresh token이 탈취되었다고 가정하여 폐기.
        try:
            decoded_token = jwt.decode(access_token, key, algorithms=['HS256'])

            token_exp = decoded_token["exp"]
            now_timestamp = time.time()
            if now_timestamp < token_exp:
                param_info = {
                    "members_id": members_id
                }
                func_ret_data = def_jwt.delete_jwt(param_info)
                if func_ret_data['status'] == "false":
                    return JsonResponse(func_ret_data)

                ret_data["status"] = "false"
                ret_data["code"] = "2016"
                ret_data["message"] = "비정상적인 토큰 발급 요청."
                return JsonResponse(ret_data)

        except jwt.ExpiredSignatureError:
            # access token 만료.(정상)
            pass

        # create new access token
        param_info = {
            "members_id": members_id
        }
        func_ret_data = def_jwt.get_jwt_access_token(param_info)
        if func_ret_data['status'] == 'false':
            return JsonResponse(func_ret_data)
        new_access_token = func_ret_data['data']

        # update access token
        param_info = {
            "members_id": members_id
        }
        func_ret_data = def_jwt.update_jwt(param_info)
        if func_ret_data['status'] == "false":
            return JsonResponse(func_ret_data)

        # response setting
        response_data = json.dumps(ret_data)

        response = HttpResponse(response_data, content_type='application/json')

        # 쿠키의 만료 시간을 현재 시간에서 7일 후로 설정
        expiration_time = datetime.datetime.now() + datetime.timedelta(days=7)

        # Access Token을 HTTP Only 쿠키로 설정하여 클라이언트에게 전달
        response.set_cookie('access_token', new_access_token, httponly=True, expires=expiration_time)

        # Refresh Token을 HTTP Only 쿠키로 설정하여 클라이언트에게 전달
        response.set_cookie('refresh_token', refresh_token, httponly=True, expires=expiration_time)

        return response

    except:
        print(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "2021"
        ret_data["message"] = "토큰 갱신에 실패하였습니다. 다시 로그인해주세요."
        return JsonResponse(ret_data)


"""
FUNCTION : get_members_id_in_access_token
DESCRIPTION : header의 cookie로 전달받은 access token으로 members_id 추출하기
"""
def get_members_id_in_access_token(request):

    ret_data = {}
    ret_data["status"] = "true"

    try:

        func_ret_data = def_get_cookie(request.META, "access_token")
        print(func_ret_data)
        if func_ret_data["status"] == "false":
            return func_ret_data

        key = def_config.JWT_SECRET_KEY

        access_token = func_ret_data["data"]
        try:
            token = jwt.decode(access_token, key, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            ret_data["status"] = "false"
            ret_data["code"] = "2014"
            ret_data["message"] = "Access Token이 만료되었습니다."
            return ret_data

        members_id = token["members_id"]
        ret_data["data"] = members_id

        return ret_data

    except:
        print(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "2023"
        ret_data["message"] = "access token 정보를 확인할 수 없습니다."
        return ret_data



