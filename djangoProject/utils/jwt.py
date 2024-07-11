import datetime
import jwt
import redis

from django.conf import settings

import utils.config as def_config
from utils.error_info import error_info


def redis_client():
    ret_data = {}
    ret_data["status"] = "true"

    try:
        r = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)

        ret_data["r"] = r

        return ret_data

    except Exception as e:
        ret_data["status"] = "false"
        ret_data["code"] = "1000"
        ret_data["message"] = error_info["1000"]
        return JsonResponse(ret_data)




def put_jwt(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:
        members_id = param_info["members_id"]
        token_data = param_info["token_data"]

        func_ret_data = redis_client()
        if func_ret_data["status"] == "false":
            return func_ret_data

        r = func_ret_data["r"]
        r.set(members_id, token_data)

        return ret_data

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2005"
        ret_data["message"] = error_info["2005"]

        return ret_data

    return ret_data


def get_jwt(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:
        members_id = param_info["members_id"]

        func_ret_data = redis_client()
        if func_ret_data["status"] == "false":
            return func_ret_data

        r = func_ret_data["r"]
        token_data = r.get(members_id)

        if token_data is None:
            ret_data["status"] = "false"
            ret_data["code"] = "2007"
            ret_data["message"] = error_info["2007"]
            return ret_data

        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]

        tmp_ret_data = {}
        tmp_ret_data["access_token"] = access_token
        tmp_ret_data["refresh_token"] = refresh_token
        ret_data["data"] = tmp_ret_data

        return ret_data

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2005"
        ret_data["message"] = error_info["2005"]

        return ret_data


def update_jwt(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:



        return ret_data

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2005"
        ret_data["message"] = error_info["2005"]

        return ret_data


# jwt를 복호화한 후 payload에서 유효기간이 지났을 경우 해당 jwt를 제거
def delete_jwt(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:


        return ret_data

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2005"
        ret_data["message"] = error_info["2005"]

        return ret_data


def get_jwt_access_token(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:
        print("jwt 생성 진입")
        members_id = param_info.get("members_id", "")

        key = def_config.JWT_SECRET_KEY
        print("key :: " + str(key))

        # pyjwt에서 제공하는 decode의 timezone이 utc라서 encoding할 만료시간도 utc를 기준으로 세팅하였음.
        payload = {
            "members_id": str(members_id),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        print("pyload 생성")

        token = jwt.encode(payload, key, algorithm='HS256')
        print("token 생성 :: " + str(token))
        ret_data['data'] = token

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2004"
        ret_data["message"] = error_info["2004"]

        return ret_data

    return ret_data


def get_jwt_refresh_token(param_info):

    ret_data = {}
    ret_data["status"] = "true"

    try:

        members_id = param_info.get("members_id", "")

        key = def_config.JWT_SECRET_KEY

        # pyjwt에서 제공하는 decode의 timezone이 utc라서 encoding할 만료시간도 utc를 기준으로 세팅하였음.
        payload = {
            "members_id": members_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)  # 테스트를 위해 매우 짧은 시간으로 세팅함.
        }

        token = jwt.encode(payload, key, algorithm='HS256')

        ret_data['data'] = token

        return ret_data

    except Exception as e:
        print("e :: " + str(e))
        ret_data["status"] = "false"
        ret_data["code"] = "2004"
        ret_data["message"] = error_info["2004"]

        return ret_data

