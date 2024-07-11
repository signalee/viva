"""
FUNCTION : get_cookie
DESCRIPTION : 헤더에서 쿠키 값을 얻는다.
"""
def get_cookie(request_headers, cookie_name):

    ret_data = {}
    ret_data["status"] = "true"
    try:

        cookies = request_headers["HTTP_COOKIE"]
        if cookies[-1] != ";":
            # cookie에 refresh token의 경우 맨 뒤에 ';'가 없을 경우가 있어 붙여주어 grap함수를 호출한다.
            cookies += ";"
        cookie_value = grap(cookies, cookie_name + "=", ';', 0)

        if cookie_value == "":
            ret_data["status"] = "false"
            ret_data["code"] = "1200"
            ret_data["message"] = "Cookie를 얻는데 오류가 발생했습니다."
            return ret_data

        ret_data["data"] = cookie_value
        return ret_data

    except:
        ret_data["status"] = "false"
        ret_data["code"] = "1200"
        ret_data["message"] = "Cookie를 얻는데 오류가 발생했습니다."
        return ret_data


def grap(text, front_str, end_str, idx):
    grap_str = ""
    front_idx = 0
    front_idx = text.find(front_str, 0)
    text = text[front_idx:]  # 0번째는 반복문을 진입하지 않으므로 먼저 해준다.
    for cnt in range(idx):
        front_idx = text.find(front_str, cnt + 1)  # 0번째는 찾았으므로 1번째부터 찾는다.

        text = text[front_idx:]
        if front_idx == -1:
            break

    text = text[len(front_str):]
    end_idx = text.find(end_str)
    if end_idx == -1:
        return grap_str

    grap_str = text[:end_idx]

    return grap_str


def grap_add(text, front_str, end_str, idx):
    grap_str = ""

    front_idx = 0
    front_idx = text.find(front_str, 0)
    text = text[front_idx:]  # 0번째는 반복문을 진입하지 않으므로 먼저 해준다.

    for cnt in range(idx):
        front_idx = text.find(front_str, cnt + 1)  # 0번째는 찾았으므로 1번째부터 찾는다.

        text = text[front_idx:]
        if front_idx == -1:
            break

    front_text = text[:len(front_str)]
    text = text[len(front_str):]

    end_idx = text.find(end_str)
    if end_idx == -1:
        return grap_str

    grap_str = front_text + text[:end_idx + len(end_str)]

    return grap_str