from django.db import connection

import traceback


"""
FUNCTION : cursor_excute_all
DESCRIPTION : ORM을 사용하지 않고 직접 쿼리문을 실행
"""
def cursor_excute_all(sql):

    ret_data = {}
    ret_data["status"] = "true"

    try:

        with connection.cursor() as cursor:
            # SQL 쿼리 실행
            cursor.execute(sql)
            if sql.split(' ')[0] in ['update', 'UPDATE', 'insert', 'INSERT', 'delete', 'DELETE']:
                # 쿼리 실행 결과를 반환할 데이터가 없을 경우 pass한다.
                pass
            else:
                # 컬럼명 가져오기
                columns = [column[0] for column in cursor.description]

                # 결과 가져오기
                rows = cursor.fetchall()

                # 결과를 컬럼명과 값의 딕셔너리 형태로 변환
                formatted_results = []
                for row in rows:
                    formatted_results.append(dict(zip(columns, row)))

                ret_data["data"] = list(formatted_results)

    except:
        print(str(traceback.format_exc()))
        ret_data["status"] = "false"
        ret_data["code"] = "1100"
        ret_data["message"] = "DB 오류가 발생했습니다."
        return ret_data

    return ret_data



