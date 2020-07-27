# -*- coding: utf-8 -*-
"""
Created on 2020/7/13 15:49

@author : dengcongyi0701@163.com

Description:

"""
import pandas as pd
import json


def count_flow():
    begin = "2020-01-19"
    end = "2020-02-17"
    acc_date = pd.date_range(begin, end, freq='1D')
    col = ['date', 'request_flow_total', 'response_flow_total']
    df = pd.DataFrame(columns=col)

    for day in acc_date:
        date = str(day.date())
        print("正在分析{}数据......".format(date))
        file_add = r"M:\华东日志数据\log\ngfw.access\ngfw.access-{}.json".format(date)
        with open(file_add, 'r', encoding='utf-8') as f:
            request_flow = 0
            response_flow = 0
            i = 0
            while True:
                i += 1
                if i % 10000 == 0:
                    print(u'正在载入第%s行......' % i)
                try:
                    line = f.readline()  # 使用逐行读取的方法
                    jl = json.loads(line)
                    item_list = list()
                    item_list.append(date)
                    request_flow += jl['_source']['request_flow']
                    response_flow += jl['_source']['response_flow']
                except Exception as e:
                    print(str(e))
                    print("分析{}数据完成。".format(date))
                    break
        new = pd.DataFrame([[date, request_flow, response_flow]], columns=col)
        df = df.append(new, ignore_index=True)

    df.to_csv(r"M:\mh_data\flow_sum.csv")


if __name__ == "__main__":
    count_flow()
