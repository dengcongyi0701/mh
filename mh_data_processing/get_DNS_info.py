# -*- coding: utf-8 -*-
"""
Created on 2020/7/17 13:54

@author : dengcongyi0701@163.com

Description:

"""

import json
import time
import pandas as pd


def get_url_info():
    ip = '10.13.78.146'
    file_add = r"M:\华东日志数据\log\ngfw.dnsflow\ngfw.dnsflow-2020-02-15.json"
    dns_info = []
    with open(file_add, 'r', encoding='utf-8') as f:
        i = 0
        while True:
            i += 1
            if i % 10000 == 0:
                print(u'正在载入第%s行......' % i)
            try:
                line = f.readline()  # 使用逐行读取的方法
                jl = json.loads(line)
                if jl['_source']['src_ip'] == ip:
                    item_list = list()
                    for a in ['src_ip', 'dst_ip', 'queries']:
                        item_list.append(jl['_source'][a])
                    ts = int(jl['_source']['ts'])
                    item_list.append(time.strftime("%H", time.localtime(ts/1000)))
                    dns_info.append(item_list)
            except Exception as e:
                print(str(e))
                print("分析数据完成。")
                break
    df = pd.DataFrame(dns_info, columns=['src_ip', 'dst_ip', 'queries', 'time'])
    df.to_csv(r"M:\beifen\dns_mal_info.csv", index=False)

def merge_dns():
    file_add = r"M:\beifen\dns_mal_info.csv"
    df = pd.read_csv(file_add)
    df1 = df.drop(['dst_ip', 'time'], axis=1)
    df1.columns = ['count', 'queries']
    mg_df = df1.groupby('queries', as_index=False).count()
    mg_df = mg_df.sort_values(by='count', ascending=False)
    dga = mg_df['queries'][:40].values
    # print(dga)

    df = df.drop(['dst_ip'], axis=1)
    df.columns = ['count', 'queries', 'time']
    mg_df = df.groupby(['queries', 'time']).count()


    dsum = {}
    for add in dga:
        lsum = [0 for i in range(24)]
        for j in range(24):
            try:
                lsum[j] = mg_df.loc[(add, j)][0]
            except Exception as e:
                continue
        dsum[add] = lsum

    ds = pd.DataFrame(dsum)
    # ds = pd.DataFrame(ds.values.T, index=ds.columns, columns=ds.index)
    print(ds.columns.values.tolist())

    for i in range(24):
        print(i)
        print(ds.iloc[i][:].values.tolist())



if __name__ == "__main__":
    # get_url_info()
    merge_dns()