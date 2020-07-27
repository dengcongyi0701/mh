# -*- coding: utf-8 -*-
"""
Created on 2020/7/9 19:01

@author : dengcongyi0701@163.com

Description: to get the src ip, src port, protocol, dst ip and dst port information from ngfw.access
             items of each day saved as csv file
"""
import json
import pandas as pd


def get_info():
    """
    提取五元组：源IP、源端口、目的IP、目的端口、协议号
    :return:
    """
    acc_date = pd.date_range("2020-02-12", "2020-02-13", freq='1D')
    acc_info = []
    for day in acc_date:
        date = str(day.date())
        file_add = r"M:\华东日志数据\log\ngfw.access\ngfw.access-{}.json".format(date)
        print("正在分析{}数据......".format(date))
        with open(file_add, 'r', encoding='utf-8') as f:
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
                    for a in ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'l4_protocol']:
                        item_list.append(jl['_source'][a])
                    acc_info.append(item_list)
                except Exception as e:
                    print(str(e))
                    print("分析{}数据完成。".format(date))
                    break
        df = pd.DataFrame(acc_info)
        df.to_csv(r"M:\mh_data\item_info({}).csv".format(date), index=False)


def get_info_more():
    """
    提取更多信息：
    id， 源类型， 目的类型， 源IP， 目的IP， 源端口， 目的端口， 协议类型， 请求流量， 回答流量， 请求包数量， 回答包数量，
    会话持续时间， 记录日期
    :return:
    """
    begin = "2020-02-13"
    end = "2020-02-17"
    acc_date = pd.date_range(begin, end, freq='1D')
    col = ['id', 'src_type', 'dst_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'l4_protocol', 'request_flow',
           'response_flow', 'request_pack', 'response_pack', 'session_time', 'record_date']
    for day in acc_date:
        date = str(day.date())
        file_add = r"M:\华东日志数据\log\ngfw.access\ngfw.access-{}.json".format(date)
        print("正在分析{}数据......".format(date))
        day_items = list()
        with open(file_add, 'r', encoding='utf-8') as f:
            i = 0
            while True:
                i += 1
                if i % 10000 == 0:
                    print(u'正在载入第%s行......' % i)
                try:
                    line = f.readline()  # 使用逐行读取的方法
                    jl = json.loads(line)
                    new_item = list()
                    new_item.append(jl['_id'])
                    for a in ['src_type', 'dst_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'l4_protocol',
                              'request_flow', 'response_flow', 'request_pack', 'response_pack', 'session_time',
                              'record_date']:
                        new_item.append(jl['_source'][a])
                    day_items.append(new_item)
                except Exception as e:
                    print(str(e))
                    print("分析{}数据完成。".format(date))
                    break
        df_info = pd.DataFrame(day_items, columns=col)
        df_info.to_csv(r"M:\mh_data\info\info_{}.csv".format(date), index=None)
        print("-----csv文件导出完毕-----".format(date))


if __name__ == "__main__":
    # get_info()
    get_info_more()

