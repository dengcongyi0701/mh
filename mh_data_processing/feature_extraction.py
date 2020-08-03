# -*- coding: utf-8 -*-
"""
Created on 2020/7/9 19:01

@author : dengcongyi0701@163.com

Description: to get the src ip, src port, protocol, dst ip and dst port information from ngfw.access
             items of each day saved as csv file
"""
import json
import pandas as pd
import numpy as np


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
        df_info = df_info.sort_values(axis=0, ascending=True, by=['record_date'])
        df_info.to_csv(r"M:\mh_data\info\info_{}.csv".format(date), index=None)
        print("-----csv文件导出完毕-----".format(date))


def feature_extraction(seconds):
    """
    新特征提取： 特征——目的主机数，访问数/目的主机数，访问数/目的端口数, 目的端口标准差， 响应流均值， 响应流标准差， 0响应流次数，
                     平均请求流， 请求流标准差
                索引——源IP， 时间
    :param seconds:
    :return:
    """
    begin = "2020-02-16"
    end = "2020-02-16"
    col = ['src_IP', 'num_of_dstIP', 'ratio_acc_dstIP', 'ratio_acc_dstPORT', 'std_dstPORT', 'mean_resp_flow',
           'std_resp_flow', 'zero_resp_flow', 'mean_req_flow', 'std_req_flow', 'time']
    acc_date = pd.date_range(begin, end, freq='1D')
    for day in acc_date:
        day_df = pd.DataFrame(columns=col)
        date = str(day.date())
        file_add = r"M:\mh_data\info\info_{}.csv".format(date)
        df = pd.read_csv(file_add)
        df = df.drop(['id', 'src_type', 'src_port', 'l4_protocol', 'request_pack', 'response_pack', 'session_time'],
                     axis=1)
        time_range = pd.date_range(day, periods=86400/seconds, freq='{}S'.format(seconds), normalize=True)
        # 在每个时间窗内进行统计
        for time in time_range:
            print("正在分析{}数据......".format(str(time)))
            df_time = df[(df.record_date < str(time+1)) & (df.record_date >= str(time))]
            # 每个源主机发起的访问数
            num_of_acc = df_time.groupby('src_ip').count()['dst_ip'].tolist()
            # 目的主机个数
            num_of_dstIP = df_time.drop_duplicates(['src_ip', 'dst_ip']).groupby('src_ip').count()['dst_ip'].tolist()
            # 目的端口个数
            num_of_dstPORT = df_time.drop_duplicates(['src_ip', 'dst_port']).groupby('src_ip').count()['dst_port'].tolist()
            # 访问数/目的主机数
            ratio_acc_dstIP = np.divide(np.array(num_of_acc), np.array(num_of_dstIP)).tolist()
            # 访问数/目的端口数
            ratio_acc_dstPORT = np.divide(np.array(num_of_acc), np.array(num_of_dstPORT)).tolist()

            std = df_time.groupby('src_ip').agg(np.std, ddof=0)
            mean = df_time.groupby('src_ip').mean()

            # 端口号标准差
            std_dstPORT = std['dst_port'].tolist()
            # 响应流均值
            mean_resp_flow = mean['response_flow'].tolist()
            # 响应流标准差
            std_resp_flow = std['response_flow'].tolist()
            # 响应流为0的访问次数
            zero_resp_flow = list()
            for srcIP in std.index:
                a = df_time[(df_time.src_ip == srcIP) & (df_time.response_flow == 0)]
                zero_resp_flow.append(a.shape[0])
            # 请求流均值
            mean_req_flow = mean['request_flow'].tolist()
            # 请求流标准差
            std_req_flow = std['request_flow'].tolist()

            dic_temp = {
                'src_IP': std.index, 'num_of_dstIP': num_of_dstIP, 'ratio_acc_dstIP': ratio_acc_dstIP,
                'ratio_acc_dstPORT': ratio_acc_dstPORT, 'std_dstPORT': std_dstPORT, 'mean_resp_flow': mean_resp_flow,
                'std_resp_flow': std_resp_flow, 'zero_resp_flow': zero_resp_flow, 'mean_req_flow': mean_req_flow,
                'std_req_flow': std_req_flow, 'time': str(time)
            }

            df_temp = pd.DataFrame(dic_temp)
            day_df = day_df.append(df_temp)


        day_df = day_df.ix[:, col]
        day_df.to_csv(r"M:\mh_data\info\features\features_{}.csv".format(date), index=None)








if __name__ == "__main__":
    # get_info()
    # get_info_more()
    feature_extraction(10)


