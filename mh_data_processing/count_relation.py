# -*- coding: utf-8 -*-
"""
Created on 2020/7/11 11:12

@author : dengcongyi0701@163.com

Description: calculate the number of access between IP segments

"""
import pandas as pd


def count_relation():
    begin = "2020-02-01"
    end = "2020-02-02"
    acc_date = pd.date_range(begin, end, freq='1D')
    col = ['src_IP', 'dst_IP', 'count_re']
    df_cr = pd.DataFrame(columns=col)

    for day in acc_date:
        date = str(day.date())
        print("正在分析{}数据......".format(date))
        file_add = u"M:\mh_data\item_info({}).csv".format(date)
        df = pd.read_csv(file_add)
        for i in range(df.shape[0]):
            temp = df.iloc[i][1].split('.')
            src_seg = "{}.{}.{}.0/24".format(temp[0], temp[1], temp[2])
            temp = df.iloc[i][3].split('.')
            dst_seg = "{}.{}.{}.0/24".format(temp[0], temp[1], temp[2])
            new = pd.DataFrame([[src_seg, dst_seg, 1]], columns=col)
            df_cr = df_cr.append(new, ignore_index=True)

            if (i+1) % 10000 == 0:
                print(u'正在处理第%s项......' % (i + 1))
                df_cr = df_cr.groupby(['src_IP', 'dst_IP'], as_index=False).sum()

    df_cr = df_cr.groupby(['src_IP', 'dst_IP'], as_index=False).sum()
    df_cr.to_csv(r"M:\mh_data\IP_relation({}_{}).csv".format(begin, end), index=None)


def merge_relation():
    col = ['src_IP', 'dst_IP', 'count_re']
    df = pd.DataFrame(columns=col)
    for i in range(6):
        file_add = r"M:\mh_data\IP_relation({}).csv".format(str(i+1))
        df_temp = pd.read_csv(file_add)
        df = df.append(df_temp, ignore_index=True)
        df = df.groupby(['src_IP', 'dst_IP'], as_index=False).sum()

    df.to_csv(r"M:\mh_data\IP_relation_total.csv", index=None)


if __name__ == "__main__":
    # count_relation()
    merge_relation()
