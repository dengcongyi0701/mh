# -*- coding: utf-8 -*-
"""
Created on 2020/7/10 14:40

@author : dengcongyi0701@163.com

Description: calculate the number of IP segments

"""
import pandas as pd
import IPy
import IPy


def is_pub_ip(ip):
    re = True
    if ip in IPy.IP('10.0.0.0-10.255.255.255') or \
            ip in IPy.IP('172.16.0.0-172.31.255.255') or \
            ip in IPy.IP('192.168.0.0-192.168.255.255'):
        re = False
    return re


def count_ip():
    """
    计算共有多少个IP被访问
    :return:
    """
    begin = "2020-02-08"
    end = "2020-02-12"
    acc_date = pd.date_range(begin, end, freq='1D')
    ip_src = dict()
    ip_dst = dict()

    for day in acc_date:
        date = str(day.date())
        print("正在分析{}数据......".format(date))
        file_add = u"M:\mh_data\item_info({}).csv".format(date)
        df = pd.read_csv(file_add)
        for i in range(df.shape[0]):
            if df.iloc[i][1] not in ip_src.keys():
                ip_src[df.iloc[i][1]] = 1
            else:
                ip_src[df.iloc[i][1]] += 1
            if df.iloc[i][3] not in ip_dst.keys():
                ip_dst[df.iloc[i][3]] = 1
            else:
                ip_dst[df.iloc[i][3]] += 1
            if (i+1) % 10000 == 0:
                print(u'正在处理第%s项......' % (i+1))

    ip_total = dict()
    for key in ip_src:
        if ip_dst.get(key):
            ip_total[key] = [ip_src[key], ip_dst[key], ip_src[key] + ip_dst[key]]
        else:
            ip_total[key] = [ip_src[key], 0, ip_src[key]]
    for key in ip_dst:
        if not ip_src.get(key):
            ip_total[key] = [0, ip_dst[key], ip_dst[key]]

    print("————————共统计到{}个IP————————".format(len(ip_total)))
    df = pd.DataFrame(ip_total)
    df = pd.DataFrame(df.values.T, index=df.columns, columns=['src', 'dst', 'total'])
    df.to_csv(r"M:\mh_data\IP_access({}_{}).csv".format(begin, end))


def merge_ip():
    """
    将IP按网段分类统计，便于可视化
    :return:
    """
    ip_count = dict()
    ip_merge = dict()
    for i in range(6):
        file_add = r"M:\mh_data\IP_access({}).csv".format(str(i+1))
        df = pd.read_csv(file_add, index_col=0)
        for j in df.index:
            ip_sp = j.split('.')
            j_merge = "{}.{}.{}.0/24".format(ip_sp[0], ip_sp[1], ip_sp[2])
            if j not in ip_count.keys():
                ip_count[j] = [df.loc[j]['src'], df.loc[j]['dst'], df.loc[j]['total']]
            else:
                ip_count[j][0] += df.loc[j]['src']
                ip_count[j][1] += df.loc[j]['dst']
                ip_count[j][2] += df.loc[j]['total']
            if j_merge not in ip_merge.keys():
                ip_merge[j_merge] = [df.loc[j]['src'], df.loc[j]['dst'], df.loc[j]['total']]
            else:
                ip_merge[j_merge][0] += df.loc[j]['src']
                ip_merge[j_merge][1] += df.loc[j]['dst']
                ip_merge[j_merge][2] += df.loc[j]['total']

    print("————————共统计到{}个IP————————".format(len(ip_count)))
    print("———————合并后共{}个网段————————".format(len(ip_merge)))
    df1 = pd.DataFrame(ip_count)
    df1 = pd.DataFrame(df1.values.T, index=df1.columns, columns=['src', 'dst', 'total'])
    df1.to_csv(r"M:\mh_data\IP_total.csv")
    df2 = pd.DataFrame(ip_merge)
    df2 = pd.DataFrame(df2.values.T, index=df2.columns, columns=['src', 'dst', 'total'])
    df2.to_csv(r"M:\mh_data\IP_merge.csv")


def count_pub_pri():
    """
    计算每天私有IP和公有IP被访问的情况
    :return:
    """
    begin = "2020-01-19"
    end = "2020-02-17"
    acc_date = pd.date_range(begin, end, freq='1D')

    #       日期     IP总数       公有IP数       私有IP数    发出访问的公有IP数  接受访问的公有IP数  发出访问的私有IP数
    col = ['date', 'IP_sum', 'pub_IP_sum', 'pri_IP_sum', 'src_pub_IP_sum', 'dst_pub_IP_sum', 'src_pri_IP_sum',
           'dst_pri_IP_sum', 'acc_sum', 'src_pub_acc', 'dst_pub_acc', 'src_pri_acc', 'dst_pri_acc']
    #       接受访问的私有IP数  访问总数  公有IP发起的访问 公有IP接受的访问  私有IP发起的访问 私有IP接受的访问

    df_day = pd.DataFrame(columns=col)
    for day in acc_date:
        date = str(day.date())
        print("正在分析{}数据......".format(date))
        file_add = u"M:\mh_data\item_info({}).csv".format(date)
        df = pd.read_csv(file_add)
        src_df = df['1'].value_counts()
        src_pubIP = []
        src_priIP = []
        src_pubacc = 0
        src_priacc = 0
        for ip in src_df.index:
            if is_pub_ip(ip):
                src_pubIP.append(ip)
                src_pubacc += src_df[ip]
            else:
                src_priIP.append(ip)
                src_priacc += src_df[ip]
        dst_df = df['3'].value_counts()
        dst_pubIP = []
        dst_priIP = []
        dst_pubacc = 0
        dst_priacc = 0
        for ip in dst_df.index:
            if is_pub_ip(ip):
                dst_pubIP.append(ip)
                dst_pubacc += dst_df[ip]
            else:
                dst_priIP.append(ip)
                dst_priacc += dst_df[ip]
        pubIP = src_pubIP + dst_pubIP
        pubIP = list({}.fromkeys(pubIP).keys())
        priIP = src_priIP + dst_priIP
        priIP = list({}.fromkeys(priIP).keys())

        new = pd.DataFrame([[date, len(pubIP)+len(priIP), len(pubIP), len(priIP), len(src_pubIP), len(dst_pubIP),
                             len(src_priIP), len(dst_priIP), df.shape[0], src_pubacc, dst_pubacc, src_priacc,
                             dst_priacc]],columns=col)
        df_day = df_day.append(new, ignore_index=True)
    df_day.to_csv(r"M:\mh_data\everyday_info.csv", index=None)



if __name__ == "__main__":
    # count_ip()
    # merge_ip()

    count_pub_pri()
