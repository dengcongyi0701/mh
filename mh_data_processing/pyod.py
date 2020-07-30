# -*- coding: utf-8 -*-
"""
Created on 2020/7/14 14:44

@author : dengcongyi0701@163.com

Description:

"""
import socket
import struct
import pandas as pd
from sklearn.preprocessing import normalize
from sklearn import decomposition
from pyod.models.knn import KNN
from pyod.models.pca import PCA
from pyod.models.vae import VAE
from pyod.models.lof import LOF
from pyod.models.iforest import IForest
from pyod.models.feature_bagging import FeatureBagging
from pyod.models.so_gaal import SO_GAAL
import pickle

import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

plt.rcParams['font.sans-serif'] = ['SimHei']  # 指定默认字体
plt.rcParams['axes.unicode_minus'] = False  # 解决保存图像是负号'-'显示为方块的问题


begin = "2020-01-19"
end = "2020-01-19"
test_date = "2020-01-19"

KNN_clf = KNN(contamination=0.05)
PCA_clf = PCA(contamination=0.05, n_components=0.9)
VAE_clf = VAE(contamination=0.05, epochs=50, gamma=0.8, capacity=0.2, encoder_neurons=[9, 4], decoder_neurons=[4, 9])
LOF_clf = LOF(contamination=0.05)
IForest_clf = IForest(contamination=0.05)
FeatureBagging_clf = FeatureBagging(contamination=0.05, check_estimator=False)
SO_GAAL_clf = SO_GAAL(contamination=0.05, stop_epochs=20)
K_models = ['SO_GAAL', 'VAE']
S_models = ['KNN', 'PCA', 'LOF', 'IForest']


def get_train_data():
    """
    获取训练样本
    :return:    x_train 9特征训练样本
                df 原训练数据
    """
    acc_date = pd.date_range(begin, end, freq='1D')
    for day in acc_date:
        date = str(day.date())
        file_add = u"M:\mh_data\info\info_{}.csv".format(date)
        if date == begin:
            df = pd.read_csv(file_add, index_col='id')
        else:
            df = df.append(pd.read_csv(file_add, index_col='id'))
    x_train = df.drop(['src_port', 'dst_port', 'l4_protocol', 'record_date'], axis=1)
    src_ip = x_train['src_ip'][:]
    dst_ip = x_train['dst_ip'][:]
    for i in src_ip.index:
        src_ip[i] = struct.unpack('!I', socket.inet_aton(src_ip[i]))[0]
        dst_ip[i] = struct.unpack('!I', socket.inet_aton(dst_ip[i]))[0]
    x_train['src_ip'] = src_ip
    x_train['dst_ip'] = dst_ip
    x_train = pd.DataFrame(normalize(x_train.values), index=x_train.index, columns=x_train.columns)
    return x_train, df


def get_test_data():
    """
    获取测试样本
    :return:    x_test 9特征测试样本
                df 原测试样本
    """
    file_add = u"M:\mh_data\info\info_{}.csv".format(test_date)
    df = pd.read_csv(file_add, index_col='id')
    x_test = df.drop(['src_port', 'dst_port', 'l4_protocol', 'record_date'], axis=1)
    src_ip = x_test['src_ip'][:]
    dst_ip = x_test['dst_ip'][:]
    for i in src_ip.index:
        src_ip[i] = struct.unpack('!I', socket.inet_aton(src_ip[i]))[0]
        dst_ip[i] = struct.unpack('!I', socket.inet_aton(dst_ip[i]))[0]
    x_test['src_ip'] = src_ip
    x_test['dst_ip'] = dst_ip
    x_test = pd.DataFrame(normalize(x_test.values), index=x_test.index, columns=x_test.columns)
    return x_test, df


def pyod_train(clf, name):
    """
    :param clf:     分类器
    :param name:    算法名称
    :return:
    """
    x_train, df_train = get_train_data()
    # x_test, df_test = get_test_data()
    # df_train = df_train.reset_index()
    # df_test = df_test.reset_index()

    print("————————————{} training————————————".format(name))
    clf.fit(x_train)

    if name in S_models:
        with open('M:\mh_data\model\{}.pkl'.format(name), 'wb') as f:
            pickle.dump(clf, f)
    # elif name in K_models:
    #     clf.save('M:\mh_data\model\{}.h5'.format(name))
    else:
        return clf



def pyod_predict(clf, name):
    """
    :param name: 算法名称
    :return:  危险IP top10， 对应最可疑访问的p-value
    """
    x_train, df_train = get_train_data()
    x_test, df_test = get_test_data()
    df_train = df_train.reset_index()
    df_test = df_test.reset_index()

    if name in S_models:
        with open('M:\mh_data\model\{}.pkl'.format(name), 'rb') as f:
            clf = pickle.load(f)
    # elif name in K_models:
    #     clf.load('M:\mh_data\model\{}.h5'.format(name))
    else:
        clf = pyod_train(clf, name)

    y_train_pred = clf.labels_
    y_train_scores = clf.decision_scores_

    # # IP按发起可疑访问的数量降序排列，取前10个为可疑IP
    x_train = x_train.reset_index()
    x_train = x_train.drop('id', axis=1)
    df_train.insert(0, 'label', y_train_pred)
    df_train.insert(0, 'score', y_train_scores)
    sus_x_train = df_train[df_train.label > 0]
    safe_x_train = df_train[df_train.label == 0]
    # sus_x_train.to_csv(u"M:\mh_data\info\{}_train_{}_{}.csv".format(name, begin, end), index=None)

    sus_x_train_ip = sus_x_train['src_ip'][:]
    train_top10 = sus_x_train_ip.value_counts()[:10]
    print("\nTen most suspicious IP in train set:")
    print(train_top10)

    print("———————————{} predicting———————————".format(name))
    y_test_pred = clf.predict(x_test)
    y_test_scores = clf.decision_function(x_test)

    df_test.insert(0, 'label', y_test_pred)
    df_test.insert(0, 'score', y_test_scores)
    print("total:", df_test.shape[0])
    sus_x_test = df_test[df_test.label > 0]
    safe_x_test = df_train[df_train.label == 0]
    print("suspicious:", sus_x_test.shape[0])

    # sus_x_test.to_csv(u"M:\mh_data\info\{}_test_{}.csv".format(name, test_date), index=None)

    sus_x_test_ip = sus_x_test['src_ip'][:]
    top10 = sus_x_test_ip.value_counts()[:10]
    print("\nTen most suspicious IP in test set:")
    print(top10)

    print("———————————P_values calculating———————————")
    ip_list = top10.index.tolist()
    # top10_acc = sus_x_test.loc[sus_x_test['src_ip'].isin(ip_list)]
    sus_x_train_score = sus_x_train['score'][:].tolist()

    pv_list = list()
    for ip in ip_list:
        score_list = sus_x_test.loc[sus_x_test['src_ip'] == ip]
        score_list = score_list['score'][:].tolist()

        # ###################
        # top10 IP 所有访问p-value均值
        # pv = 0pick
        # for sc in score_list:
        #     pv += cal_pValue(sus_x_train_score, sc)
        # pv /= len(score_list)
        # ###################

        score = max(score_list)
        print(score_list)
        pv = cal_pValue(sus_x_train_score, score)
        pv_list.append(pv)

    return ip_list, pv_list


def cal_pValue(sus_train, sample_score):
    """
    :param train: 训练集中可疑访问得分
    :param sample_score: 待计算样本的异常分数
    :return: p_value
    """

    s = 0
    for train_sc in sus_train:
        if train_sc < sample_score:
            s += 1
    pv = s/len(sus_train)
    return pv


if __name__ == "__main__":

    # pyod_train(SO_GAAL_clf, "SO_GAAL")
    ipl, pvl = pyod_predict(SO_GAAL_clf, "SO_GAAL")
    # print(ipl)
    # print(pvl)

