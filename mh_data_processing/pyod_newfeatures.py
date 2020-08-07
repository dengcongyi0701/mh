# -*- coding: utf-8 -*-
"""
Created on 2020/7/29 14:37

@author : dengcongyi0701@163.com

Description:

"""

import socket
import struct
import numpy as np
import pandas as pd
from sklearn.preprocessing import normalize
from sklearn import decomposition
from pyod.models.abod import ABOD
from pyod.models.auto_encoder import AutoEncoder
from pyod.models.knn import KNN
from pyod.models.pca import PCA
from pyod.models.vae import VAE
from pyod.models.lof import LOF
from pyod.models.iforest import IForest
from pyod.models.feature_bagging import FeatureBagging
from pyod.models.hbos import HBOS
from pyod.models.cblof import CBLOF
from pyod.models.loda import LODA
from pyod.models.mcd import MCD
from pyod.models.mo_gaal import MO_GAAL
from pyod.models.so_gaal import SO_GAAL

import datetime
import pickle


begin = "2020-02-13"
end = "2020-02-15"

test_date = "2020-02-16"

KNN_clf = KNN(contamination=0.05)
PCA_clf = PCA(contamination=0.05)
VAE_clf = VAE(contamination=0.05, epochs=30, encoder_neurons=[9, 4], decoder_neurons=[4, 9])
# VAE_clf = VAE(contamination=0.05, epochs=50, gamma=0.8, capacity=0.2, encoder_neurons=[9, 4], decoder_neurons=[4, 9])
LOF_clf = LOF(contamination=0.05)
IForest_clf = IForest(contamination=0.05)
AutoEncoder_clf = AutoEncoder(contamination=0.05, epochs=30, hidden_neurons=[9, 4, 4, 9])
FeatureBagging_clf = FeatureBagging(contamination=0.05, check_estimator=False)
ABOD_clf = ABOD(contamination=0.05)
HBOS_clf = HBOS(contamination=0.05)
CBLOF_clf = CBLOF(contamination=0.05)
LODA_clf = LODA(contamination=0.05)
MCD_clf = MCD(contamination=0.05)
MO_GAAL_clf = MO_GAAL(k=3, stop_epochs=2, contamination=0.05)
SO_GAAL_clf = SO_GAAL(contamination=0.05)
KNN_MAH_clf = None

S_models = ["KNN", "LOF", "PCA", "IForest", "HBOS", "LODA", "MCD", "CBLOF", "FeatureBagging", "ABOD"]
K_models = ["AutoEncoder", "SO_GAAL", "VAE"]

def get_train_data():
    """
    获取训练样本
    :return:    x_train 9特征训练样本
                df 原训练数据
    """
    acc_date = pd.date_range(begin, end, freq='1D')
    for day in acc_date:
        date = str(day.date())
        file_add = r"M:\mh_data\info\features\features_{}.csv".format(date)
        if date == begin:
            df = pd.read_csv(file_add, index_col=['src_IP', 'time'])
        else:
            df = df.append(pd.read_csv(file_add, index_col=['src_IP', 'time']))
    x_train = pd.DataFrame(normalize(df.values), index=df.index, columns=df.columns)
    return x_train, df


def get_test_data():
    """
    获取测试样本
    :return:    x_test 9特征测试样本
                df 原测试样本
    """
    file_add = r"M:\mh_data\info\features\features_{}.csv".format(test_date)
    df = pd.read_csv(file_add, index_col=['src_IP', 'time'])
    x_test = pd.DataFrame(normalize(df.values), index=df.index, columns=df.columns)
    return x_test, df


def pyod_train(clf, name):
    """
    :param clf:     分类器
    :param name:    算法名称
    :return:
    """
    x_train, df_train = get_train_data()

    if name == "KNN_MAH":
        x_train_cov = np.cov(x_train, rowvar=False)
        clf = KNN(metric='mahalanobis', metric_params={'V': x_train_cov})

    print("————————————{} training————————————".format(name))
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("time:{}".format(time))

    clf.fit(x_train)

    print("———————{} finished training————————".format(name))
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("time:{}".format(time))

    if name in S_models:
        with open('M:\mh_data\model\{}\{}.pkl'.format(name, name), 'wb') as f:
            pickle.dump(clf, f)
    elif name in K_models:
        clf.save("M:\mh_data\model\{}\{}".format(name, name))
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
        with open('M:\mh_data\model\{}\{}.pkl'.format(name, name), 'rb') as f:
            clf = pickle.load(f)
    elif name in K_models:
        clf.read("M:\mh_data\model\{}\{}".format(name, name), x_train.shape[0], x_train.shape[1])
    else:
        clf = pyod_train(clf, name)

    y_train_pred = clf.labels_
    y_train_scores = clf.decision_scores_

    df_train.insert(0, 'label', y_train_pred)
    df_train.insert(0, 'score', y_train_scores)
    df_train = df_train.sort_values(by='score', ascending=False)
    train_top10 = df_train[['src_IP', 'time', 'score']][:10]
    print("\nTen most suspicious IP in train set:")
    print(train_top10)

    print("———————————{} predicting———————————".format(name))
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("time:{}".format(time))

    y_test_pred = clf.predict(x_test)
    y_test_scores = clf.decision_function(x_test)

    print("——————{} finished predicting———————".format(name))
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("time:{}".format(time))


    train_mal = df_train[df_train.label == 1]['score'][:].tolist()
    train_ben = df_train[df_train.label == 0]['score'][:].tolist()

    df_test.insert(0, 'label', y_test_pred)
    df_test.insert(0, 'score', y_test_scores)
    df_test = df_test.sort_values(by='score', ascending=False)

    # # # 计算测试样本的p_value，耗时间
    # test_mal = df_test[df_test.label == 1]['score'][:].tolist()
    # test_ben = df_test[df_test.label == 0]['score'][:].tolist()
    # test_pv = cal_pValue(train_mal, train_ben, test_mal, test_ben)
    # df_test.insert(0, 'p_value', test_pv)
    # top10 = df_test[['src_IP', 'time', 'score', 'p_value']][:10]
    # print("\nTen most suspicious ITEMs in test set:")
    # print(top10)
    # sus_test = df_test[df_test.label == 1]
    # sus_test = sus_test[['src_IP', 'score']]
    # a = sus_test.groupby('src_IP').count().sort_values(by='score', ascending=False)[:10]
    # print("\nTen most suspicious IPs:")
    # print(a)


    #######################
    top10 = df_test[['src_IP', 'time', 'score']][:10]
    print("\nTen most suspicious ITEMs in test set:")
    print(top10)

    sus_test = df_test[df_test.label == 1]
    sus_test = sus_test[['src_IP', 'score']]
    a = sus_test.groupby('src_IP').count().sort_values(by='score', ascending=False)[:10]

    # 计算恶意主机p_value最大值
    biggest_score = []
    for ip in a.index:
        score_list = sus_test.loc[sus_test['src_IP'] == ip]
        score_list = score_list['score'][:].tolist()
        biggest_score.append(max(score_list))
    ip_pv = cal_IP_pValue(train_mal, biggest_score)
    a.insert(1, 'p_value', ip_pv)

    print("\nTen most suspicious IPs:")
    print(a)

    # 数据可视化
    # 降维
    pca = decomposition.PCA(n_components=3)
    pca_test = pd.DataFrame(pca.fit_transform(x_test))
    pca_test.insert(0, 'label', y_test_pred)
    pca_test.insert(0, 'IP', df_test.pop('src_IP'))

    # 抽取百分之一的数据
    pca_sample = pca_test.sample(frac=0.01, axis=0)
    safe = pca_sample[pca_sample.label == 0]
    dangerous = pca_sample[pca_sample.label > 0]
    safe.to_csv("{}_safe.csv".format(name), index=None)
    dangerous.to_csv("{}_dangerous.csv".format(name), index=None)
    print("\nthe number of safe points:", safe.shape[0])
    print("the number of dangerous points:", dangerous.shape[0])
    #####################################

def cal_pValue(train_mal, train_ben ,test_mal, test_ben):
    """
    :param train: 训练集样本异常分数
    :param sample_score: 测试集样本异常分数
    :return: 测试集样本p_value
    """
    # pv_list = list()
    # for i in range(len(test_label)):
    #     s = 0
    #     if test_label[i] == 1:
    #         for train_sc in train_mal:
    #             if train_sc <= test_scores[i]:
    #                 break
    #             s += 1
    #         pv = (len(train_mal)-s)/len(train_mal)
    #     else:
    #         for train_sc in train_ben:
    #             if train_sc < test_scores[i]:
    #                 break
    #             s += 1
    #         pv = s/len(train_ben)
    #     pv_list.append(pv)
    # return pv_list

    pv_list = list()
    len_train_mal = len(train_mal)
    len_train_ben = len(train_ben)
    c_train_m = 0
    for c_test_m in range(len(test_mal)):
        while c_train_m < len_train_mal and test_mal[c_test_m] < train_mal[c_train_m]:
            c_train_m += 1
        pv_list.append((len_train_mal-c_train_m)/len_train_mal)
    c_train_b = 0
    for c_test_b in range(len(test_ben)):
        while c_train_b < len_train_ben and test_ben[c_test_b] <= train_ben[c_train_b]:
            c_train_b += 1
        pv_list.append(c_train_b/len_train_ben)
    return pv_list

def cal_IP_pValue(sus_train, biggest_score):
    """
    :param train: 训练集中可疑访问得分
    :param sample_score: 10个危险IP最高的异常得分
    :return: p_value
    """
    pv_list = list()
    for test_sc in biggest_score:
        s = 0
        for train_sc in sus_train:
            if train_sc <= test_sc:
                break
            s += 1
        pv = (len(sus_train)-s)/len(sus_train)
        pv_list.append(pv)
    return pv_list


if __name__ == "__main__":
    pyod_train(ABOD_clf, "ABOD")
    # pyod_predict(HBOS_clf, "HBOS")
