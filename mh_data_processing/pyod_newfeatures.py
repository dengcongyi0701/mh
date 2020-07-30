# -*- coding: utf-8 -*-
"""
Created on 2020/7/29 14:37

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


begin = "2020-02-13"
end = "2020-02-15"
test_date = "2020-02-16"

KNN_clf = KNN(contamination=0.05)
PCA_clf = PCA(contamination=0.05, n_components=0.9)
VAE_clf = VAE(contamination=0.05, epochs=50, gamma=0.8, capacity=0.2, encoder_neurons=[9, 4], decoder_neurons=[4, 9])
LOF_clf = LOF(contamination=0.01)
IForest_clf = IForest(contamination=0.05)
FeatureBagging_clf = FeatureBagging(contamination=0.05, check_estimator=False)
SO_GAAL_clf = SO_GAAL(contamination=0.05, stop_epochs=20)

S_models = []

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

    print("————————————{} training————————————".format(name))
    clf.fit(x_train)

    if name in S_models:
        with open('M:\mh_data\model\{}.pkl'.format(name), 'wb') as f:
            pickle.dump(clf, f)
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
    y_test_pred = clf.predict(x_test)
    y_test_scores = clf.decision_function(x_test)

    df_test.insert(0, 'label', y_test_pred)
    df_test.insert(0, 'score', y_test_scores)
    df_test = df_test.sort_values(by='score', ascending=False)
    top10 = df_test[['src_IP', 'time', 'score']][:10]
    print("\nTen most suspicious IP in test set:")
    print(top10)

    sus_test = df_test[df_test.label == 1]
    sus_test = sus_test[['src_IP', 'score']]
    a = sus_test.groupby('src_IP').count().sort_values(by='score', ascending=False)
    print(a)


if __name__ == "__main__":
    pyod_predict(VAE_clf, "VAE")