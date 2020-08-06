# -*- coding: utf-8 -*-
"""Single-Objective Generative Adversarial Active Learning.
Part of the codes are adapted from
https://github.com/leibinghe/GAAL-based-outlier-detection
"""
# Author: Winston Li <jk_zhengli@hotmail.com>
# License: BSD 2 clause

from __future__ import division
from __future__ import print_function

from collections import defaultdict

import numpy as np
import pickle
from keras.layers import Input
from keras.models import Model
from keras.optimizers import SGD
from keras.models import load_model

from sklearn.utils import check_array
from sklearn.utils.validation import check_is_fitted

from .base import BaseDetector
from .gaal_base import create_discriminator
from .gaal_base import create_generator


class SO_GAAL(BaseDetector):
    """Single-Objective Generative Adversarial Active Learning.

    SO-GAAL directly generates informative potential outliers to assist the
    classifier in describing a boundary that can separate outliers from normal
    data effectively. Moreover, to prevent the generator from falling into the
    mode collapsing problem, the network structure of SO-GAAL is expanded from
    a single generator (SO-GAAL) to multiple generators with different
    objectives (MO-GAAL) to generate a reasonable reference distribution for
    the whole dataset.
    Read more in the :cite:`liu2019generative`.

    Parameters
    ----------
    contamination : float in (0., 0.5), optional (default=0.1)
        The amount of contamination of the data set, i.e.
        the proportion of outliers in the data set. Used when fitting to
        define the threshold on the decision function.

    stop_epochs : int, optional (default=20)
        The number of epochs of training.

    lr_d : float, optional (default=0.01)
        The learn rate of the discriminator.

    lr_g : float, optional (default=0.0001)
        The learn rate of the generator.

    decay : float, optional (default=1e-6)
        The decay parameter for SGD.

    momentum : float, optional (default=0.9)
        The momentum parameter for SGD.

    Attributes
    ----------
    decision_scores_ : numpy array of shape (n_samples,)
        The outlier scores of the training data.
        The higher, the more abnormal. Outliers tend to have higher
        scores. This value is available once the detector is fitted.

    threshold_ : float
        The threshold is based on ``contamination``. It is the
        ``n_samples * contamination`` most abnormal samples in
        ``decision_scores_``. The threshold is calculated for generating
        binary outlier labels.

    labels_ : int, either 0 or 1
        The binary labels of the training data. 0 stands for inliers
        and 1 for outliers/anomalies. It is generated by applying
        ``threshold_`` on ``decision_scores_``.
    """

    def __init__(self, stop_epochs=20, lr_d=0.01, lr_g=0.0001,
                 decay=1e-6, momentum=0.9, contamination=0.1):
        super(SO_GAAL, self).__init__(contamination=contamination)
        self.stop_epochs = stop_epochs
        self.lr_d = lr_d
        self.lr_g = lr_g
        self.decay = decay
        self.momentum = momentum

    def fit(self, X, y=None):
        """Fit detector. y is ignored in unsupervised methods.

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The input samples.

        y : Ignored
            Not used, present for API consistency by convention.

        Returns
        -------
        self : object
            Fitted estimator.
        """
        X = check_array(X)
        self._set_n_classes(y)
        latent_size = X.shape[1]
        data_size = X.shape[0]
        stop = 0
        epochs = self.stop_epochs * 3
        self.train_history = defaultdict(list)

        self.discriminator = create_discriminator(latent_size, data_size)
        self.discriminator.compile(
            optimizer=SGD(lr=self.lr_d, decay=self.decay,
                          momentum=self.momentum), loss='binary_crossentropy')

        self.generator = create_generator(latent_size)
        latent = Input(shape=(latent_size,))
        fake = self.generator(latent)
        self.discriminator.trainable = False
        fake = self.discriminator(fake)
        self.combine_model = Model(latent, fake)
        self.combine_model.compile(
            optimizer=SGD(lr=self.lr_g, decay=self.decay,
                          momentum=self.momentum), loss='binary_crossentropy')

        # Start iteration
        for epoch in range(epochs):
            print('Epoch {} of {}'.format(epoch + 1, epochs))
            batch_size = min(500, data_size)
            num_batches = int(data_size / batch_size)

            for index in range(num_batches):
                # print('\nTesting for epoch {} index {}:'.format(epoch + 1,
                #                                                 index + 1))

                # Generate noise
                noise_size = batch_size
                noise = np.random.uniform(0, 1, (int(noise_size), latent_size))

                # Get training data
                data_batch = X[index * batch_size: (index + 1) * batch_size]

                # Generate potential outliers
                generated_data = self.generator.predict(noise, verbose=0)

                # Concatenate real data to generated data
                x = np.concatenate((data_batch, generated_data))
                y = np.array([1] * batch_size + [0] * int(noise_size))

                # Train discriminator
                discriminator_loss = self.discriminator.train_on_batch(x, y)
                self.train_history['discriminator_loss'].append(
                    discriminator_loss)

                # Train generator
                if stop == 0:
                    trick = np.array([1] * noise_size)
                    generator_loss = self.combine_model.train_on_batch(noise,
                                                                       trick)
                    self.train_history['generator_loss'].append(generator_loss)
                else:
                    trick = np.array([1] * noise_size)
                    generator_loss = self.combine_model.evaluate(noise, trick)
                    self.train_history['generator_loss'].append(generator_loss)

            # Stop training generator
            if epoch + 1 > self.stop_epochs:
                stop = 1

        # Detection result
        self.decision_scores_ = self.discriminator.predict(X)
        self._process_decision_scores()
        return self

    def save(self, add):
        self.discriminator.save("{}.h5".format(add))
        np.savez("{}_info.npz".format(add), label=self.labels_, threshold=self.threshold_, score=self.decision_scores_)

    def read(self, add, n_sam, n_fea):
        self.discriminator = load_model("{}.h5".format(add))
        info = np.load("{}_info.npz".format(add))
        self.labels_ = info['label']
        self.threshold_ = info['threshold']
        self.decision_scores_ = info['score']


    def decision_function(self, X):
        """Predict raw anomaly score of X using the fitted detector.

        The anomaly score of an input sample is computed based on different
        detector algorithms. For consistency, outliers are assigned with
        larger anomaly scores.

        Parameters
        ----------
        X : numpy array of shape (n_samples, n_features)
            The training input samples. Sparse matrices are accepted only
            if they are supported by the base estimator.

        Returns
        -------
        anomaly_scores : numpy array of shape (n_samples,)
            The anomaly score of the input samples.
        """
        check_is_fitted(self, ['discriminator'])
        X = check_array(X)
        pred_scores = self.discriminator.predict(X)
        return pred_scores
