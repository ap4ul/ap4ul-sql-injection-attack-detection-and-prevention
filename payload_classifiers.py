# Classifier Imports
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.naive_bayes import MultinomialNB
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Removing TensorFlow Warnings
import os
os.environ['CUDA_VISIBLE_DEVICES'] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2" 

# Disabling Standard Warnings
import warnings
warnings.filterwarnings('always')

"""
*****************
*****************

PURPOSE: Importing Libraries for Neural Network Models
REFERENCE: https://machinelearningmastery.com/develop-word-embedding-model-predicting-movie-review-sentiment/

*****************
*****************
"""
from keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential 
from keras.layers import Dense
from keras.layers import LSTM
from keras.layers.core import SpatialDropout1D
from keras.layers import Flatten
from keras.layers import Embedding
from keras.layers import GlobalMaxPooling1D
from keras.layers import Dropout
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D

# Importing Standard Libraries
import pandas as pd
import numpy as np
import pickle

# Importing Feature Extraction for Traditional Models
from sklearn.feature_extraction.text import TfidfVectorizer

# Importing Training & Evaluation Metrics
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

# SVM Classifier
def svm_classifier(x_train,y_train):
    print("--- Training  SVM Classifier ---\n")
    svm_model = SVC(C=10, gamma=1, kernel='linear')
    svm_model.fit(x_train,y_train)

    # Saving SVM Model
    with open("svm_model.pkl", "wb") as f:
        pickle.dump(svm_model, f)

    return svm_model

# Random Forest Classifier
def rf_classifier(x_train,y_train):

    print("--- Training Random Forest Classifier ---\n")
    rf_model = RandomForestClassifier(random_state=137)
    rf_model.fit(x_train,y_train)

    # Saving Random Forest Model
    with open("rf_model.pkl", "wb") as f:
        pickle.dump(rf_model, f)

    return rf_model

# XGB Classifier
def xgb_classifier(x_train,y_train):

    print("--- Training XGBoost Classifier --\n")
    xgb_model = XGBClassifier(max_depth=8,n_estimators=180, nthread=4, objective='multi:softmax')
    xgb_model.fit(x_train, y_train)

    # Saving XGBoost Model
    with open("xgb_model.pkl", "wb") as f:
        pickle.dump(xgb_model, f)

    return xgb_model

# Naive Bayes Classifier
def nb_classifier(x_train,y_train):

    print("--- Training Naive Bayes Classifier --\n")
    nb_model = MultinomialNB()
    nb_model.fit(x_train,y_train)

    # Saving Naive Bayes Model
    with open("nb_model.pkl", "wb") as f:
       pickle.dump(nb_model, f)

    return nb_model

# Loading Relevant Datasets
def load_datasets():
    print("--- Loading the Datasets ---\n")
    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/auth-bypass.txt', 'r') as authbypass_file:
        auth_bypass = authbypass_file.readlines()

    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/blind-sqli.txt', 'r') as blindsqli_file:
        blind_sqli = blindsqli_file.readlines()
    
    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/DoS.txt', 'r') as dossqli_file:
        dos_sqli = dossqli_file.readlines()

    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/in_band.txt', 'r') as inband_file:
        inband_sqli = inband_file.readlines()
    
    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/rce.txt', 'r') as rcesqli_file:
        rce_sqli = rcesqli_file.readlines()

    with open('/home/kali/sql-injection-attack-detection-and-prevention/datasets/multiclass/norm.txt', 'r') as normal_text:
        benign_text = normal_text.readlines()

    """
    *****************
    *****************

    PURPOSE: Labelling Dataset Payloads
    REFERENCE: https://sparkbyexamples.com/pandas/pandas-concat-dataframes-explained/

    *****************
    *****************
    """
    authbypass_df = pd.DataFrame({'data':auth_bypass,'label' : 0})
    blind_df = pd.DataFrame({'data':blind_sqli,'label' : 1})
    dos_df = pd.DataFrame({'data':dos_sqli,'label' : 2})
    inband_df = pd.DataFrame({'data':inband_sqli,'label' : 3})
    rce_df = pd.DataFrame({'data':rce_sqli,'label' : 4})
    benign_df = pd.DataFrame({'data':benign_text,'label' : 5})
    data = [authbypass_df, blind_df, dos_df, inband_df, rce_df, benign_df]
    df_concat = pd.concat(data, ignore_index=True, sort=False)
    df_concat['data'] = df_concat['data'].str.replace('\n', '')
    df_concat['data'] = [entry.lower() for entry in df_concat['data']]
    print(df_concat)
    print("--- Datasets Successfully Loaded ---\n")
    
    return df_concat

# Feature Extraction - TF-IDF
def tfidf_vect(dframe):
    
    print("--- Data Feature Extraction - TF IDF Vectorizer ---\n")
    vect = TfidfVectorizer()
    data = vect.fit_transform(dframe['data'])
    label = dframe['label']
    print("--- Feature Extraction Successful ---\n")

    # Saving Vectorizer - Uncomment to save TF-IDF vectorizer
    with open("vectorizer.pkl", "wb") as f:
       pickle.dump(vect, f)

    return data,label

# Implementing Evaluation Metrics
def eval_metrics(pred, label_test):

    print("--- Evaluating Classifier Performance Metrics ---\n")
    overall_accuracy = accuracy_score(label_test,pred)
    overall_precision = precision_score(label_test,pred, average='weighted')
    overall_recall = recall_score(label_test,pred, average='weighted')
    overall_f1 = f1_score(label_test,pred,average='weighted')

    print("Accuracy: "+ str(overall_accuracy * 100.0))
    print("Precision: "+ str(overall_precision * 100.0))
    print("Recall: "+ str(overall_recall * 100.0))
    print("F1 Score: "+ str(overall_f1 * 100.0))

    conf_mat = confusion_matrix(label_test, pred)
    report = classification_report(label_test, pred)
    TP = np.diag(conf_mat)
    FP = conf_mat.sum(axis=0) - TP
    FN = conf_mat.sum(axis=1) - TP
    TN = conf_mat.sum() - (FP + FN + TP)
    accuracy = (TP + TN) / (TP + TN + FP + FN)
    precision = TP / (TP + FP + 1e-10)
    recall = recall_score(label_test, pred, average=None)
    f1 = f1_score(label_test, pred, average=None)
    FPR = FP / (FP + TN + 1e-10)

    for i, (acc, prec, rec, f1_sc, fpr) in enumerate(zip(accuracy, precision, recall, f1, FPR)):
        print("Class: "+ str(i))
        print("Accuracy : " + str(acc * 100.0))
        print("Precision : " + str(prec * 100.0))
        print("Recall : " + str(rec * 100.0))
        print("F1 Score : " + str(f1_sc * 100.0))
        print("False Positive Rate : " + str(fpr))
    
    print("Classification Report: " + str(report))
    overall_fpr = FP.sum() / (FP.sum() + TN.sum() + 1e-10)
    print("Overall FPR:" + str(overall_fpr))
    print(conf_mat)

# Counting Train and Test Split Classes Count
def traintestsplit_count(label_train, label_test):
    train_class_counts = {}
    test_class_counts = {}

    # Training Split Class Count
    for label in label_train:
        if label in train_class_counts:
            train_class_counts[label] += 1
        else:
            train_class_counts[label] = 1

    # Testing Split Class Count
    for label in label_test:
        if label in test_class_counts:
            test_class_counts[label] += 1
        else:
            test_class_counts[label] = 1

    print("Class counts in train split:", train_class_counts)
    print("Class counts in test split:", test_class_counts)


"""
*****************
*****************

PURPOSE: Loading GloVe
REFERENCE: https://anakin297.medium.com/multi-class-text-classification-using-cnn-and-word2vec-b17daff45260
           https://github.com/ML2021/TF-RNN-CNN-text-processing/blob/main/Multi%20Class%20Text%20Classification%20word2vec%20using%20CNN.ipynb
*****************
*****************
"""
def load_glove():
    word_dict = {}
    with open(os.path.join('glove.6B/glove.6B.%sd.txt' % 100),encoding="utf8") as glove_file:
        for line in glove_file:
            values = line.split()
            word = values[0]
            vec = np.asarray(values[1:], dtype='float32')
            word_dict[word] = vec
    return word_dict

"""
*****************
*****************

PURPOSE: Feature Extraction and Classification
REFERENCE: https://anakin297.medium.com/multi-class-text-classification-using-cnn-and-word2vec-b17daff45260
           https://github.com/ML2021/TF-RNN-CNN-text-processing/blob/main/Multi%20Class%20Text%20Classification%20word2vec%20using%20CNN.ipynb
*****************
*****************
"""
def training_model():

    df = load_datasets()

    # data, label = tfidf_vect(df)

    word2vec = load_glove()
       
    # CNN Preprocessing and Feature Extraction
    payloads = df['data']
    label = df['label']
    tokenizer = Tokenizer()
    tokenizer.fit_on_texts(payloads)
    encoded_payloads = tokenizer.texts_to_sequences(payloads)
    index = tokenizer.word_index
    
    # Saving Tokenizer
    with open("tokenizer.pickle", "wb") as tokenizer_file:
        pickle.dump(tokenizer, tokenizer_file)

    
    """
    *****************
    *****************

    PURPOSE: Word Embedding Vectorization
    REFERENCE: https://anakin297.medium.com/multi-class-text-classification-using-cnn-and-word2vec-b17daff45260
               https://github.com/ML2021/TF-RNN-CNN-text-processing/blob/main/Multi%20Class%20Text%20Classification%20word2vec%20using%20CNN.ipynb
    *****************
    *****************
    """
    embedding_dimension = 100
    matrix = np.zeros((len(index) + 1, embedding_dimension))
    for word, i in index.items():
        embedding_vector = word2vec.get(word)
        if embedding_vector is not None:
            matrix[i] = embedding_vector
    
    max_sequence_length = max(len(s) for s in encoded_payloads)
    data = pad_sequences(encoded_payloads,  maxlen=max_sequence_length)

    # Splitting Training and Testing Data
    print("--- Splitting Training and Testing Data ---\n")
    data_train, data_test, label_train, label_test = train_test_split(data,label,test_size=0.40,stratify=label,random_state=3)
    traintestsplit_count(label_train, label_test)
    
    """
    *****************
    *****************

    PURPOSE: Word Embedding Vectorization
    REFERENCE: https://realpython.com/python-keras-text-classification/

    *****************
    *****************
    """
    # UNCOMMENT TO TRAIN CNN MODEL
    # model = Sequential()
    # model.add(Embedding(len(index) + 1, embedding_dimension,weights=[matrix], input_length=max_sequence_length, trainable=False))
    # model.add(Conv1D(64, 5, activation='relu'))
    # model.add(GlobalMaxPooling1D())
    # model.add(Dense(64, activation='relu'))
    # model.add(Dropout(0.5))
    # model.add(Dense(6, activation='softmax'))

    # UNCOMMENT TO TRAIN LSTM MODEL
    # model = Sequential()
    # model.add(Embedding(len(index) + 1, embedding_dimension,weights=[matrix], input_length=max_sequence_length))
    # model.add(SpatialDropout1D(0.2))
    # model.add(LSTM(100, dropout=0.2, recurrent_dropout=0.2))
    # model.add(Dense(6, activation='softmax'))

    model = Sequential()
    model.add(Embedding(len(index) + 1, embedding_dimension,weights=[matrix], input_length=max_sequence_length))
    model.add(SpatialDropout1D(0.2))
    model.add(Conv1D(128, 5, activation='relu'))
    model.add(MaxPooling1D(pool_size=2))
    model.add(LSTM(100, dropout=0.5, recurrent_dropout=0.2))
    model.add(Dense(6, activation='softmax'))

    # CNN Training and Evaluation
    model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    training_process = model.fit(data_train, label_train, epochs=10, validation_data=(data_test, label_test), batch_size=64)
    loss, accuracy = model.evaluate(data_test, label_test)
    print('Accuracy: ' + str(accuracy*100))
    y_pred1 = model.predict(data_test)
    y_pred = np.argmax(y_pred1, axis=1)
    eval_metrics(y_pred,label_test)
    model.save("second_cnn_lstm_model.h5")

    # Calculating Training and Validation Loss
    training_loss = training_process.history['loss']
    validation_loss = training_process.history['val_loss']

    # Defining the Epochs Range
    epochs = range(1, len(training_loss) + 1)

    # Plotting Losses
    plt.figure(figsize=(10,5))
    plt.plot(epochs, training_loss, 'b-', label='Training loss')
    plt.plot(epochs, validation_loss, 'r-', label='Validation loss')
    plt.title('Training and Validation Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend()
    plt.show()

    # Calculating Training and Validation Accuracy
    training_accuracy = training_process.history['accuracy']
    validation_accuracy = training_process.history['val_accuracy']

    # Defining the Epochs Range
    epochs = range(1, len(training_accuracy) + 1)

    # Plotting Accuracies
    plt.figure(figsize=(10, 5))
    plt.plot(epochs, training_accuracy, 'b-', label='Training Accuracy')
    plt.plot(epochs, validation_accuracy, 'r-', label='Validation Accuracy')
    plt.title('Training and Validation Accuracy')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.show()

    # Confusion Matrix Display
    conf_matrix = confusion_matrix(label_test, y_pred)
    display = ConfusionMatrixDisplay(confusion_matrix=conf_matrix)
    display.plot(cmap=plt.cm.Blues)
    plt.show()

training_model()