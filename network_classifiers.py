# Importing Standard Libraries
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import json

# Importing Sci-kit Learn Libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Importing Deep Learning Libraries
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense
from keras.layers import LSTM
from keras.models import load_model

# Load NetFlow Dataset
netflow_dataset = pd.read_csv("netflow.csv")

# Dropping Irrelevant and Biased Features
def drop_features(dataset):
    features = ['exaddr', 'engine_type', 'engine_id', 'src_mask', 'dst_mask', 'src_as', 'dst_as', '#:unix_secs', 'unix_nsecs', 'sysuptime','first', 'last', 'nexthop', 'srcaddr', 'dstaddr', 'input', 'output']
    dataset.drop(columns=features, inplace=True)

# Normalise Train Features
def norm_train_features(scaler, features):
    norm_train = scaler.fit_transform(features)
    return norm_train

# Normalise Test Features
def norm_test_features(scaler, features):
    norm_test = scaler.transform(features)
    return norm_test

# XGBoost Classifier
def XGB_model(train_feat, train_labels):
    xgb = XGBClassifier(alpha=0.1, base_score=0.5, booster='gblinear', learning_rate=0.1, eval_metric='rmse', n_estimators=100)
    xgb.fit(train_feat, train_labels)
    joblib.dump(xgb, 'netflow_xgb_model.pkl')
    return xgb

# LinearSVC Classifier
def SVM_model(train_feat, train_labels):
    svm = LinearSVC(C=1.0, loss='squared_hinge', penalty='l2')
    svm.fit(train_feat, train_labels)
    joblib.dump(svm, 'netflow_svm_model.pkl')
    return svm

# RandomForest Classifier
def RF_model(train_feat, train_labels):
    rf = RandomForestClassifier(criterion='gini',max_depth=1,max_features='auto',max_leaf_nodes=2,min_samples_leaf=2,min_samples_split=0.1,min_weight_fraction_leaf=0.1,n_estimators=80)  
    rf.fit(train_feat, train_labels)
    joblib.dump(rf, 'netflow_rf_model.pkl')
    return rf

# Naive Bayes Classifier
def NB_model(train_feat, train_labels):
    nb = GaussianNB()
    nb.fit(train_feat, train_labels)
    joblib.dump(nb, 'netflow_nb_model.pkl')
    return nb

# Calculating Evaluation Metrics
def eval_metrics(test_labels,test_pred):
    print("--- Evaluating Classifier Performance Metrics ---\n")
    overall_accuracy = accuracy_score(test_labels,test_pred)
    overall_precision = precision_score(test_labels,test_pred)
    overall_recall = recall_score(test_labels,test_pred)
    overall_f1 = f1_score(test_labels,test_pred)

    print("Overall Accuracy: "+ str(overall_accuracy * 100.0))
    print("Overall Precision: "+ str(overall_precision * 100.0))
    print("Overall Recall: "+ str(overall_recall * 100.0))
    print("Overall F1 Score: "+ str(overall_f1 * 100.0))

    conf_mat = confusion_matrix(test_labels, test_pred)
    TN, FP, FN, TP = conf_mat.ravel()

    # Malicious Class Metrics
    mal_accuracy = (TP + TN) / (TP + TN + FP + FN)
    mal_precision = TP / (TP + FP)
    mal_recall = TP / (TP + FN)
    mal_f1 = 2 * (mal_precision * mal_recall) / (mal_precision + mal_recall)

    # Benign Class Metrics
    benign_accuracy = (TP + TN) / (TP + TN + FP + FN)
    benign_precision = TN / (TN + FN)
    benign_recall = TN / (TN + FP)
    benign_f1 = 2 * (benign_precision * benign_recall) / (benign_precision + benign_recall)

    # FPR for Both Classes
    mal_FPR = FP / (FP + TN)
    benign_FPR = FN / (FN + TP)

    print("For Class 1 (Malicious):")
    print("Accuracy: " + str(mal_accuracy * 100.0))
    print("Precision: " + str(mal_precision * 100.0))
    print("Recall: " + str(mal_recall * 100.0))
    print("F1 Score: " + str(mal_f1 * 100.0))
    print("FPR (Malicious): " + str(mal_FPR))

    print("For Class 0 (Benign):")
    print("Accuracy: " + str(benign_accuracy * 100.0))
    print("Precision: " + str(benign_precision * 100.0))
    print("Recall: " + str(benign_recall * 100.0))
    print("F1 Score: " + str(benign_f1 * 100.0))
    print("FPR (Benign): " + str(benign_FPR))

    report = classification_report(test_labels, test_pred)
    print("Classification Report: \n" + str(report))
    print("\nConfusion Matrix:")
    print(conf_mat)

# Get Test Predictions
def get_testpredictions(model,test_feat):
    test_predictions = model.predict(test_feat)
    return test_predictions

# Drop features
drop_features(netflow_dataset)

# Separating Labels
features = netflow_dataset.drop('Label', axis=1)
labels = netflow_dataset['Label']

# Split into train and test sets
train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size=0.3, random_state=42)

# View  number of malicious and benign data in the testing split
test_counts = test_labels.value_counts()
print("\nTesting Data:")
print("Number of Malicious Samples:", test_counts[1])
print("Number of Benign Samples:", test_counts[0])

# View  number of malicious and benign data in the training split
train_counts = train_labels.value_counts()
print("\nTraining Data:")
print("Number of Malicious Samples:", train_counts[1]) 
print("Number of Benign Samples:", train_counts[0]) 

# Normalising Training Data
scaler = StandardScaler()
norm_train_feat = norm_train_features(scaler,train_features)

# Normalising Testing Data
norm_test_feat = norm_test_features(scaler,test_features)

# Reshaping Features for DL Models
train_features = norm_train_feat.reshape(train_features.shape[0], train_features.shape[1], 1)
test_features = norm_test_feat.reshape(test_features.shape[0], test_features.shape[1], 1)

# CNN model
# model = Sequential()
# model.add(Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(train_features.shape[1], 1)))
# model.add(MaxPooling1D(pool_size=2))
# model.add(Flatten())  # You need to flatten the data before passing it to the dense layer
# model.add(Dense(1, activation='sigmoid'))

# LSTM Model
# model = Sequential()
# model.add(LSTM(100, input_shape=(train_features.shape[1], 1), dropout=0.2, recurrent_dropout=0.2))
# model.add(Dense(1, activation='sigmoid'))

# CNN-LSTM Model
model = Sequential()
model.add(Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(train_features.shape[1], 1)))
model.add(MaxPooling1D(pool_size=2))
model.add(LSTM(100, input_shape=(train_features.shape[1], 1), dropout=0.2, recurrent_dropout=0.2))
model.add(Dense(1, activation='sigmoid'))

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
training_process = model.fit(train_features, train_labels, epochs=20, batch_size=32, validation_split=0.2)

# Evaluate the model
test_loss, test_accuracy = model.evaluate(test_features, test_labels)
print("Test Accuracy: ", test_accuracy)

# Predict
test_pred = (model.predict(test_features) > 0.5).astype("int32")

# Use your existing eval_metrics function
eval_metrics(test_labels, test_pred)

model.save("netflow_cnnlstm.h5")
joblib.dump(scaler, 'netflow_scaler.pkl')

# Calculating Training and Validation Accuracy
training_accuracy = training_process.history['accuracy']
validation_accuracy = training_process.history['val_accuracy']

# Plotting Accuracy 
plt.figure(figsize=(8,5))
plt.plot(training_accuracy,'b-', label='Training Accuracy')
plt.plot(validation_accuracy,'r-', label='Validation Accuracy')
plt.title('Model Accuracy')
plt.ylabel('Accuracy')
plt.xlabel('Epochs')
plt.legend()
plt.tight_layout()
plt.show()

# Calculating Training and Validation Loss
training_loss = training_process.history['loss']
validation_loss = training_process.history['val_loss']

# Plotting Loss
plt.figure(figsize=(8,5))
plt.plot(training_loss,'b-', label='Training Lccuracy')
plt.plot(validation_loss,'r-', label='Validation Accuracy')
plt.title('Model Loss')
plt.ylabel('Loss')
plt.xlabel('Epoch')
plt.legend()
plt.tight_layout()
plt.show()

# Confusion Matrix Display
conf_matrix = confusion_matrix(test_labels, test_pred)
display = ConfusionMatrixDisplay(confusion_matrix=conf_matrix, display_labels=[0,1])
display.plot(cmap=plt.cm.Blues)
plt.show()