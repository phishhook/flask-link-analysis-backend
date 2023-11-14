#importing required libraries

from contextlib import nullcontext
import gc
from flask import Flask, request
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature_extractor import extract_features

import time




# Load the model during app startup
with open("pickle/model2.pkl", "rb") as file:
    file = open("pickle/model2.pkl","rb")
    gbc = pickle.load(file)
    file.close()



app = Flask(__name__)

@app.route("/", methods=["POST"])
def index():

    url = request.args.get("url")
    obj = extract_features(url)
    x = obj
    if x is None:
        return "N/A"
    x = np.array(obj).reshape(1,87) 

    y_pred =gbc.predict(x)[0]
    print(y_pred)
    #0 is safe       
    #1 is unsafe
    y_pro_safe = gbc.predict_proba(x)[0,0]
    y_pro_unsafe = gbc.predict_proba(x)[0,1]
    gc.collect()
    #print(y_pro_phishing)
    #print(y_pro_non_phishing)
    # if(y_pred ==1 ):
    ##pred = "It is {0:.2f} % safe to go ".format(y_pro_safe*100)
    pred = "{0:.2f}%".format(y_pro_safe*100)
    return pred
    


if __name__ == "__main__":
    app.run(port=8000,debug=True)