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
from feature2 import FeatureExtraction as FeatureExtraction2




# Load the model during app startup
with open("pickle/model.pkl", "rb") as file:
    file = open("pickle/model.pkl","rb")
    gbc = pickle.load(file)
    file.close()



app = Flask(__name__)

@app.route("/", methods=["POST"])
def index():

    url = request.args.get("url")
    obj= FeatureExtraction2(url)
  

    if(obj.features == []):
        return f"N/A, {url}"
    x = np.array(obj.getFeaturesList()).reshape(1,30) 
    final_URL = obj.getFinalURL()
    print(final_URL)

    y_pred =gbc.predict(x)[0]
    print(y_pred)
    # 1 is not phishing       
    # -1 is phishing
    y_pro_phishing = gbc.predict_proba(x)[0,0]
    y_pro_non_phishing = gbc.predict_proba(x)[0,1]
    gc.collect()
    #print(y_pro_phishing)
    #print(y_pro_non_phishing)
    # if(y_pred == 1 ):
    pred = "{0:.2f}%".format(y_pro_non_phishing*100)

    response_str = f"{pred}, {final_URL}"
    return response_str
    


if __name__ == "__main__":
    app.run(port=8080, debug=True)