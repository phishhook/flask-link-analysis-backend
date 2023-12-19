## Installation
The Code is written in Python 3.9.6 If you don't have Python installed you can find it [here](https://www.python.org/downloads/). If you are using a lower version of Python you can upgrade using the pip package, ensuring you have the latest version of pip. To install the required packages and libraries, run this command in the project directory after [cloning](https://www.howtogeek.com/451360/how-to-clone-a-github-repository/) the repository:
```bash
pip install -r requirements.txt
```

<br>

## Start Server
```bash
python3 app,py
```


<br>
<br>

## Results

||ML Model|	Accuracy|  	f1_score|	Recall|	Precision|
|---|---|---|---|---|---|
0|	Gradient Boosting Classifier|	0.974|	0.977|	0.994|	0.986|
1|	CatBoost Classifier|	        0.972|	0.975|	0.994|	0.989|
2|	Random Forest|	                0.967|	0.971|	0.993|	0.990|
3|	Decision Tree|      	        0.960|	0.964|	0.991|	0.993|
4|	K-Nearest Neighbors|        	0.956|	0.961|	0.991|	0.989|
5|	Logistic Regression|        	0.934|	0.941|	0.943|	0.927|
6|	Naive Bayes Classifier|     	0.605|	0.454|	0.292|	0.997|
