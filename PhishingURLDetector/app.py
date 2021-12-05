import feature
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
#from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier


data = pd.read_csv("dataset.csv")
data = data.drop(["index","port","Abnormal_URL","popUpWidnow","Statistical_report"],axis=1).copy()
data = data.sample(frac=1).reset_index(drop=True)

print(feature.url)

y = data["Result"].values
X = data.drop(["Result"],axis=1)
X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.2,random_state=12)

#model = LogisticRegression(max_iter=1000)
model = RandomForestClassifier()
model.fit(X_train, np.ravel(y_train, order='C'))

y_predict = model.predict([[feature.urlfeatures.having_IPhaving_IP_Address(),
feature.urlfeatures.URLURL_Length(),
feature.urlfeatures.Shortining_Service(),
feature.urlfeatures.having_At_Symbol(),
feature.urlfeatures.double_slash_redirecting(),
feature.urlfeatures.Prefix_Suffix(),
feature.urlfeatures.having_Sub_Domain(),
feature.urlfeatures.SSLfinal_State(),
feature.urlfeatures.Domain_registeration_length(),
feature.urlfeatures.favicon(),
feature.urlfeatures.HTTPS_token(),
feature.urlfeatures.Request_URL(),
feature.urlfeatures.URL_of_Anchor(),
feature.urlfeatures.Links_in_tags(),
feature.urlfeatures.SFH(),
feature.urlfeatures.Submitting_to_email(),
feature.urlfeatures.Redirect(),
feature.urlfeatures.on_mouseover(),
feature.urlfeatures.RightClick(),
feature.urlfeatures.Iframe(),
feature.urlfeatures.age_of_domain(),
feature.urlfeatures.DNSRecord(),
feature.urlfeatures.web_traffic(),
feature.urlfeatures.Page_Rank(),
feature.urlfeatures.Google_Index(),
feature.urlfeatures.Links_pointing_to_page()]])

print(y_predict)
if y_predict == -1:
    print("phishing")
    import block
    block
    
else:
   print("legitimate Website.")