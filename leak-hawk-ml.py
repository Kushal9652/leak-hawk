import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
import joblib

# 1. Load dataset
df = pd.read_csv("leakhawk_dataset.csv")

# 2. Encode target labels
label_encoder = LabelEncoder()
df['Leak_Type_Encoded'] = label_encoder.fit_transform(df['Leak_Type'])

# 3. Features & target
X = df[['Data_Snippet', 'Pattern_Matched', 'Risk_Score', 'Anomaly_Flag']]
y = df['Leak_Type_Encoded']

# 4. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 5. Preprocessing
preprocessor = ColumnTransformer(
    transformers=[
        ('text', TfidfVectorizer(max_features=5000, ngram_range=(1, 2)), 'Data_Snippet'),
        ('cat', OneHotEncoder(handle_unknown='ignore'), ['Pattern_Matched', 'Anomaly_Flag']),
        ('num', 'passthrough', ['Risk_Score'])
    ]
)

# 6. Model
model = XGBClassifier(
    eval_metric='mlogloss',
    use_label_encoder=False,
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8
)

# 7. Pipeline
pipeline = Pipeline([
    ('preprocessor', preprocessor),
    ('classifier', model)
])

# 8. Train
pipeline.fit(X_train, y_train)

# 9. Evaluate
y_pred = pipeline.predict(X_test)
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# 10. Save model & label encoder
joblib.dump(pipeline, "leakhawk_model.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
print("✅ Model saved as leakhawk_model.pkl")
print("✅ Label encoder saved as label_encoder.pkl")
