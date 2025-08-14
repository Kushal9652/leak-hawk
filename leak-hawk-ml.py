import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import joblib

# 1. Load dataset
df = pd.read_csv("leakhawk_dataset.csv")

# 2. Check columns
print("Columns:", df.columns)

# Assume:
# 'text' -> leak content
# 'label' -> leak type (or 0/1 for non-leak/leak)
if 'text' not in df.columns or 'label' not in df.columns:
    raise ValueError("CSV must contain 'text' and 'label' columns.")

# 3. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    df['text'], df['label'],
    test_size=0.2,
    random_state=42
)

# 4. Create pipeline
model_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1,2))),
    ('clf', LogisticRegression(max_iter=1000))
])

# 5. Train model
model_pipeline.fit(X_train, y_train)

# 6. Evaluate
y_pred = model_pipeline.predict(X_test)
print(classification_report(y_test, y_pred))

# 7. Save model
joblib.dump(model_pipeline, "leakhawk_model.pkl")
print("✅ Model saved as leakhawk_model.pkl")
