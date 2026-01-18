import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split

# Load the training data
TRAIN_PATH = r"X:\AI_TI_ENGINE\data\processed\splits\train.csv"
df = pd.read_csv(TRAIN_PATH)

# Features and labels
X = df.drop(columns=["label"])
y = df["label"]

# Train/test split (using 20% of data for validation)
X_train, X_val, y_train, y_val = train_test_split(
    X, y,
    test_size=0.2,  # 20% for validation
    random_state=42,
    stratify=y  # Keep label distribution the same in both train and val
)

# Create and train the Random Forest model
rf_model = RandomForestClassifier(random_state=42)
rf_model.fit(X_train, y_train)

# Predict on validation set
y_pred = rf_model.predict(X_val)

# Confusion matrix
cm = confusion_matrix(y_val, y_pred)
print("Confusion Matrix:")
print(cm)

# Classification report (precision, recall, F1-score)
print("\nClassification Report:")
print(classification_report(y_val, y_pred))

# Feature importances
print("\nFeature Importances:")
importances = rf_model.feature_importances_
for feature, importance in zip(X.columns, importances):
    print(f"{feature}: {importance}")
