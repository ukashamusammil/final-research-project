import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
import joblib  # Import joblib to save the model

# Load the training data (from train.csv)
TRAIN_PATH = r"X:\AI_TI_ENGINE\data\processed\splits\train.csv"
df_train = pd.read_csv(TRAIN_PATH)

# Load the validation data (from val.csv)
VAL_PATH = r"X:\AI_TI_ENGINE\data\processed\splits\val.csv"
df_val = pd.read_csv(VAL_PATH)

# Features and labels for both train and validation sets
X_train = df_train.drop(columns=["label"])
y_train = df_train["label"]

X_val = df_val.drop(columns=["label"])
y_val = df_val["label"]

# Create and train the Random Forest model
rf_model = RandomForestClassifier(random_state=42)
rf_model.fit(X_train, y_train)

# Save the trained model to a file 
MODEL_PATH = r"X:\AI_TI_ENGINE\models\random_forest_model.pkl"
joblib.dump(rf_model, MODEL_PATH)
print(f"Model saved to: {MODEL_PATH}")

# Predict on validation set (from val.csv)
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
for feature, importance in zip(X_train.columns, importances):
    print(f"{feature}: {importance}")
