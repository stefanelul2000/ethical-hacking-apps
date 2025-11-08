from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pandas as pd
import joblib
import os
import re
import time
app = FastAPI(title="Iris Classification API")

DATA_DIR = "data"
MODEL_DIR = "model"
USER_DATA_PATH = os.path.join(DATA_DIR, "user_data.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "iris_model.pkl")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

iris = load_iris()
iris_df = pd.DataFrame(iris.data, columns=iris.feature_names)
iris_df["label"] = iris.target

target_names = dict(enumerate(iris.target_names))

class IrisData(BaseModel):
    sepal_length: float
    sepal_width: float
    petal_length: float
    petal_width: float
    label: int 

class IrisPredict(BaseModel):
    sepal_length: float
    sepal_width: float
    petal_length: float
    petal_width: float

@app.post("/add-data")
def add_data(item: IrisData):
    """Add user-provided flower data."""

    label_str = str(item.label).strip()
    start = time.time()

    try:
        match = re.match(r"^(\d+)+$", label_str)
    except re.error:
        raise HTTPException(status_code=400, detail="Invalid regex pattern used for label validation")

    duration = time.time() - start

    if not match:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid label format. Validation took {duration:.4f}s"
        )

    new_row = pd.DataFrame([{
        "sepal length (cm)": item.sepal_length,
        "sepal width (cm)": item.sepal_width,
        "petal length (cm)": item.petal_length,
        "petal width (cm)": item.petal_width,
        "label": item.label
    }])

    if os.path.exists(USER_DATA_PATH):
        existing = pd.read_csv(USER_DATA_PATH)
        df = pd.concat([existing, new_row], ignore_index=True)
    else:
        df = new_row

    df.to_csv(USER_DATA_PATH, index=False)

    return {
        "message": "Sample added successfully",
        "validation_time_seconds": round(duration, 6),
    }



@app.post("/train")
def train_model():
    """Train a Random Forest on Iris + user data."""
    df = iris_df.copy()
    if os.path.exists(USER_DATA_PATH):
        user_df = pd.read_csv(USER_DATA_PATH)
        df = pd.concat([df, user_df], ignore_index=True)

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))

    joblib.dump(model, MODEL_PATH)
    return {"message": "Model trained successfully", "accuracy": acc}


@app.post("/predict")
def predict(item: IrisPredict):
    """Predict Iris species."""
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=400, detail="No trained model found. Train first.")
    model = joblib.load(MODEL_PATH)

    X_input = [[
        item.sepal_length,
        item.sepal_width,
        item.petal_length,
        item.petal_width
    ]]
    pred = model.predict(X_input)[0]
    species = target_names[pred]
    return {"prediction": int(pred), "species": species}


@app.get("/")
def root():
    return {"message": "Iris classification API is running"}
