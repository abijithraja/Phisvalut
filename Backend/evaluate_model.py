#!/usr/bin/env python3
"""
Evaluate PhishVault model performance on labeled test data
Usage: python evaluate_model.py [test_data.csv]
"""

import csv
import sys
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    roc_auc_score, confusion_matrix, classification_report
)
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_test_data(filename):
    """Load test data from CSV file"""
    X, y, urls = [], [], []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= 1000:  # Limit for quick testing
                    break
                url = row['url']
                label = int(row['label'])  # 0 = safe, 1 = phishing
                urls.append(url)
                y.append(label)
        logger.info(f"Loaded {len(urls)} test samples from {filename}")
        return urls, y
    except FileNotFoundError:
        logger.error(f"Test file {filename} not found!")
        return [], []
    except Exception as e:
        logger.error(f"Error loading test data: {e}")
        return [], []

def extract_features_batch(detector, urls):
    """Extract features for a batch of URLs"""
    X = []
    for i, url in enumerate(urls):
        if i % 100 == 0:
            logger.info(f"Processing URL {i+1}/{len(urls)}")
        
        try:
            # Extract features using detector (quick scan for batch processing)
            features = detector.extract_url_features(url, deep=False)
            
            # Align to model feature names
            model_feature_names = None
            if hasattr(detector.model, "feature_names") and detector.model.feature_names:
                model_feature_names = list(detector.model.feature_names)
            elif hasattr(detector.model, "get_booster"):
                try:
                    model_feature_names = list(detector.model.get_booster().feature_names)
                except Exception:
                    model_feature_names = None
            if not model_feature_names:
                model_feature_names = list(detector.feature_cols)
            
            # Create feature vector
            row = [float(features.get(c, 0.0)) for c in model_feature_names]
            X.append(row)
            
        except Exception as e:
            logger.warning(f"Failed to extract features for {url}: {e}")
            # Use zero vector as fallback
            X.append([0.0] * len(detector.feature_cols))
    
    return np.array(X)

def evaluate_model(detector, X, y, urls):
    """Evaluate model performance"""
    logger.info("Starting model evaluation...")
    
    # Apply preprocessing
    X_processed = X.copy()
    if detector.imputer is not None:
        logger.info("Applying imputer...")
        X_processed = detector.imputer.transform(X_processed)
    
    if detector.scaler is not None:
        logger.info("Applying scaler...")
        X_processed = detector.scaler.transform(X_processed)
    
    # Get model predictions
    logger.info("Getting model predictions...")
    try:
        if hasattr(detector.model, "predict_proba"):
            # sklearn interface
            probs = detector.model.predict_proba(X_processed)[:, 1]
        else:
            # XGBoost Booster interface
            import xgboost as xgb
            model_cols = list(detector.feature_cols)
            dmat = xgb.DMatrix(X_processed, feature_names=model_cols)
            probs = detector.model.predict(dmat)
    except Exception as e:
        logger.error(f"Model prediction failed: {e}")
        return
    
    # Apply calibrator if available
    if detector.calibrator is not None:
        logger.info("Applying calibrator...")
        try:
            probs = detector.calibrator.predict_proba(X_processed)[:, 1]
        except Exception as e:
            logger.warning(f"Calibrator failed: {e}")
    
    # Apply threshold
    threshold = detector.threshold
    preds = (probs > threshold).astype(int)
    
    # Calculate metrics
    logger.info("\n" + "="*60)
    logger.info("EVALUATION RESULTS")
    logger.info("="*60)
    logger.info(f"Dataset size: {len(y)}")
    logger.info(f"Threshold: {threshold:.4f}")
    logger.info(f"Class distribution: {np.bincount(y)} (0=safe, 1=phishing)")
    logger.info("")
    
    # Basic metrics
    accuracy = accuracy_score(y, preds)
    precision = precision_score(y, preds, zero_division=0)
    recall = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)
    
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")
    logger.info(f"F1-Score:  {f1:.4f}")
    
    try:
        auc = roc_auc_score(y, probs)
        logger.info(f"ROC AUC:   {auc:.4f}")
    except Exception as e:
        logger.warning(f"Could not compute ROC AUC: {e}")
    
    # Confusion matrix
    cm = confusion_matrix(y, preds)
    logger.info(f"\nConfusion Matrix:")
    logger.info(f"                Predicted")
    logger.info(f"Actual    Safe  Phishing")
    logger.info(f"Safe      {cm[0,0]:4d}  {cm[0,1]:8d}")
    logger.info(f"Phishing  {cm[1,0]:4d}  {cm[1,1]:8d}")
    
    # Detailed classification report
    logger.info(f"\nDetailed Classification Report:")
    logger.info(classification_report(y, preds, target_names=['Safe', 'Phishing']))
    
    # Show prediction distribution
    logger.info(f"\nPrediction Probability Distribution:")
    logger.info(f"Min prob:  {probs.min():.4f}")
    logger.info(f"Max prob:  {probs.max():.4f}")
    logger.info(f"Mean prob: {probs.mean():.4f}")
    logger.info(f"Std prob:  {probs.std():.4f}")
    
    # Show worst misclassifications
    logger.info(f"\nWorst Misclassifications (showing up to 20):")
    misclassified = []
    for i, (u, p, pr, lab) in enumerate(zip(urls, preds, probs, y)):
        if p != lab:
            error_type = "False Positive" if lab == 0 else "False Negative"
            misclassified.append((error_type, pr, u))
    
    # Sort by probability (most confident mistakes first)
    misclassified.sort(key=lambda x: abs(x[1] - 0.5), reverse=True)
    
    for i, (error_type, prob, url) in enumerate(misclassified[:20]):
        logger.info(f"{error_type:14s} prob={prob:.4f} {url}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'threshold': threshold,
        'confusion_matrix': cm,
        'probabilities': probs
    }

def main():
    """Main evaluation function"""
    # Import and initialize detector
    try:
        from main import initialize_detector, detector
        if not initialize_detector():
            logger.error("Failed to initialize detector")
            sys.exit(1)
        logger.info("✅ Detector initialized successfully")
    except ImportError as e:
        logger.error(f"Failed to import detector: {e}")
        sys.exit(1)
    
    # Load test data
    test_file = sys.argv[1] if len(sys.argv) > 1 else "test_data.csv"
    urls, y = load_test_data(test_file)
    
    if not urls:
        logger.error("No test data loaded. Please provide a CSV file with 'url' and 'label' columns.")
        logger.info("Example CSV format:")
        logger.info("url,label")
        logger.info("https://www.google.com,0")
        logger.info("https://phishing-example.com,1")
        sys.exit(1)
    
    # Extract features
    logger.info("Extracting features from URLs...")
    X = extract_features_batch(detector, urls)
    
    # Evaluate model
    results = evaluate_model(detector, X, y, urls)
    
    logger.info("\n" + "="*60)
    logger.info("EVALUATION COMPLETE")
    logger.info("="*60)

if __name__ == "__main__":
    main()
