# utils/ml_persistence.py - Machine Learning Model Persistence
import pickle
import json
import os
import numpy as np
from datetime import datetime
from collections import deque

MODEL_DIR = "models"
MODEL_FILE = os.path.join(MODEL_DIR, "orchestrator_model.pkl")
FEEDBACK_FILE = os.path.join(MODEL_DIR, "feedback.json")
TRAINING_DATA_FILE = os.path.join(MODEL_DIR, "training_data.json")

class MLPersistence:
    """Save and load ML models, collect feedback for continuous improvement"""
    
    def __init__(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        self.feedback = self._load_feedback()
        self.training_data = self._load_training_data()
    
    def _load_feedback(self):
        """Load feedback from file"""
        if os.path.exists(FEEDBACK_FILE):
            try:
                with open(FEEDBACK_FILE, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _load_training_data(self):
        """Load training data from file"""
        if os.path.exists(TRAINING_DATA_FILE):
            try:
                with open(TRAINING_DATA_FILE, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_feedback(self):
        """Save feedback to file"""
        with open(FEEDBACK_FILE, 'w') as f:
            json.dump(self.feedback[-1000:], f, indent=2)
    
    def _save_training_data(self):
        """Save training data to file"""
        with open(TRAINING_DATA_FILE, 'w') as f:
            json.dump(self.training_data[-5000:], f, indent=2)
    
    def save_model(self, model):
        """Save trained model to disk"""
        try:
            with open(MODEL_FILE, 'wb') as f:
                pickle.dump(model, f)
            print(f"  [ML] Model saved to {MODEL_FILE}")
            return True
        except Exception as e:
            print(f"  [ML] Error saving model: {e}")
            return False
    
    def load_model(self):
        """Load trained model from disk"""
        if os.path.exists(MODEL_FILE):
            try:
                with open(MODEL_FILE, 'rb') as f:
                    model = pickle.load(f)
                print(f"  [ML] Model loaded from {MODEL_FILE}")
                return model
            except Exception as e:
                print(f"  [ML] Error loading model: {e}")
        return None
    
    def record_feedback(self, alert_id, features, predicted_risk, actual_risk, was_correct, user_rating=None):
        """Record feedback for model improvement"""
        feedback_entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_id": alert_id,
            "features": features,
            "predicted_risk": predicted_risk,
            "actual_risk": actual_risk,
            "was_correct": was_correct,
            "user_rating": user_rating,
        }
        self.feedback.append(feedback_entry)
        self._save_feedback()
        
        # Add to training data if we have actual outcome
        if actual_risk is not None:
            self.training_data.append({
                "features": features,
                "label": actual_risk,
                "timestamp": datetime.now().isoformat(),
                "alert_id": alert_id,
            })
            self._save_training_data()
        
        return len(self.feedback)
    
    def get_training_data(self, min_samples=100):
        """Get training data for model retraining"""
        if len(self.training_data) < min_samples:
            return None, None
        
        X = []
        y = []
        for sample in self.training_data:
            if sample.get("label") is not None:
                X.append(sample["features"])
                y.append(sample["label"])
        
        if len(X) < min_samples:
            return None, None
        
        return np.array(X), np.array(y)
    
    def get_feedback_stats(self):
        """Get statistics about feedback"""
        if not self.feedback:
            return {"total": 0, "accuracy": 0}
        
        correct = sum(1 for f in self.feedback if f.get("was_correct", False))
        total = len(self.feedback)
        
        return {
            "total": total,
            "correct": correct,
            "accuracy": round(correct / total * 100, 2) if total > 0 else 0,
            "feedback_with_ratings": sum(1 for f in self.feedback if f.get("user_rating")),
            "training_samples": len(self.training_data),
        }
    
    def auto_retrain_if_needed(self, model, orchestrator, threshold=100):
        """Auto-retrain if enough new feedback collected"""
        new_samples = len(self.training_data) - getattr(self, "_last_train_count", 0)
        
        if new_samples >= threshold:
            print(f"  [ML] Auto-retraining with {new_samples} new samples...")
            X, y = self.get_training_data()
            if X is not None and len(X) >= threshold:
                # Retrain model
                from sklearn.ensemble import RandomForestClassifier
                new_model = RandomForestClassifier(n_estimators=100, random_state=42)
                new_model.fit(X, y)
                
                # Update orchestrator model
                orchestrator.model = new_model
                self.save_model(new_model)
                self._last_train_count = len(self.training_data)
                print(f"  [ML] Model retrained successfully")
                return True
        
        return False

# Global instance
ml_persistence = MLPersistence()