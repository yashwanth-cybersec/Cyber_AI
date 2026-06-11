# agents/anomaly_agent.py
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SK_OK = True
except ImportError:
    SK_OK = False

class AnomalyAgent:
    def __init__(self):
        self.trained = False
        if SK_OK:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            try:
                normal = np.array([[i] for i in range(1,8)]*15)
                self.model.fit(normal)
                self.trained = True
            except Exception: pass

    def predict(self, feature):
        if not SK_OK or not self.trained:
            return 0.6 if (feature[0] if feature else 0) > 15 else 0.0
        try:
            return 0.6 if self.model.predict([feature])[0] == -1 else 0.0
        except Exception: return 0.0
