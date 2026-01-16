from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from typing import List, Dict, Tuple
from src.utils.logger import setup_logger
import os
import pickle

logger = setup_logger("ml_classifier")

class MLVulnerabilityClassifier:
    """Traditional ML-based vulnerability classification"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            token_pattern=r'\b\w+\b',
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42
        )
        self.is_trained = False
        self.vulnerability_types = [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal',
            'hardcoded_secrets'
        ]
    
    def train(self, training_data: List[Dict]):
        """Train the model on vulnerability examples"""
        X_texts = []
        y_labels = []
        
        for sample in training_data:
            X_texts.append(sample['code'])
            y_labels.append(sample['vulnerability_type'])
        
        # Vectorize code samples using TF-IDF (Term Frequency-Inverse Document Frequency)
        # This converts code text into numerical vectors that the ML model can understand
        X = self.vectorizer.fit_transform(X_texts)
        
        # Train RandomForest classifier
        # We use RandomForest because it handles high-dimensional sparse data (like code tokens) well
        self.classifier.fit(X, y_labels)
        self.is_trained = True
        
        logger.info(f"Model trained successfully on {len(training_data)} samples")
    
    def predict(self, code_snippet: str) -> Tuple[str, float]:
        """Predict vulnerability type and confidence"""
        if not self.is_trained:
            return ("unknown", 0.0)
        
        X = self.vectorizer.transform([code_snippet])
        prediction = self.classifier.predict(X)[0]
        probabilities = self.classifier.predict_proba(X)[0]
        confidence = max(probabilities)
        
        return (prediction, confidence)
    
    def save_model(self, path: str = "models/ml_classifier.pkl"):
        """Save trained model"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.vectorizer,
                'classifier': self.classifier,
                'is_trained': self.is_trained
            }, f)
    
    def load_model(self, path: str = "models/ml_classifier.pkl"):
        """Load trained model"""
        if os.path.exists(path):
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.vectorizer = data['vectorizer']
                self.classifier = data['classifier']
                self.is_trained = data['is_trained']
            logger.info(f"Model loaded successfully from {path}")
        else:
            logger.warning(f"No saved model found at {path}. A new model will be trained on the fly.")
    
    def get_synthetic_training_data(self) -> List[Dict]:
        """Generate synthetic training data for demonstration"""
        return [
            # SQL Injection examples
            {
                'code': 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
                'vulnerability_type': 'sql_injection'
            },
            {
                'code': 'query = f"SELECT * FROM users WHERE name=\'{username}\'"',
                'vulnerability_type': 'sql_injection'
            },
            {
                'code': 'db.execute("SELECT * FROM products WHERE id=%s" % product_id)',
                'vulnerability_type': 'sql_injection'
            },
            
            # XSS examples
            {
                'code': 'document.getElementById("output").innerHTML = userInput;',
                'vulnerability_type': 'xss'
            },
            {
                'code': 'element.innerHTML = "<div>" + request.data + "</div>";',
                'vulnerability_type': 'xss'
            },
            
            # Command Injection examples
            {
                'code': 'os.system("ping " + user_input)',
                'vulnerability_type': 'command_injection'
            },
            {
                'code': 'subprocess.call(cmd, shell=True)',
                'vulnerability_type': 'command_injection'
            },
            {
                'code': 'eval(user_input)',
                'vulnerability_type': 'command_injection'
            },
            
            # Path Traversal examples
            {
                'code': 'open("/var/files/" + filename, "r")',
                'vulnerability_type': 'path_traversal'
            },
            {
                'code': 'file_path = request.args.get("file"); open(file_path)',
                'vulnerability_type': 'path_traversal'
            },
            
            # Hardcoded Secrets examples
            {
                'code': 'api_key = "sk-1234567890abcdef"',
                'vulnerability_type': 'hardcoded_secrets'
            },
            {
                'code': 'password = "admin123"',
                'vulnerability_type': 'hardcoded_secrets'
            },
        ]
