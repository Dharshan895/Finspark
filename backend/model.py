import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from backend.generator import USERS, ROLES

# Feature columns we will use for training
FEATURE_COLS = [
    "volume_mb", 
    "hour_of_day", 
    "is_off_hours", 
    "is_unusual_location", 
    "is_atypical_resource",
    "role_admin", "role_contractor", "role_vendor", "role_employee",
    "action_login", "action_file_access", "action_db_query", "action_config_change", "action_data_export"
]

class UEBAModel:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42)
        self.is_trained = False
        
    def extract_features(self, event):
        user_id = event["user_id"]
        profile = USERS.get(user_id, {
            "primary_location": "US-East",
            "typical_resources": [],
            "role": event["role"],
            "mean_volume": 10.0
        })
        
        # 1. Location check
        is_unusual_location = 1 if event["location"] != profile["primary_location"] else 0
        
        # 2. Resource check
        is_atypical_resource = 1 if event["resource"] not in profile["typical_resources"] else 0
        
        # Prepare one-hot values
        role = event["role"]
        action = event["action"]
        
        features = {
            "volume_mb": float(event["volume_mb"]),
            "hour_of_day": int(event["hour_of_day"]),
            "is_off_hours": 1 if event["is_off_hours"] else 0,
            "is_unusual_location": is_unusual_location,
            "is_atypical_resource": is_atypical_resource,
            
            # Roles one-hot
            "role_admin": 1 if role == "admin" else 0,
            "role_contractor": 1 if role == "contractor" else 0,
            "role_vendor": 1 if role == "vendor" else 0,
            "role_employee": 1 if role == "employee" else 0,
            
            # Actions one-hot
            "action_login": 1 if action == "login" else 0,
            "action_file_access": 1 if action == "file_access" else 0,
            "action_db_query": 1 if action == "db_query" else 0,
            "action_config_change": 1 if action == "config_change" else 0,
            "action_data_export": 1 if action == "data_export" else 0,
        }
        return features

    def train(self, baseline_events):
        df_feats = pd.DataFrame([self.extract_features(e) for e in baseline_events])
        X = df_feats[FEATURE_COLS]
        self.model.fit(X)
        self.is_trained = True
        print("UEBA Isolation Forest Model trained successfully.")

    def score_event(self, event):
        if not self.is_trained:
            return 15, "Model is initializing...", []
            
        feats = self.extract_features(event)
        df_feat = pd.DataFrame([feats])
        X = df_feat[FEATURE_COLS]
        
        # Decision function: lower values mean more anomalous. Range is approx [-0.5, 0.5]
        decision = self.model.decision_function(X)[0]
        
        # Map decision to risk score: 0 to 100
        # Typical normal: score > 0, typical anomaly: score < -0.1
        # Let's use a nice soft mapping:
        # If decision >= 0.15, risk is low (0-20)
        # If decision around 0, risk is medium (30-65)
        # If decision < -0.05, risk is high (70-100)
        if decision >= 0.12:
            risk_score = int(max(0, 15 - (decision - 0.12) * 50))
        elif decision >= 0.0:
            risk_score = int(15 + (0.12 - decision) * 450)
        else:
            risk_score = int(70 + min(30, abs(decision) * 200))
            
        # Adjust risk score based on high-threat heuristics
        if feats["is_unusual_location"] == 1:
            risk_score = min(100, risk_score + 15)
        if feats["is_atypical_resource"] == 1:
            risk_score = min(100, risk_score + 15)
        if event["action"] == "data_export" and event["volume_mb"] > 2000.0:
            risk_score = 98 # Severe threat
            
        mitre_mappings = self._get_mitre_mapping(event, feats)
        explanation = self._generate_explanation(event, feats, risk_score, mitre_mappings)
        
        return risk_score, explanation, mitre_mappings

    def _get_mitre_mapping(self, event, feats):
        mappings = []
        action = event["action"]
        
        # 1. Valid Accounts (T1078)
        if action == "login" and feats["is_unusual_location"] == 1:
            mappings.append({"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"})
            
        # 2. Exfiltration Over Alternative Protocol (T1048) / Data Transfer Limit (T1030)
        if action == "data_export" and event["volume_mb"] > 1000.0:
            mappings.append({"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"})
            mappings.append({"id": "T1030", "name": "Data Transfer Size Limit", "tactic": "Exfiltration"})
        elif action == "file_access" and event["volume_mb"] > 300.0:
            mappings.append({"id": "T1030", "name": "Data Transfer Size Limit", "tactic": "Exfiltration"})
            
        # 3. Account Manipulation (T1098) / Impair Defenses (T1562)
        if action == "config_change" and feats["is_atypical_resource"] == 1:
            mappings.append({"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"})
            mappings.append({"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"})
            
        # 4. File and Directory Discovery (T1083)
        if action == "file_access" and feats["is_atypical_resource"] == 1:
            mappings.append({"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"})
            
        # 5. Remote Services (T1021) / Impossible Travel
        if feats["is_unusual_location"] == 1:
            mappings.append({"id": "T1021.001", "name": "Remote Services: RDP / SSH", "tactic": "Lateral Movement"})
            
        return mappings

    def _generate_explanation(self, event, feats, risk_score, mitre):
        if risk_score < 40:
            return "Event aligns with historical user baseline. Standard operational access verified."
            
        # Generative explanation builder (Mock LLM response structure)
        user_id = event["user_id"]
        role = event["role"]
        action = event["action"]
        resource = event["resource"]
        volume = event["volume_mb"]
        hour = event["hour_of_day"]
        location = event["location"]
        
        # Template structure to mimic advanced LLM agent output
        points = []
        
        if feats["is_unusual_location"] == 1:
            points.append(f"initiated access from an anomalous remote location '{location}' which does not match their typical primary location")
            
        if feats["is_atypical_resource"] == 1:
            points.append(f"accessed the highly restricted/sensitive path '{resource}' that is outside their standard directory baseline")
            
        if feats["is_off_hours"] == 1:
            points.append(f"conducted operations during off-hours ({hour}:00) when privileged activity is restricted")
            
        profile = USERS.get(user_id, {})
        mean_vol = profile.get("mean_volume", 20.0)
        if volume > mean_vol * 3.0:
            points.append(f"transferred an unusually high volume of data ({volume} MB), exceeding their historical average of {mean_vol} MB by over 300%")
            
        if action == "data_export" and role == "contractor":
            points.append("executed a 'data_export' action which is not authorized in contractor role profiles")
            
        if not points:
            points.append("displayed minor statistical variance in access patterns")
            
        explanation = (
            f"[AI UEBA Insight] High-risk anomaly detected for user '{user_id}' (Role: {role.upper()}). "
            f"The event was flagged because the user " + " and ".join(points) + ". "
            f"This behavior maps to MITRE ATT&CK techniques: " + ", ".join([f"{m['id']} ({m['name']})" for m in mitre]) + "."
        )
        
        # Check if user wanted to demo an actual LLM integration.
        # We can document this hook here for Hackathon slides:
        # To hook up a real LLM:
        # import google.generativeai as genai
        # model = genai.GenerativeModel('gemini-1.5-flash')
        # response = model.generate_content(f"Analyze this suspicious event: {event}")
        # return response.text
        
        return explanation
