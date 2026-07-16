import datetime
import uuid

class SOAREngine:
    def __init__(self):
        # Maps user_id -> state
        self.user_states = {}
        # List of active incidents in the SOC queue
        self.soc_queue = []
        
    def get_user_state(self, user_id, role):
        if user_id not in self.user_states:
            self.user_states[user_id] = {
                "user_id": user_id,
                "role": role,
                "status": "active", # active, locked
                "cumulative_risk": 0,
                "updated_at": datetime.datetime.now().isoformat()
            }
        return self.user_states[user_id]
        
    def evaluate_event(self, event, event_risk, explanation, mitre_mappings):
        user_id = event["user_id"]
        role = event["role"]
        state = self.get_user_state(user_id, role)
        
        # Cumulative risk is updated. We can use the max risk of recent events
        # or aggregate them. Let's make it the max of current event and previous risk
        # but with some weight.
        old_risk = state["cumulative_risk"]
        new_risk = max(old_risk, event_risk)
        state["cumulative_risk"] = new_risk
        state["updated_at"] = datetime.datetime.now().isoformat()
        
        triggered_actions = []
        
        # SOAR trigger: If risk >= 75 and user is still active
        if new_risk >= 75 and state["status"] == "active":
            state["status"] = "locked"
            
            # Formulate the incident details
            incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
            ticket = {
                "incident_id": incident_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "user_id": user_id,
                "role": role,
                "risk_score": new_risk,
                "mitre_techniques": [m["name"] for m in mitre_mappings],
                "explanation": explanation,
                "status": "triggered",
                "actions_taken": [
                    f"SOAR-Playbook: Account {user_id} automatically DISABLED in Active Directory",
                    "SOAR-Playbook: Revoked OAuth & API access tokens",
                    "SOAR-Playbook: Alert notification broadcasted to SOC Analyst channels",
                    "SOAR-Playbook: Syslog audit record written to encrypted vault"
                ]
            }
            
            self.soc_queue.append(ticket)
            triggered_actions = ticket["actions_taken"]
            
        return state, triggered_actions

    def unlock_user(self, user_id):
        if user_id in self.user_states:
            self.user_states[user_id]["status"] = "active"
            self.user_states[user_id]["cumulative_risk"] = 0
            self.user_states[user_id]["updated_at"] = datetime.datetime.now().isoformat()
            
            # Mark incident as resolved in the SOC queue if it exists
            for ticket in self.soc_queue:
                if ticket["user_id"] == user_id and ticket["status"] == "triggered":
                    ticket["status"] = "resolved"
                    ticket["actions_taken"].append("Manual override: Account unlocked by security administrator")
            return True
        return False

    def get_all_states(self):
        return list(self.user_states.values())
        
    def get_soc_queue(self):
        return self.soc_queue
