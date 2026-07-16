import random
import time
import uuid
from datetime import datetime, timedelta
import numpy as np
from faker import Faker

fake = Faker()

# Define the user list
USERS = {}
ROLES = ["admin", "contractor", "vendor", "employee"]

# Seed for reproducibility in baseline generation
random.seed(42)
np.random.seed(42)

# Create 50 users with profiles
for i in range(1, 51):
    user_id = f"user_{i:02d}"
    if i <= 5:
        role = "admin"
    elif i <= 15:
        role = "contractor"
    elif i <= 20:
        role = "vendor"
    else:
        role = "employee"
        
    # Typical locations
    primary_location = random.choice(["US-East", "US-West", "GB-London", "IN-Bangalore"])
    
    # Base profiles
    USERS[user_id] = {
        "user_id": user_id,
        "role": role,
        "primary_location": primary_location,
        "typical_actions": {
            "admin": ["login", "file_access", "db_query", "config_change"],
            "contractor": ["login", "file_access", "db_query"],
            "vendor": ["login", "file_access"],
            "employee": ["login", "file_access", "db_query", "data_export"]
        }[role],
        "typical_resources": {
            "admin": ["/sys/config/auth", "/sys/admin/db", "/db/customer_vault", "/shared/it_wiki"],
            "contractor": ["/proj/banking_app/src", "/proj/banking_app/docs", "/shared/team_chat"],
            "vendor": ["/vendor/invoices", "/vendor/maintenance_portal", "/shared/vendor_guidelines"],
            "employee": ["/shared/hr/benefits", "/shared/finance/reports", "/db/transactions", "/shared/marketing"]
        }[role],
        "mean_volume": {
            "admin": 25.0,
            "contractor": 15.0,
            "vendor": 5.0,
            "employee": 45.0
        }[role],
        "std_volume": {
            "admin": 10.0,
            "contractor": 5.0,
            "vendor": 2.0,
            "employee": 20.0
        }[role],
        "typical_hours": {
            "admin": (7, 20),      # wider hours
            "contractor": (9, 17), # strictly office hours
            "vendor": (9, 17),     # strictly office hours
            "employee": (8, 18)    # standard office hours
        }[role]
    }

class LogGenerator:
    def __init__(self):
        self.active_attacks = []
        
    def generate_event(self, user_id=None, override_fields=None):
        if not user_id:
            user_id = random.choice(list(USERS.keys()))
            
        profile = USERS[user_id]
        
        # Decide action and resource
        action = random.choice(profile["typical_actions"])
        resource = random.choice(profile["typical_resources"])
        
        # Hours
        min_h, max_h = profile["typical_hours"]
        hour = int(np.random.normal((min_h + max_h) / 2.0, (max_h - min_h) / 4.0))
        hour = max(0, min(23, hour))
        
        # Determine is_off_hours
        is_off_hours = hour < 7 or hour > 19
        
        # Volume
        volume = max(0.1, np.random.normal(profile["mean_volume"], profile["std_volume"]))
        volume = round(volume, 2)
        
        # Location
        location = profile["primary_location"]
        if random.random() < 0.02: # 2% chance of remote/different location
            location = random.choice(["FR-Paris", "SG-Singapore", "UA-Kyiv", "BR-Rio"])
            
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        # Keep current hour for generated event
        timestamp = timestamp.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        
        event = {
            "timestamp": timestamp.isoformat(),
            "user_id": user_id,
            "role": profile["role"],
            "action": action,
            "resource": resource,
            "volume_mb": volume,
            "hour_of_day": hour,
            "is_off_hours": is_off_hours,
            "location": location,
            "session_id": str(uuid.uuid4())[:8],
            "status": "active"
        }
        
        if override_fields:
            event.update(override_fields)
            
        return event

    def generate_baseline(self, num_events=10000):
        events = []
        for _ in range(num_events):
            events.append(self.generate_event())
        return events

    # --- Scripted Demo Attacks ---
    
    def trigger_attack_1(self):
        """
        Attack 1: Contractor Off-Hours Data Export (T1030 / T1048)
        Contractor account exporting a massive dataset at 2 AM.
        """
        contractors = [uid for uid, p in USERS.items() if p["role"] == "contractor"]
        target_user = random.choice(contractors)
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        
        sequence = [
            # 1. Login at 2:05 AM
            {
                "timestamp": now.replace(hour=2, minute=5, second=10).isoformat(),
                "user_id": target_user,
                "role": "contractor",
                "action": "login",
                "resource": "/shared/team_chat",
                "volume_mb": 0.5,
                "hour_of_day": 2,
                "is_off_hours": True,
                "location": "UA-Kyiv", # Unusual location
                "session_id": session_id
            },
            # 2. Access database
            {
                "timestamp": now.replace(hour=2, minute=6, second=30).isoformat(),
                "user_id": target_user,
                "role": "contractor",
                "action": "db_query",
                "resource": "/db/customer_vault", # Sensitive! Not in profile
                "volume_mb": 1.2,
                "hour_of_day": 2,
                "is_off_hours": True,
                "location": "UA-Kyiv",
                "session_id": session_id
            },
            # 3. Export massive database tables (4500 MB)
            {
                "timestamp": now.replace(hour=2, minute=8, second=45).isoformat(),
                "user_id": target_user,
                "role": "contractor",
                "action": "data_export", # Not typical for contractor
                "resource": "/db/customer_vault",
                "volume_mb": 4500.0, # Massive!
                "hour_of_day": 2,
                "is_off_hours": True,
                "location": "UA-Kyiv",
                "session_id": session_id
            }
        ]
        return sequence

    def trigger_attack_2(self):
        """
        Attack 2: Admin Brute Force & Config Change (T1110 / T1098)
        Rapid login failures followed by critical security config change.
        """
        admins = [uid for uid, p in USERS.items() if p["role"] == "admin"]
        target_user = random.choice(admins)
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        
        sequence = [
            # 1. Failed Login 1 (Simulated as login from unexpected remote location, high rate)
            {
                "timestamp": (now - timedelta(seconds=15)).isoformat(),
                "user_id": target_user,
                "role": "admin",
                "action": "login",
                "resource": "/sys/config/auth",
                "volume_mb": 0.1,
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": "CN-Beijing", # Suspicious location
                "session_id": session_id,
                "notes": "Failed password attempt"
            },
            # 2. Login Success from CN-Beijing
            {
                "timestamp": (now - timedelta(seconds=5)).isoformat(),
                "user_id": target_user,
                "role": "admin",
                "action": "login",
                "resource": "/sys/config/auth",
                "volume_mb": 0.2,
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": "CN-Beijing",
                "session_id": session_id
            },
            # 3. Critical Configuration Manipulation (T1098)
            {
                "timestamp": now.isoformat(),
                "user_id": target_user,
                "role": "admin",
                "action": "config_change",
                "resource": "/sys/config/auth", # Restricted config resource
                "volume_mb": 12.5, # Config change is usually small, but let's make it highly specific
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": "CN-Beijing",
                "session_id": session_id
            }
        ]
        return sequence

    def trigger_attack_3(self):
        """
        Attack 3: Vendor Privilege Escalation (T1078)
        Vendor user bypassing typical files to query core database.
        """
        vendors = [uid for uid, p in USERS.items() if p["role"] == "vendor"]
        target_user = random.choice(vendors)
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        
        sequence = [
            # 1. Login
            {
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "user_id": target_user,
                "role": "vendor",
                "action": "login",
                "resource": "/vendor/maintenance_portal",
                "volume_mb": 0.4,
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": USERS[target_user]["primary_location"],
                "session_id": session_id
            },
            # 2. Execute DB Query on restricted banking schema (T1078 Privilege Abuse)
            {
                "timestamp": now.isoformat(),
                "user_id": target_user,
                "role": "vendor",
                "action": "db_query", # Vendors NEVER run DB queries normally!
                "resource": "/db/customer_vault", # Extremely sensitive database
                "volume_mb": 250.0, # High volume for a vendor
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": USERS[target_user]["primary_location"],
                "session_id": session_id
            }
        ]
        return sequence

    def trigger_attack_4(self):
        """
        Attack 4: Employee Massive Hoarding (T1030)
        Rapidly downloading dozens of files outside typical directories.
        """
        employees = [uid for uid, p in USERS.items() if p["role"] == "employee"]
        target_user = random.choice(employees)
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now()
        
        sequence = []
        # Rapid series of 5 downloads of sensitive files within seconds
        for i in range(5):
            sequence.append({
                "timestamp": (now + timedelta(seconds=i * 2)).isoformat(),
                "user_id": target_user,
                "role": "employee",
                "action": "file_access",
                "resource": f"/sys/admin/db/backup_{i}", # Outside standard employee scope
                "volume_mb": 450.0, # Accumulating large amounts of data
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": USERS[target_user]["primary_location"],
                "session_id": session_id
            })
        return sequence

    def trigger_attack_5(self):
        """
        Attack 5: Concurrent Multi-Session Access (T1140)
        Admin logging in from two completely different geographical locations in seconds.
        """
        admins = [uid for uid, p in USERS.items() if p["role"] == "admin"]
        target_user = random.choice(admins)
        now = datetime.now()
        
        sequence = [
            # 1. Login session from regular location
            {
                "timestamp": (now - timedelta(seconds=2)).isoformat(),
                "user_id": target_user,
                "role": "admin",
                "action": "login",
                "resource": "/sys/config/auth",
                "volume_mb": 0.5,
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": USERS[target_user]["primary_location"],
                "session_id": "sess_reg1"
            },
            # 2. Concurrent login session from remote location (impossible travel)
            {
                "timestamp": now.isoformat(),
                "user_id": target_user,
                "role": "admin",
                "action": "login",
                "resource": "/sys/admin/db",
                "volume_mb": 0.5,
                "hour_of_day": now.hour,
                "is_off_hours": now.hour < 7 or now.hour > 19,
                "location": "RU-Moscow", # Impossible travel!
                "session_id": "sess_adv2"
            }
        ]
        return sequence
