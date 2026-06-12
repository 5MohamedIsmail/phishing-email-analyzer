import email
from email import policy

def extract_body(msg):
    """
    Walks through the email parts to find and extract the plain text and HTML bodies.
    
    Args:
        msg: The parsed EmailMessage object.
        
    Returns:
        A dictionary with 'plain' and 'html' keys containing the respective body text.
    """
    bodies = {"plain": "", "html": ""}
    
    # An email can be just text, or multipart (containing both text and html, or attachments).
    # msg.walk() iterates over every part of the email.
    for part in msg.walk():
        # We only care about the actual content parts, not the multipart containers themselves.
        if part.get_content_maintype() == 'multipart':
            continue
            
        content_type = part.get_content_type()
        
        # Extract plain text
        if content_type == 'text/plain':
            try:
                # get_content() automatically handles decoding (like Base64 or Quoted-Printable)
                bodies["plain"] += part.get_content()
            except Exception as e:
                bodies["plain"] += f"\\n[Error extracting plain text: {e}]"
                
        # Extract HTML
        elif content_type == 'text/html':
            try:
                bodies["html"] += part.get_content()
            except Exception as e:
                bodies["html"] += f"\\n[Error extracting HTML: {e}]"
                
    return bodies

def parse_email(file_bytes):
    """
    Parses a raw .eml file and extracts basic metadata (headers) and the body.
    
    Args:
        file_bytes: The raw byte content of the uploaded .eml file.
        
    Returns:
        A dictionary containing the extracted headers, bodies, and the raw message object.
    """
    # Parse the email bytes into an EmailMessage object.
    # The 'policy.default' tells Python to automatically decode complex headers.
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    
    # Extract the bodies using our new function
    bodies = extract_body(msg)
    
    # Extract specific headers.
    parsed_data = {
        "From": msg.get("From", "Not Found"),
        "To": msg.get("To", "Not Found"),
        "Subject": msg.get("Subject", "Not Found"),
        "Date": msg.get("Date", "Not Found"),
        "Reply-To": msg.get("Reply-To", "Not Found"),
        "Return-Path": msg.get("Return-Path", "Not Found"),
        "body_plain": bodies["plain"],
        "body_html": bodies["html"],
        
        # We store the entire message object so we can pass it to other modules later.
        "raw_message": msg 
    }
    
    return parsed_data
