import base64
import binascii
import re
import urllib.parse

def detect_encoding(data):
    """
    Detect the encoding of the provided data
    
    Args:
        data (str): The data to analyze
        
    Returns:
        str or None: The detected encoding type or None if not detected
    """
    # Check if it's empty
    if not data or len(data) < 4:
        return None
    
    # Check for Base64 encoding
    if is_base64(data):
        return "base64"
    
    # Check for Hex encoding
    if is_hex(data):
        return "hex"
    
    # Check for URL encoding
    if is_url_encoded(data):
        return "url"
    
    # Check for ASCII85 encoding
    if is_ascii85(data):
        return "ascii85"
    
    # Check for Quoted-Printable encoding
    if is_quoted_printable(data):
        return "quoted-printable"
    
    # No recognized encoding detected
    return None

def is_base64(data):
    """Check if a string is Base64 encoded"""
    # Trim leading/trailing whitespace
    if isinstance(data, str):
        data = data.strip()
    
    # Minimum 24 characters for reasonable base64 data
    if len(data) < 24:
        return False
    
    # Handle PDFs and other binary formats (check for common signatures after decoding)
    try:
        # Check if data is reasonably base64-like (allowing for some tolerance)
        # Modified pattern for standard Base64 that allows for some non-base64 chars like line breaks
        clean_data = re.sub(r'[\s\r\n]', '', data)
        
        # Regular pattern for standard Base64 (allow line breaks by not using ^ and $)
        standard_pattern = r'[A-Za-z0-9+/]+(=?=?=?)'
        
        # Check if most of the string matches the pattern
        match_ratio = len(re.findall(r'[A-Za-z0-9+/=]', clean_data)) / len(clean_data) if clean_data else 0
        
        if match_ratio > 0.95:  # At least 95% of chars should be base64 chars
            # Try to decode it as base64
            try:
                # Add padding if needed
                if len(clean_data) % 4 != 0:
                    clean_data += '=' * (4 - len(clean_data) % 4)
                
                decoded = base64.b64decode(clean_data)
                
                # Check for some common file signatures in decoded data
                if (decoded.startswith(b'%PDF') or  # PDF
                    decoded.startswith(b'PK\x03\x04') or  # ZIP / Office docs
                    decoded.startswith(b'\xFF\xD8\xFF') or  # JPEG
                    decoded.startswith(b'\x89PNG') or  # PNG
                    decoded.startswith(b'GIF8') or  # GIF
                    decoded.startswith(b'BM') or  # BMP
                    decoded.startswith(b'ID3') or  # MP3
                    decoded.startswith(b'\x00\x00\x00\x18ftypmp4')):  # MP4
                    return True
                    
                # Try to detect if the decoded content is something meaningful
                # For text content, check if it has reasonable character distribution
                try:
                    text = decoded.decode('utf-8', errors='strict')
                    # Check if it looks like text and not random garbage
                    if re.search(r'[a-zA-Z0-9.,;:!?()}{"\' ]{10,}', text):
                        return True
                except UnicodeDecodeError:
                    # Not UTF-8 text, could still be valid binary data
                    # If it's longer than 100 bytes, assume it might be valid binary
                    if len(decoded) > 100:
                        return True
            except Exception:
                pass
        
        # URL-safe Base64 variant
        url_safe_pattern = r'[A-Za-z0-9_-]+(=?=?=?)'
        match_ratio = len(re.findall(r'[A-Za-z0-9_\-=]', clean_data)) / len(clean_data) if clean_data else 0
        
        if match_ratio > 0.95:  # At least 95% of chars should be base64 chars
            try:
                # Add padding if needed
                if len(clean_data) % 4 != 0:
                    clean_data += '=' * (4 - len(clean_data) % 4)
                    
                decoded = base64.urlsafe_b64decode(clean_data)
                
                # Same checks as above
                if (decoded.startswith(b'%PDF') or  # PDF
                    decoded.startswith(b'PK\x03\x04') or  # ZIP / Office docs
                    decoded.startswith(b'\xFF\xD8\xFF') or  # JPEG
                    decoded.startswith(b'\x89PNG') or  # PNG
                    decoded.startswith(b'GIF8') or  # GIF
                    decoded.startswith(b'BM') or  # BMP
                    decoded.startswith(b'ID3') or  # MP3
                    decoded.startswith(b'\x00\x00\x00\x18ftypmp4')):  # MP4
                    return True
                    
                try:
                    text = decoded.decode('utf-8', errors='strict')
                    if re.search(r'[a-zA-Z0-9.,;:!?()}{"\' ]{10,}', text):
                        return True
                except UnicodeDecodeError:
                    if len(decoded) > 100:
                        return True
            except Exception:
                pass
    except Exception:
        pass
    
    return False

def is_hex(data):
    """Check if a string is Hex encoded"""
    # Regular pattern for hexadecimal strings
    pattern = r'^[0-9A-Fa-f]+$'
    
    # Check if the string matches the pattern and has an even length
    if re.match(pattern, data) and len(data) % 2 == 0:
        # Try to decode it as hex
        try:
            decoded = binascii.unhexlify(data)
            return True
        except Exception:
            pass
    
    return False

def is_url_encoded(data):
    """Check if a string is URL encoded"""
    # Look for percent-encoded characters
    if '%' in data and re.search(r'%[0-9A-Fa-f]{2}', data):
        # Try to decode it as URL-encoded
        try:
            decoded = urllib.parse.unquote(data)
            # If the decoded string is different from the original, it was likely URL-encoded
            return decoded != data
        except Exception:
            pass
    
    return False

def is_ascii85(data):
    """Check if a string is ASCII85 encoded"""
    # Regular pattern for ASCII85
    pattern = r'^<~[!-u]+~>$'
    
    if re.match(pattern, data):
        try:
            # Strip the delimiters and try to decode
            content = data[2:-2]
            decoded = base64.a85decode(content)
            return True
        except Exception:
            pass
    
    return False

def is_quoted_printable(data):
    """Check if a string is Quoted-Printable encoded"""
    # Look for the =XX pattern typical of Quoted-Printable
    if '=' in data and re.search(r'=[0-9A-F]{2}', data):
        try:
            import quopri
            decoded = quopri.decodestring(data.encode()).decode()
            # If the decoded string is different from the original, it was likely QP-encoded
            return decoded != data
        except Exception:
            pass
    
    return False

def decode_content(data, encoding_type):
    """
    Decode content based on its encoding type
    
    Args:
        data (str): The data to decode
        encoding_type (str): The encoding type
        
    Returns:
        bytes: The decoded content
    """
    if encoding_type == "base64":
        try:
            # Special handling for PDFs - PDF signature in base64 starts with JVBERi0
            if data.strip().startswith('JVBERi0'):
                print("Detected PDF in base64 format - using precise handling")
            
            # Clean the data - remove whitespace, newlines
            clean_data = re.sub(r'[\s\r\n]', '', data)
            
            # Remove any non-base64 characters (more aggressive cleaning for problematic inputs)
            clean_data = re.sub(r'[^A-Za-z0-9+/=]', '', clean_data)
            
            # Add padding if needed
            if len(clean_data) % 4 != 0:
                clean_data += '=' * (4 - len(clean_data) % 4)
            
            # Try to decode with standard base64
            try:
                decoded = base64.b64decode(clean_data)
                # Check if it's a PDF
                if decoded.startswith(b'%PDF'):
                    print("Successfully decoded PDF content")
                return decoded
            except Exception as e1:
                print(f"Standard base64 decode failed: {str(e1)}")
                
                # Try with URL-safe Base64 variant
                try:
                    decoded = base64.urlsafe_b64decode(clean_data)
                    if decoded.startswith(b'%PDF'):
                        print("Successfully decoded PDF content with URL-safe base64")
                    return decoded
                except Exception as e2:
                    print(f"URL-safe base64 decode failed: {str(e2)}")
                    
                    # As a last resort, try with original data
                    try:
                        return base64.b64decode(data)
                    except Exception as e3:
                        print(f"Original data base64 decode failed: {str(e3)}")
                        raise
        except Exception as e:
            # Log the error for debugging
            print(f"Base64 decode error: {str(e)}")
            # Return the original data as bytes if decoding fails
            if isinstance(data, str):
                return data.encode()
            return data
    
    elif encoding_type == "hex":
        try:
            # Remove any whitespace
            clean_data = re.sub(r'\s', '', data)
            return binascii.unhexlify(clean_data)
        except Exception as e:
            print(f"Hex decode error: {str(e)}")
            if isinstance(data, str):
                return data.encode()
            return data
    
    elif encoding_type == "url":
        try:
            decoded = urllib.parse.unquote(data)
            return decoded.encode()
        except Exception as e:
            print(f"URL decode error: {str(e)}")
            if isinstance(data, str):
                return data.encode()
            return data
    
    elif encoding_type == "ascii85":
        try:
            # Strip the delimiters if present
            if data.startswith('<~') and data.endswith('~>'):
                data = data[2:-2]
            return base64.a85decode(data)
        except Exception as e:
            print(f"ASCII85 decode error: {str(e)}")
            if isinstance(data, str):
                return data.encode()
            return data
    
    elif encoding_type == "quoted-printable":
        try:
            import quopri
            return quopri.decodestring(data.encode())
        except Exception as e:
            print(f"Quoted-printable decode error: {str(e)}")
            if isinstance(data, str):
                return data.encode()
            return data
    
    # Default case - return the data as bytes
    if isinstance(data, str):
        return data.encode()
    return data
