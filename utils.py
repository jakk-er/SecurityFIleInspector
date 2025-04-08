import requests
import magic
import hashlib
import re
import mimetypes

def download_from_url(url):
    """
    Download content from a URL
    
    Args:
        url (str): URL to download from
        
    Returns:
        bytes: Downloaded content or None if failed
    """
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()  # Raise an error for bad responses
        
        # Get content
        content = response.content
        return content
    except Exception as e:
        print(f"Error downloading from URL: {str(e)}")
        return None

def determine_file_type_extension(content):
    """
    Determine the MIME type and appropriate extension for content
    
    Args:
        content (bytes or str): Content to analyze
        
    Returns:
        tuple: (mime_type, extension)
    """
    if isinstance(content, str):
        content = content.encode('utf-8', errors='ignore')
    
    try:
        # Use python-magic to determine file type
        mime_type = magic.from_buffer(content, mime=True)
        
        # Get appropriate extension for the MIME type
        extension = mimetypes.guess_extension(mime_type)
        
        # Handle special cases and common extensions
        if extension is None or extension == '.bin':
            if mime_type == 'application/octet-stream':
                # Try to determine a more specific type
                if content.startswith(b'MZ'):
                    return 'application/x-dosexec', 'exe'
                elif content.startswith(b'%PDF'):
                    return 'application/pdf', 'pdf'
                elif content.startswith(b'\x89PNG'):
                    return 'image/png', 'png'
                elif content.startswith(b'\xFF\xD8\xFF'):
                    return 'image/jpeg', 'jpg'
                else:
                    return mime_type, 'bin'
            
            # Special cases for common types
            if mime_type == 'text/plain':
                # Check for common text formats
                text_content = content.decode('utf-8', errors='ignore')
                if re.search(r'<html.*?>|<!DOCTYPE html>', text_content, re.IGNORECASE):
                    return 'text/html', 'html'
                elif re.search(r'<?xml.*?>', text_content):
                    return 'application/xml', 'xml'
                elif re.search(r'^\s*{.*}\s*$', text_content, re.DOTALL):
                    return 'application/json', 'json'
                else:
                    return mime_type, 'txt'
            
            # More mappings
            type_to_ext = {
                'application/x-executable': 'elf',
                'application/x-dosexec': 'exe',
                'application/pdf': 'pdf',
                'application/zip': 'zip',
                'application/x-rar-compressed': 'rar',
                'application/x-tar': 'tar',
                'application/x-gzip': 'gz',
                'application/x-bzip2': 'bz2',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
                'application/msword': 'doc',
                'application/vnd.ms-excel': 'xls',
                'application/vnd.ms-powerpoint': 'ppt',
                'image/jpeg': 'jpg',
                'image/png': 'png',
                'image/gif': 'gif',
                'image/webp': 'webp',
                'image/svg+xml': 'svg',
                'video/mp4': 'mp4',
                'video/webm': 'webm',
                'video/x-msvideo': 'avi',
                'audio/mpeg': 'mp3',
                'audio/wav': 'wav',
                'audio/ogg': 'ogg',
                'text/html': 'html',
                'text/css': 'css',
                'text/javascript': 'js',
                'application/javascript': 'js',
                'application/json': 'json',
                'application/xml': 'xml',
                'text/csv': 'csv',
            }
            
            if mime_type in type_to_ext:
                extension = '.' + type_to_ext[mime_type]
            else:
                extension = '.bin'  # Default for unknown
        
        # Remove the leading dot from the extension
        if extension and extension.startswith('.'):
            extension = extension[1:]
        
        return mime_type, extension or 'bin'
    
    except Exception as e:
        print(f"Error determining file type: {str(e)}")
        return 'application/octet-stream', 'bin'  # Default fallback

def generate_file_hash(content):
    """
    Generate MD5, SHA-1, and SHA-256 hashes for content
    
    Args:
        content (bytes): Content to hash
        
    Returns:
        dict: Hash values
    """
    if isinstance(content, str):
        content = content.encode('utf-8', errors='ignore')
    
    hash_md5 = hashlib.md5(content).hexdigest()
    hash_sha1 = hashlib.sha1(content).hexdigest()
    hash_sha256 = hashlib.sha256(content).hexdigest()
    
    return {
        'md5': hash_md5,
        'sha1': hash_sha1,
        'sha256': hash_sha256
    }

def sanitize_filename(filename):
    """
    Sanitize a filename to be safe for file systems
    
    Args:
        filename (str): Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Limit length (adjustable to filesystem needs)
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        name = name[:max_length - len(ext)]
        filename = name + ext
    
    return filename
