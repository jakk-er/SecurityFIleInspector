import hashlib
import io
import os
import re
import base64
import binascii
import magic
import zipfile
import tarfile
import gzip
import bz2
import lzma
import math
import string
from io import BytesIO
from PIL import Image

from encoding_detector import detect_encoding, decode_content
from utils import determine_file_type_extension

def generate_file_hash(content):
    """Generates MD5 and SHA256 hashes for file content."""
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    return {'md5': md5_hash, 'sha256': sha256_hash}


def extract_base64_images_from_html(content):
    """
    Extract Base64 encoded images from HTML content

    Args:
        content (bytes): HTML content as bytes

    Returns:
        list: List of extracted image files
    """
    results = []

    try:
        # Convert bytes to string
        html_str = content.decode('utf-8', errors='ignore')

        # Find all base64 encoded data
        # Pattern for data URIs: data:[<media type>][;base64],<data>
        # More permissive pattern to catch various formats including:
        # - standard data:image/png;base64,...
        # - data:image/svg+xml;base64,...
        # - non-standard variations with different whitespace/quotes
        data_uri_pattern = r'data:image/([a-zA-Z0-9\-+.]+);base64,([A-Za-z0-9+/=\s]+)'
        matches = re.findall(data_uri_pattern, html_str)

        for i, (img_type, base64_data) in enumerate(matches):
            try:
                # Decode the base64 data
                img_data = base64.b64decode(base64_data)

                # Determine the file type from the content
                detected_type, extension = determine_file_type_extension(img_data)

                # Use the detected type if available, otherwise use the one from the data URI
                if not extension:
                    extension = img_type

                # Compare hash before adding
                decoded_hash = generate_file_hash(img_data)
                if decoded_hash['md5'] != generate_file_hash(content)['md5']:
                    # Add to results
                    results.append({
                        "name": f"decoded_image_{i+1}.{extension}",
                        "content": img_data,
                        "size": len(img_data),
                        "type": detected_type or f"image/{img_type}",
                        "source": "base64_image"
                    })
                    print(f"Extracted base64 image {i+1}: {extension} type ({len(img_data)} bytes)")
            except Exception as e:
                print(f"Error decoding base64 image {i+1}: {str(e)}")

        # Also look for inline style background images with the same permissive pattern
        style_image_pattern = r'url\(["\']?data:image/([a-zA-Z0-9\-+.]+);base64,([A-Za-z0-9+/=\s]+)["\']?\)'
        style_matches = re.findall(style_image_pattern, html_str)

        for i, (img_type, base64_data) in enumerate(style_matches):
            try:
                img_data = base64.b64decode(base64_data)
                detected_type, extension = determine_file_type_extension(img_data)

                if not extension:
                    extension = img_type

                results.append({
                    "name": f"extracted_bg_image_{i+1}.{extension}",
                    "content": img_data,
                    "size": len(img_data),
                    "type": detected_type or f"image/{img_type}",
                    "source": "base64_background_image"
                })
                print(f"Extracted base64 background image {i+1}: {extension} type ({len(img_data)} bytes)")
            except Exception as e:
                print(f"Error decoding base64 background image {i+1}: {str(e)}")

        # Look for SVG data in the HTML with more accurate validation
        # Make pattern more precise to avoid false positives
        svg_pattern = r'<svg[^>]*>.*?</svg>'
        svg_matches = re.findall(svg_pattern, html_str, re.DOTALL)

        for i, svg_content in enumerate(svg_matches):
            # Basic validation to filter out false positives
            # Valid SVG should have viewport attributes or viewBox
            if (re.search(r'width=["\']\\d+(?:px|%|em|rem)?["\']', svg_content) and 
                re.search(r'height=["\']\d+(?:px|%|em|rem)?["\']', svg_content)) or \
               re.search(r'viewBox=["\']\d+\s+\d+\s+\d+\s+\d+["\']', svg_content):

                # Additional validation - SVG should have at least one shape or path
                if re.search(r'<(?:path|rect|circle|ellipse|line|polyline|polygon|text)[^>]*>', svg_content):
                    results.append({
                        "name": f"extracted_svg_{i+1}.svg",
                        "content": svg_content.encode('utf-8'),
                        "size": len(svg_content),
                        "type": "image/svg+xml",
                        "source": "embedded_svg"
                    })
                    print(f"Extracted valid SVG image {i+1}: ({len(svg_content)} bytes)")
            else:
                print(f"Skipped invalid SVG match {i+1}")

    except Exception as e:
        print(f"Error extracting base64 images from HTML: {str(e)}")

    return results


def analyze_file(content, filename, recursion_depth=0, max_recursion=1, content_hashes=None):
    """
    Analyze a file to detect hidden files and determine file types.

    Args:
        content (bytes): The file content as bytes
        filename (str): The filename
        recursion_depth (int): Current recursion depth for nested analysis
        max_recursion (int): Maximum allowed recursion depth to prevent deep nested analysis
        content_hashes (set): Set to track content hashes

    Returns:
        list: List of detected files with metadata
    """
    detected_files = []

    # Safety check for recursion
    if recursion_depth > max_recursion:
        print(f"Maximum recursion depth reached ({max_recursion}), stopping further analysis")
        return detected_files

    # Initialize or use provided content hashes
    if content_hashes is None:
        content_hashes = set()

    # Add the original file hash and skip if already seen
    original_hash = generate_file_hash(content)['md5']
    if original_hash in content_hashes:
        return []
    content_hashes.add(original_hash)

    # Add the original file to the list
    result = determine_file_type_extension(content)
    file_type = result[0]
    extension = result[1] if len(result) > 1 else ''


    # If the determined extension doesn't match the original filename extension,
    # use the determined extension for a more accurate file type
    original_extension = os.path.splitext(filename)[1][1:] if '.' in filename else ''
    if not original_extension or original_extension.lower() != extension.lower():
        if extension:
            filename = os.path.splitext(filename)[0] + '.' + extension

    detected_files.append({
        "name": filename,
        "content": content,
        "size": len(content),
        "type": file_type,
        "content_hash": original_hash,
        "extension": extension
    })

    # Special handling for HTML files - look for embedded Base64 images
    if file_type == 'text/html' and recursion_depth == 0:
        base64_images = extract_base64_images_from_html(content)
        if base64_images:
            detected_files.extend(base64_images)

    # Only explore nested content if we haven't reached max depth
    if recursion_depth < max_recursion:
        # Check for archive files and extract contents
        extracted = extract_from_archive(content, file_type)
        if extracted:
            detected_files.extend(extracted)

        # Check for encoded content
        try:
            if isinstance(content, bytes):
                content_str = content.decode('utf-8', errors='ignore')
            else:
                content_str = content

            encoding_type = detect_encoding(content_str)
            if encoding_type:
                try:
                    print(f"Detected encoding: {encoding_type}")
                    decoded_content = decode_content(content_str, encoding_type)
                    result = determine_file_type_extension(decoded_content)
                    decoded_type = result[0]
                    decoded_ext = result[1] if len(result) > 1 else 'bin'

                    # Add any decoded content that we can identify
                    # PDF files and binary data will have a meaningful type other than text/plain
                    # Also check file size to ensure it's not just a tiny fragment
                    if len(decoded_content) > 500:  # Increased minimum size to avoid tiny fragments
                        # Check for valid file signatures in decoded content to filter out garbage
                        valid_decoded = False

                        # For PDFs - use robust validation
                        if decoded_content.startswith(b'%PDF'):
                            # Enhanced validation with multiple PDF markers
                            has_pages = b'/Pages' in decoded_content[:2000]
                            has_endobj = b'endobj' in decoded_content[:5000]
                            has_startxref = b'startxref' in decoded_content
                            has_trailer = b'trailer' in decoded_content or b'/Trailer' in decoded_content
                            has_eof = b'%%EOF' in decoded_content

                            # Only consider valid if all required PDF structure markers are present
                            if has_pages and has_endobj and has_startxref and has_trailer and has_eof:
                                valid_decoded = True
                                decoded_type = "application/pdf"
                                decoded_ext = "pdf"
                                print("Detected PDF with valid structure")
                            else:
                                print("Rejected PDF with incomplete structure")

                        # For ZIP files
                        elif decoded_content.startswith(b'PK\x03\x04'):
                            if b'PK\x01\x02' in decoded_content[:8192]:  # Central directory header
                                valid_decoded = True

                        # For images                        
                        elif (decoded_content.startswith(b'\xFF\xD8\xFF') or  # JPEG
                              decoded_content.startswith(b'\x89PNG\r\n\x1A\n') or  # PNG
                              decoded_content.startswith((b'GIF87a', b'GIF89a'))):  # GIF
                            valid_decoded = True

                        # For other common formats with a content type assigned
                        elif decoded_type and decoded_type not in ('text/plain', 'application/octet-stream'):
                            valid_decoded = True

                        # For text-like content, validate it has reasonable character distribution
                        elif decoded_type == 'text/plain':
                            try:
                                text = decoded_content.decode('utf-8', errors='strict')
                                # Only accept if it has a reasonable amount of text characters
                                if re.search(r'[a-zA-Z0-9.,;:!?()}{"\' ]{20,}', text):
                                    valid_decoded = True
                            except:
                                # Not valid UTF-8 text
                                pass

                        if valid_decoded:
                            # Compare hash before adding
                            decoded_hash = generate_file_hash(decoded_content)['md5']
                            if decoded_hash not in content_hashes:
                                content_hashes.add(decoded_hash)
                                detected_files.append({
                                    "name": f"decoded_{os.path.splitext(filename)[0]}.{decoded_ext}",
                                    "content": decoded_content,
                                    "size": len(decoded_content),
                                    "type": decoded_type,
                                    "encoding": encoding_type
                                })

                            # Recursively check decoded content for nested files, but only if we're not at max depth
                            if recursion_depth + 1 <= max_recursion:
                                # Use extract_file_content directly instead of a recursive analyze_file call 
                                # to avoid double-analysis of the same content
                                nested_files = extract_file_content(
                                    decoded_content,
                                    recursion_depth + 1,
                                    max_recursion,
                                    content_hashes=content_hashes
                                )
                                if nested_files:
                                    detected_files.extend(nested_files)
                except Exception as e:
                    # If decoding fails, log and continue with other checks
                    print(f"Error decoding content: {str(e)}")

                    # Try special handling for files where normal decoding fails
                    try:
                        # For base64, try a more aggressive approach by ignoring non-base64 chars
                        if encoding_type == "base64":
                            clean_data = re.sub(r'[^A-Za-z0-9+/=]', '', content_str)
                            if len(clean_data) % 4 != 0:
                                clean_data += '=' * (4 - len(clean_data) % 4)

                            try:
                                decoded_content = base64.b64decode(clean_data)
                                result = determine_file_type_extension(decoded_content)
                                decoded_type = result[0]
                                decoded_ext = result[1] if len(result) > 1 else 'bin'

                                # Check if it looks like a valid file - use the same validation as above
                                valid_decoded = False

                                if decoded_content.startswith(b'%PDF'):
                                    # Apply the same robust PDF validation as above
                                    has_pages = b'/Pages' in decoded_content[:2000]
                                    has_endobj = b'endobj' in decoded_content[:5000]
                                    has_startxref = b'startxref' in decoded_content
                                    has_trailer = b'trailer' in decoded_content or b'/Trailer' in decoded_content
                                    has_eof = b'%%EOF' in decoded_content

                                    # Only consider valid if all required markers are present
                                    if has_pages and has_endobj and has_startxref and has_trailer and has_eof:
                                        valid_decoded = True
                                        decoded_type = "application/pdf" 
                                        decoded_ext = "pdf"
                                        print("Detected PDF with valid structure in special handling")
                                    else:
                                        print("Rejected PDF with incomplete structure in special handling")
                                elif decoded_type and decoded_type not in ('text/plain', 'application/octet-stream'):
                                    valid_decoded = True

                                if valid_decoded and len(decoded_content) > 500:
                                    detected_files.append({
                                        "name": f"decoded_{os.path.splitext(filename)[0]}.{decoded_ext}",
                                        "content": decoded_content,
                                        "size": len(decoded_content),
                                        "type": decoded_type,
                                        "encoding": encoding_type
                                    })
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception as e:
            # If any error occurs during encoding detection, log and continue with other checks
            print(f"Error during encoding detection: {str(e)}")

        # Look for embedded files and hidden content at recursion level 0
        if recursion_depth == 0:
            # Check for known hidden content markers
            hidden_markers = find_hidden_markers(content)
            for pos, encoding in hidden_markers:
                hidden_content = extract_hidden_content(content, pos, encoding)
                if hidden_content:
                    # Generate name and analyze extracted content
                    hidden_name = f"hidden_{encoding}_{len(detected_files)}"
                    result = determine_file_type_extension(hidden_content)
                    hidden_type = result[0]
                    hidden_ext = result[1] if len(result) > 1 else ''
                    if hidden_ext:
                        hidden_name += f".{hidden_ext}"

                    detected_files.append({
                        "name": hidden_name,
                        "content": hidden_content,
                        "size": len(hidden_content),
                        "type": hidden_type,
                        "source": f"hidden_{encoding}"
                    })

            # Look for traditionally embedded files
            embedded_files = extract_file_content(content, recursion_depth, max_recursion, content_hashes)
            if embedded_files:
                detected_files.extend(embedded_files)

    return detected_files

def extract_from_archive(content, file_type):
    """
    Extract files from archive formats (zip, tar, etc.)

    Args:
        content (bytes): Archive file content
        file_type (str): MIME type of the content

    Returns:
        list: Extracted files with metadata
    """
    extracted_files = []

    # Handle ZIP files
    if file_type == "application/zip" or file_type == "application/x-zip-compressed":
        try:
            with zipfile.ZipFile(BytesIO(content)) as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.file_size > 0 and not file_info.is_dir():
                        extracted_content = zip_ref.read(file_info.filename)
                        result = determine_file_type_extension(extracted_content)
                        extracted_type = result[0]
                        extension = result[1] if len(result) > 1 else ''

                        extracted_files.append({
                            "name": os.path.basename(file_info.filename),
                            "content": extracted_content,
                            "size": file_info.file_size,
                            "type": extracted_type,
                            "source": "zip"
                        })
        except Exception as e:
            # If ZIP extraction fails, continue with other checks
            pass

    # Handle TAR files
    elif file_type in ["application/x-tar", "application/x-gtar"]:
        try:
            with tarfile.open(fileobj=BytesIO(content), mode="r:*") as tar_ref:
                for member in tar_ref.getmembers():
                    if member.isfile() and member.size > 0:
                        extracted_content = tar_ref.extractfile(member).read()
                        result = determine_file_type_extension(extracted_content)
                        extracted_type = result[0]
                        extension = result[1] if len(result) > 1 else ''

                        extracted_files.append({
                            "name": os.path.basename(member.name),
                            "content": extracted_content,
                            "size": member.size,
                            "type": extracted_type,
                            "source": "tar"
                        })
        except Exception as e:
            # If TAR extraction fails, continue with other checks
            pass

    # Handle GZIP files
    elif file_type == "application/gzip":
        try:
            with gzip.GzipFile(fileobj=BytesIO(content), mode="rb") as gz_ref:
                extracted_content = gz_ref.read()
                result = determine_file_type_extension(extracted_content)
                extracted_type = result[0]
                extension = result[1] if len(result) > 1 else ''

                extracted_files.append({
                    "name": f"extracted.{extension}",
                    "content": extracted_content,
                    "size": len(extracted_content),
                    "type": extracted_type,
                    "source": "gzip"
                })
        except Exception as e:
            # If GZIP extraction fails, continue with other checks
            pass

    # Handle BZ2 files
    elif file_type == "application/x-bzip2":
        try:
            extracted_content = bz2.decompress(content)
            result = determine_file_type_extension(extracted_content)
            extracted_type = result[0]
            extension = result[1] if len(result) > 1 else ''

            extracted_files.append({
                "name": f"extracted.{extension}",
                "content": extracted_content,
                "size": len(extracted_content),
                "type": extracted_type,
                "source": "bzip2"
            })
        except Exception as e:
            # If BZ2 extraction fails, continue with other checks
            pass

    # Handle XZ/LZMA files
    elif file_type == "application/x-xz":
        try:
            extracted_content = lzma.decompress(content)
            result = determine_file_type_extension(extracted_content)
            extracted_type = result[0]
            extension = result[1] if len(result) > 1 else ''

            extracted_files.append({
                "name": f"extracted.{extension}",
                "content": extracted_content,
                "size": len(extracted_content),
                "type": extracted_type,
                "source": "lzma"
            })
        except Exception as e:
            # If LZMA extraction fails, continue with other checks
            pass

    return extracted_files

def validate_image_content(content, extension):
    """
    Strictly validate image content to reduce false positives
    
    Args:
        content (bytes): Image content to validate
        extension (str): Expected image extension
        
    Returns:
        bool: True if valid image, False otherwise
    """
    try:
        if extension == 'jpg' or extension == 'jpeg':
            # JPEG validation
            if not content.startswith(b'\xFF\xD8\xFF'):
                return False
                
            # Check for proper JPEG structure
            # Must have SOI (\xFF\xD8) at start and EOI (\xFF\xD9) at end
            if not content.endswith(b'\xFF\xD9'):
                return False
                
            # Check for JFIF or Exif marker
            if not (b'JFIF' in content[:23] or b'Exif' in content[:23]):
                return False
                
            # Minimum size for a valid JPEG (header + minimal image data)
            if len(content) < 128:
                return False
                
        elif extension == 'png':
            # PNG validation
            if not content.startswith(b'\x89PNG\r\n\x1a\n'):
                return False
                
            # Must have IHDR chunk after signature
            if b'IHDR' not in content[8:24]:
                return False
                
            # Must have IEND chunk at end
            if not content.endswith(b'IEND\xaeB`\x82'):
                return False
                
            # Minimum size for a valid PNG
            if len(content) < 57:  # Header + IHDR + IEND
                return False
                
        elif extension == 'gif':
            # GIF validation
            if not content.startswith((b'GIF87a', b'GIF89a')):
                return False
                
            # Check for proper structure (must have global color table and image descriptor)
            if len(content) < 38:  # Minimum size for GIF header + color table
                return False
                
            # Must end with semicolon
            if not content.endswith(b'\x3B'):
                return False
                
        elif extension == 'bmp':
            # BMP validation
            if not content.startswith(b'BM'):
                return False
                
            # Check minimum size for BMP header
            if len(content) < 54:  # Standard BMP header size
                return False
                
            # Validate BMP header
            try:
                size = int.from_bytes(content[2:6], 'little')
                if size != len(content):
                    return False
            except:
                return False
        
        # Additional general image validation
        try:
            # Try to open and verify the image
            img = Image.open(io.BytesIO(content))
            img.verify()  # Verify image data
            
            # Check reasonable dimensions
            if img.size[0] < 8 or img.size[1] < 8:  # Minimum 8x8 pixels
                return False
            if img.size[0] > 16384 or img.size[1] > 16384:  # Max 16384x16384 pixels
                return False
                
            return True
        except:
            return False
            
    except Exception as e:
        print(f"Error validating image: {str(e)}")
        return False

def extract_file_content(content, recursion_depth=0, max_recursion=1, content_hashes=None):
    """
    Extract embedded files from content by looking for file signatures

    Args:
        content (bytes): Content to analyze
        recursion_depth (int): Current recursion depth for nested analysis
        max_recursion (int): Maximum allowed recursion depth to prevent deep nested analysis
        content_hashes (set): Set to track content hashes

    Returns:
        list: Detected embedded files
    """
    embedded_files = []

    # Initialize set to track content hashes if not provided
    if content_hashes is None:
        content_hashes = set()

    # Convert content to hex for signature scanning
    hex_content = content.hex()

    # Common file signatures in hex
    signatures = {
        'ffd8ff': {'ext': 'jpg', 'mime': 'image/jpeg'},
        '89504e47': {'ext': 'png', 'mime': 'image/png'},
        '4749463837': {'ext': 'gif', 'mime': 'image/gif'},
        '4749463839': {'ext': 'gif', 'mime': 'image/gif'},
        '25504446': {'ext': 'pdf', 'mime': 'application/pdf'},
        '504b0304': {'ext': 'zip', 'mime': 'application/zip'},
        '4d5a': {'ext': 'exe', 'mime': 'application/x-msdownload'},
        '7f454c46': {'ext': 'elf', 'mime': 'application/x-executable'},
        '377abcaf': {'ext': '7z', 'mime': 'application/x-7z-compressed'},
        '1f8b08': {'ext': 'gz', 'mime': 'application/gzip'},
        'cafebabe': {'ext': 'class', 'mime': 'application/java'},
        '526172211a': {'ext': 'rar', 'mime': 'application/x-rar-compressed'},
    }

    # Scan for file signatures in hex content
    for signature, info in signatures.items():
        start_pos = 0
        while True:
            pos = hex_content.find(signature, start_pos)
            if pos == -1:
                break

            # Calculate byte position
            byte_pos = pos // 2

            # Extract content from signature position
            potential_file = content[byte_pos:]

            # Validate extracted content
            try:
                # Get file type using python-magic
                detected_type = magic.from_buffer(potential_file, mime=True)

                # Additional validation based on file type
                is_valid = False

                if info['ext'] == 'exe' and potential_file.startswith(b'MZ'):
                    # Check for PE header
                    if len(potential_file) > 0x40:
                        pe_offset = int.from_bytes(potential_file[0x3C:0x40], byteorder='little')
                        if pe_offset < len(potential_file)-1 and potential_file[pe_offset:pe_offset+2] == b'PE':
                            is_valid = True

                elif info['ext'] in ['jpg', 'jpeg'] and potential_file.startswith(b'\xFF\xD8\xFF'):
                    # Look for JPEG end marker
                    if b'\xFF\xD9' in potential_file:
                        end_pos = potential_file.find(b'\xFF\xD9') + 2
                        potential_file = potential_file[:end_pos]
                        is_valid = True

                elif info['ext'] == 'png' and potential_file.startswith(b'\x89PNG\r\n\x1A\n'):
                    # Look for PNG IEND chunk
                    if b'IEND' in potential_file:
                        end_pos = potential_file.find(b'IEND') + 8
                        potential_file = potential_file[:end_pos]
                        is_valid = True

                elif info['ext'] == 'pdf' and potential_file.startswith(b'%PDF'):
                    # Look for PDF EOF marker
                    if b'%%EOF' in potential_file:
                        end_pos = potential_file.find(b'%%EOF') + 5
                        potential_file = potential_file[:end_pos]
                        is_valid = True

                else:
                    # For other types, trust the magic number
                    is_valid = detected_type == info['mime']

                if is_valid:
                    embedded_files.append({
                        "name": f"embedded_{len(embedded_files)}_{info['ext']}",
                        "content": potential_file,
                        "size": len(potential_file),
                        "type": info['mime'],
                        "source": "hex_signature",
                        "extension": info['ext']
                    })

            except Exception:
                pass

            start_pos = pos + len(signature)

    # Only perform deep analysis if recursion depth is permitted
    # For low recursion depth settings, we'll be more conservative to prevent false positives
    conservative_mode = max_recursion < 2

    # Common file signatures (magic numbers) and their corresponding extensions
    # Using more specific/longer signatures to reduce false positives
    file_signatures = [
        # Images - more specific signatures 
        (b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46', 'jpg'),  # JPEG/JFIF
        (b'\xFF\xD8\xFF\xE1', 'jpg'),  # JPEG/Exif
        (b'\x89PNG\r\n\x1A\n', 'png'),  # PNG - already specific
        (b'GIF87a', 'gif'),  # GIF87a
        (b'GIF89a', 'gif'),  # GIF89a
        (b'BM\x76\x01', 'bmp'),  # BMP with more specific header check
        # Documents - more specific signatures where possible
        (b'%PDF-1.', 'pdf'),  # PDF with version
        (b'PK\x03\x04\x14\x00\x06\x00', 'docx'),  # DOCX/Office XML
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'doc'),  # DOC/XLS/PPT (OLE)
        # Archives - more specific
        (b'PK\x03\x04\x14\x00\x00\x00\x08\x00', 'zip'),  # ZIP with specific header
        # Executables - more specific signatures to avoid false positives
        (b'MZ\x90\x00', 'exe'),  # EXE with a more specific header check
        (b'\x7FELF\x01\x01\x01', 'elf'),  # ELF with more specific header
        # Media - already specific
        (b'\x00\x00\x00\x18ftypmp4', 'mp4'),  # MP4
        (b'\x1A\x45\xDF\xA3\x01\x00\x00\x00', 'mkv'),  # MKV more specific
        (b'ID3\x03\x00', 'mp3'),  # MP3 with version check
        (b'RIFF....WAVE', 'wav'),  # WAV with format check (.... means any 4 bytes)
    ]

    # Convert to bytes if it's a string
    if isinstance(content, str):
        content = content.encode('utf-8', errors='ignore')

    # Search for file signatures in the content
    for signature, extension in file_signatures:
        offset = 0
        while True:
            pos = content.find(signature, offset)
            if pos == -1:
                break

            # For signatures with wildcards (e.g., "RIFF....WAVE")
            if b'.' in signature:
                pattern_parts = signature.split(b'.')
                matched = True
                current_pos = pos

                for part in pattern_parts:
                    if part:  # Skip empty parts
                        if content[current_pos:current_pos+len(part)] != part:
                            matched = False
                            break
                        current_pos += len(part)
                    else:  # For '.' wildcard
                        current_pos += 1

                if not matched:
                    offset = pos + 1
                    continue

            # Extract potential file content from signature position
            try:
                # Try to identify the file type from this position
                file_content = content[pos:]

                # Skip very small fragments - they're likely false positives
                if len(file_content) < 1024:  # Require at least 1KB
                    offset = pos + len(signature)
                    continue

                # Use python-magic to identify file type
                file_type = magic.from_buffer(file_content, mime=True)

                # Enhanced validation to reduce false positives
                valid_file = False

                # PDF validation - Check for proper PDF structure with enhanced validation
                if extension == 'pdf' and file_content.startswith(b'%PDF-1.'):
                    # PDFs must have ALL these specific PDF structural elements to be considered valid
                    has_pages = b'/Pages' in file_content[:2000]
                    has_endobj = b'endobj' in file_content[:3000]
                    has_startxref = b'startxref' in file_content
                    has_trailer = b'trailer' in file_content or b'/Trailer' in file_content
                    has_eof = b'%%EOF' in file_content

                    # Only consider valid if ALL required markers are present
                    valid_file = has_pages and has_endobj and has_startxref and has_trailer and has_eof

                # EXE validation - Check for proper PE header structure
                elif extension == 'exe' and file_content.startswith(b'MZ'):
                    # Look for PE header marker which should be present in legitimate executables
                    pe_header_offset = content[pos+0x3C:pos+0x40]
                    if len(pe_header_offset) == 4:
                        try:
                            pe_offset = int.from_bytes(pe_header_offset, byteorder='little')
                            # Check if PE signature exists at the calculated offset
                            if pe_offset < len(file_content) - 2 and file_content[pe_offset:pe_offset+2] == b'PE':
                                valid_file = True
                        except:
                            pass

                # ZIP, DOCX validation
                elif extension in ('zip', 'docx') and file_content.startswith(b'PK\x03\x04'):
                    # ZIP files should have at least one directory entry
                    if b'PK\x01\x02' in file_content[:8192]:  # Central directory header
                        valid_file = True

                # Image validation - typically they have reasonable size and proper format
                elif extension in ('jpg', 'png', 'gif', 'bmp'):
                    # Images should have a reasonable size and matching mime type
                    if (('image/' in file_type) and 
                            len(file_content) > 100 and
                            len(file_content) < 20 * 1024 * 1024):  # 20MB max for images
                        valid_file = True

                # For other file types, use basic mime type validation
                elif file_type and file_type != "application/octet-stream" and file_type != "text/plain":
                    # Additional check: known extension should match detected mime type
                    if ((extension == 'mp4' and file_type in ('video/mp4', 'application/mp4')) or
                        (extension == 'mp3' and file_type in ('audio/mpeg', 'audio/mp3')) or
                        (extension == 'wav' and file_type == 'audio/wav') or
                        (extension == 'mkv' and file_type in ('video/x-matroska', 'application/x-matroska'))):
                        valid_file = True

                # Apply additional restrictions in conservative mode
                if conservative_mode:
                    # In conservative mode, we only allow certain file types to reduce false positives
                    if extension in ('exe', 'elf'):
                        # Disable executable detection completely in conservative mode
                        valid_file = False
                    elif extension in ('zip', 'docx'):
                        # Require stronger ZIP validation in conservative mode
                        if not (file_content.startswith(b'PK\x03\x04') and 
                                b'PK\x01\x02' in file_content[:4096] and
                                b'PK\x05\x06' in file_content):  # End of central directory
                            valid_file = False
                    elif extension == 'pdf':
                        # In conservative mode, only accept PDFs with perfect structure
                        if not (file_content.startswith(b'%PDF-1.') and \
                                b'/Pages' in file_content[:2000] and \
                                b'endobj' in file_content[:3000] and \
                                b'startxref' in file_content and \
                                (b'trailer' in file_content or b'/Trailer' in file_content) and \
                                b'%%EOF' in file_content):
                            valid_file = False

                # Only add validated files to the results
                if valid_file:
                    # Increase size limit to 200MB
                    max_size = min(200 * 1024 * 1024, len(file_content))  # 200MB or file size, whichever is smaller

                    # Check content hash before adding
                    file_hash = generate_file_hash(file_content[:max_size])['md5']
                    if file_hash not in content_hashes:
                        content_hashes.add(file_hash)
                        embedded_files.append({
                        "name": f"embedded_{len(embedded_files) + 1}.{extension}",
                        "content": file_content[:max_size],
                        "size": max_size,
                        "type": file_type,
                        "source": "embedded",
                        "extension": extension
                    })
            except Exception as e:
                print(f"Error processing potential embedded file: {str(e)}")
                pass

            # Move past this signature with a larger step to avoid overlapping detections
            offset = pos + len(signature)

    return embedded_files

def find_hidden_markers(content):
    """
    Detect potential hidden content markers using advanced pattern matching and entropy analysis

    Args:
        content (bytes): Content to analyze

    Returns:
        list: List of tuples containing (position, encoding_type, metadata)
    """
    markers = []

    try:
        # Also look for custom BASE64 marker
        if isinstance(content, bytes):
            base64_marker = b'\x00BASE64\x00'
            marker_pos = content.find(base64_marker)
            if marker_pos != -1:
                try:
                    # Read 4 bytes after marker for length
                    marker_start = marker_pos + len(base64_marker)
                    length_bytes = content[marker_start:marker_start + 4]
                    length = int.from_bytes(length_bytes, 'big')
                    
                    # Validate length is reasonable (up to 200MB)
                    if 0 < length <= 200 * 1024 * 1024:
                        # Extract the complete base64 content
                        content_end = marker_start + 4 + length
                        if content_end <= len(content):
                            base64_content = content[marker_start + 4:content_end]
                            if len(base64_content) == length:
                                markers.append((marker_pos, "base64"))
                                print(f"Found valid BASE64 marker with length {length}")
                            else:
                                print("Incomplete BASE64 content")
                        else:
                            print("BASE64 content extends beyond file end")
                    else:
                        print(f"Invalid BASE64 length: {length}")

                except Exception as e:
                    print(f"Error processing custom BASE64 marker: {str(e)}")

        content_str = content.decode('utf-8', errors='ignore') if isinstance(content, bytes) else str(content)

        # 1. Detect Base64 encoded content with validation
        base64_pattern = r"(?:[A-Za-z0-9+/]{4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)"
        for match in re.finditer(base64_pattern, content_str):
            base64_str = match.group()
            try:
                decoded = base64.b64decode(base64_str, validate=True)
                if len(decoded) > 64:
                    result = determine_file_type_extension(decoded)
                    file_type = result[0]
                    if file_type not in ['text/plain', 'application/octet-stream']:
                        markers.append((match.start(), "base64"))
            except (binascii.Error, ValueError):
                continue

        # 2. Detect hex-encoded content with validation
        hex_pattern = r"(?:[0-9a-fA-F]{2}\s*){8,}"
        for match in re.finditer(hex_pattern, content_str):
            hex_str = match.group().replace(" ", "")
            if len(hex_str) % 2 != 0:
                continue

            try:
                decoded = bytes.fromhex(hex_str)
                if len(decoded) >= 16:
                    result = determine_file_type_extension(decoded)
                    file_type = result[0]
                    markers.append((match.start(), "hex"))
            except ValueError:
                continue

        # 3. Detect suspicious patterns
        suspicious_js_patterns = [
            r"eval\(.*?\)",
            r"document\.write\(.*?\)",
            r"(?:fromCharCode|createElement|appendChild)\(.*?\)",
            r"\\x[0-9a-fA-F]{2}"
        ]
        for pattern in suspicious_js_patterns:
            for match in re.finditer(pattern, content_str):
                markers.append((match.start(), "suspicious_js"))

    except Exception as e:
        print(f"Error in hidden marker detection: {str(e)}")

    return markers

def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence"""
    if not data:
        return 0

    entropy = 0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    for count in counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy

def extract_hidden_content(content, pos, encoding, metadata=None):
    """
    Extract and validate hidden content with improved validation
    
    Args:
        content (bytes): Original content
        pos (int): Position in content where hidden data starts
        encoding (str): Encoding type detected
        metadata (dict): Additional detection metadata
        
    Returns:
        bytes: Extracted content if valid, None otherwise
    """
    try:
        if encoding == "base64":
            # Method 1: Custom marker-based extraction
            if pos + 8 <= len(content) and content[pos:pos+8] == b'\x00BASE64\x00':
                try:
                    # Extract length from the 4 bytes after marker
                    length = int.from_bytes(content[pos+8:pos+12], 'big')
                    
                    # Validate length is reasonable (increased to handle larger files)
                    if 0 < length <= 500 * 1024 * 1024:  # 500MB limit
                        # Extract the exact base64 content
                        base64_content = content[pos+12:pos+12+length]
                        if len(base64_content) == length:
                            try:
                                decoded = base64.b64decode(base64_content)
                                return decoded
                            except Exception as e:
                                print(f"Error decoding marked base64 content: {str(e)}")
                except Exception as e:
                    print(f"Error processing custom BASE64 marker: {str(e)}")
            
            # Method 2: Standard base64 pattern detection
            else:
                try:
                    # Look for base64 content starting at pos
                    base64_str = ""
                    while pos < len(content):
                        char = chr(content[pos])
                        if char in string.ascii_letters + string.digits + '+/=':
                            base64_str += char
                            pos += 1
                        else:
                            break

                    # Add padding if needed
                    missing_padding = len(base64_str) % 4
                    if missing_padding:
                        base64_str += '=' * (4 - missing_padding)

                    # Only try to decode if we have enough data
                    if len(base64_str) >= 24:  # Minimum reasonable base64 length
                        try:
                            decoded = base64.b64decode(base64_str, validate=True)
                            # Validate decoded content
                            if len(decoded) > 500:  # Minimum size threshold
                                result = determine_file_type_extension(decoded)
                                if result[0] not in ('application/octet-stream', 'text/plain'):
                                    return decoded
                        except Exception:
                            pass
                except Exception as e:
                    print(f"Error processing standard base64 content: {str(e)}")

        elif encoding == "hex":
            hex_str = ""
            while pos < len(content):
                char = chr(content[pos]).lower()
                if char in string.hexdigits:
                    hex_str += char
                    pos += 1
                else:
                    break

            if len(hex_str) % 2 != 0:
                hex_str = hex_str[:-1]

            try:
                decoded = bytes.fromhex(hex_str)
                if len(decoded) >= 16:
                    # Calculate entropy
                    sample = decoded[:4096]
                    entropy = calculate_entropy(sample)
            
                    # Check entropy is in valid range
                    if 4.5 <= entropy <= 7.5:
                        result = determine_file_type_extension(decoded)
                        if result[0] not in ['application/octet-stream', 'text/plain']:
                            return validate_extracted_content(decoded)
            except ValueError:
                pass
            return None

        elif encoding == "suspicious_js":
            start = max(0, pos - 50)
            end = min(len(content), pos + 150)
            return content[start:end]

        return None
    except Exception as e:
        print(f"Error extracting {encoding} content: {str(e)}")
        return None

def validate_extracted_content(data, min_size=128):
    """
    Validate extracted content through multiple checks

    Args:
        data (bytes): Data to validate
        min_size (int): Minimum valid file size

    Returns:
        bytes: Validated data or None
    """
    if not data or len(data) < min_size:
        return None
        
    # More stringent validation for embedded content
    try:
        result = determine_file_type_extension(data)
        file_type = result[0]
        
        # Skip generic binary data
        if file_type == 'application/octet-stream':
            return None
            
        # Validate PDFs more thoroughly
        if file_type == 'application/pdf':
            if not (data.startswith(b'%PDF-') and
                   b'/Pages' in data[:4096] and
                   b'endobj' in data and
                   b'startxref' in data and
                   b'%%EOF' in data[-1024:]):
                return None
    except Exception as e:
        print(f"Error validating content: {str(e)}")
        return None

    result = determine_file_type_extension(data)
    file_type = result[0]
    if file_type == 'application/octet-stream':
        return None

    if file_type == 'application/pdf':
        if not all([b'%PDF-' in data[:5],
                   b'/Pages' in data[:4096],
                   b'endobj' in data,
                   b'startxref' in data,
                   b'%%EOF' in data[-1024:]]):
            return None

    entropy = calculate_entropy(data[:4096])
    if entropy > 7.5 and file_type == 'application/octet-stream':
        return None

    if file_type.startswith('text/'):
        printable = sum(b in string.printable.encode() for b in data)
        if printable / len(data) < 0.8:
            return None

    return data
