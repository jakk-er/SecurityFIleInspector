import streamlit as st
import os
import tempfile
import validators
import requests
import time
import json
import re
from io import BytesIO
import trafilatura

from file_analyzer import analyze_file, extract_file_content
from encoding_detector import detect_encoding, decode_content
from virustotal_api import scan_file, get_scan_results
from utils import download_from_url, determine_file_type_extension, generate_file_hash

# Function to extract and process web content
def extract_web_content(url, content):
    """
    Extract and process web content for further analysis
    
    Args:
        url (str): URL that was downloaded
        content (bytes): Raw content downloaded from the URL
        
    Returns:
        list: List of extracted files for analysis
    """
    results = []
    
    # First, add the original HTML content
    results.append({
        "name": f"{url.split('/')[-1] or 'index'}.html",
        "content": content,
        "size": len(content),
        "type": "text/html",
        "source": "original"
    })
    
    try:
        # Convert bytes to string for trafilatura and other operations
        html_str = content.decode('utf-8', errors='ignore')
        
        # Extract main text content using trafilatura
        downloaded = trafilatura.extract(html_str)
        if downloaded:
            results.append({
                "name": f"{url.split('/')[-1] or 'index'}_text.txt",
                "content": downloaded.encode('utf-8'),
                "size": len(downloaded),
                "type": "text/plain",
                "source": "extracted_text"
            })
        
        # Extract CSS
        css_patterns = [
            r'<style[^>]*>(.*?)</style>',
            r'<link[^>]*rel=["\']\s*stylesheet\s*["\'],[^>]*href=["\'](.*?)["\'][^>]*>'
        ]
        
        # Extract all CSS blocks
        all_css = []
        for pattern in css_patterns:
            css_matches = re.findall(pattern, html_str, re.DOTALL)
            all_css.extend(css_matches)
        
        if all_css:
            combined_css = '\n\n'.join(all_css)
            results.append({
                "name": f"{url.split('/')[-1] or 'index'}_styles.css",
                "content": combined_css.encode('utf-8'),
                "size": len(combined_css),
                "type": "text/css",
                "source": "extracted_css"
            })
        
        # Extract JavaScript
        js_patterns = [
            r'<script[^>]*>(.*?)</script>',
            r'<script[^>]*src=["\'](.*?)["\'][^>]*>'
        ]
        
        # Extract all JavaScript blocks
        all_js = []
        for pattern in js_patterns:
            js_matches = re.findall(pattern, html_str, re.DOTALL)
            all_js.extend(js_matches)
        
        if all_js:
            combined_js = '\n\n'.join(all_js)
            results.append({
                "name": f"{url.split('/')[-1] or 'index'}_scripts.js",
                "content": combined_js.encode('utf-8'),
                "size": len(combined_js),
                "type": "text/javascript",
                "source": "extracted_js"
            })
        
        # Extract links
        links = re.findall(r'<a[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>', html_str, re.DOTALL)
        if links:
            links_text = '\n'.join([f"{link[0]}: {link[1]}" for link in links])
            results.append({
                "name": f"{url.split('/')[-1] or 'index'}_links.txt",
                "content": links_text.encode('utf-8'),
                "size": len(links_text),
                "type": "text/plain",
                "source": "extracted_links"
            })
        
        # Extract image URLs and download when possible
        img_patterns = [
            r'<img[^>]*src=["\'](.*?)["\'][^>]*>',  # Regular image tags
            r'url\(["\']?(.*?)["\']?\)',  # CSS background images
            r'content=["\'](.*?\.(?:jpg|jpeg|png|gif|webp|svg|bmp|ico))["\']'  # Meta image tags
        ]
        
        all_img_urls = []
        for pattern in img_patterns:
            found_urls = re.findall(pattern, html_str, re.IGNORECASE)
            all_img_urls.extend(found_urls)
        
        # Create a list of unique image URLs
        unique_img_urls = list(set(all_img_urls))
        
        if unique_img_urls:
            # First add a text file with all image URLs
            img_text = '\n'.join(unique_img_urls)
            results.append({
                "name": f"{url.split('/')[-1] or 'index'}_images.txt",
                "content": img_text.encode('utf-8'),
                "size": len(img_text),
                "type": "text/plain",
                "source": "extracted_image_urls"
            })
            
            # Try to download and analyze the image files
            base_url = url
            if not base_url.endswith('/'):
                base_url = base_url[:base_url.rfind('/')+1]
                
            for img_url in unique_img_urls[:10]:  # Limit to first 10 images to avoid overload
                try:
                    # Handle relative URLs
                    if img_url.startswith('//'):
                        img_url = 'http:' + img_url
                    elif not img_url.startswith(('http://', 'https://', 'data:')):
                        if img_url.startswith('/'):
                            # Absolute path from domain
                            domain = '/'.join(url.split('/')[:3])  # http(s)://domain.com
                            img_url = domain + img_url
                        else:
                            # Relative path
                            img_url = base_url + img_url
                    
                    # Skip data URIs as they're already embedded
                    if img_url.startswith('data:'):
                        continue
                    
                    # Attempt to download the image
                    try:
                        img_content = download_from_url(img_url)
                        if img_content:
                            img_name = img_url.split('/')[-1]
                            if not img_name or len(img_name) < 3:
                                # Generate a name if URL doesn't have a proper filename
                                extension = '.img'
                                # Try to determine extension from content
                                if img_content.startswith(b'\xff\xd8\xff'):
                                    extension = '.jpg'
                                elif img_content.startswith(b'\x89PNG\r\n\x1a\n'):
                                    extension = '.png'
                                elif img_content.startswith(b'GIF8'):
                                    extension = '.gif'
                                elif img_content.startswith(b'RIFF') and b'WEBP' in img_content[:20]:
                                    extension = '.webp'
                                
                                img_name = f"image_{len(results)}{extension}"
                            
                            # Add the image file to results
                            results.append({
                                "name": img_name,
                                "content": img_content,
                                "size": len(img_content),
                                "type": determine_file_type_extension(img_content)[0],
                                "source": "downloaded_image"
                            })
                    except Exception as e:
                        # If download fails, just skip this image
                        pass
                        
                except Exception as e:
                    # If URL processing fails, just skip this image
                    pass
            
    except Exception as e:
        st.error(f"Error extracting web content: {str(e)}")
    
    return results

# Function to categorize files as potentially malicious or benign
def categorize_files(files):
    """
    Categorize files as potentially malicious or benign based on file type
    
    Args:
        files (list): List of file dictionaries to categorize
        
    Returns:
        tuple: (potentially_malicious_files, benign_files)
    """
    potentially_malicious = []
    benign_media = []
    
    for file in files:
        file_type = file.get('type', '').lower()
        file_name = file.get('name', '').lower()
        #extension = os.path.splitext(file_name)[1][1:] if '.' in file_name else ''
        extension = file.get('extension', '').lower()
        
        # Check if file is a potentially malicious type
        is_malicious = False
        
        # Executable files and scripts
        if (
            file_type.startswith(('application/x-executable', 'application/x-msdos-program', 'application/x-msdownload')) or
            file_type.startswith(('application/x-sh', 'application/x-csh', 'application/x-perl', 'application/x-python')) or
            extension in ['exe', 'dll', 'sys', 'bin', 'scr', 'bat', 'cmd', 'vbs', 'ps1', 'js', 'py', 'pl', 'rb', 'sh'] or
            'script' in file_type
        ):
            is_malicious = True
        
        # ActiveX and Java
        elif (
            file_type.startswith('application/java') or
            extension in ['class', 'jar', 'ocx', 'cab']
        ):
            is_malicious = True
        
        # Macro-enabled documents
        elif (
            extension in ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm'] or
            (file_type == 'application/vnd.ms-office' and 'macro' in file_name)
        ):
            is_malicious = True
            
        # Any file that was specifically decoded or detected by special analysis
        elif 'encoding' in file or file.get('source') in ['decoded', 'special']:
            is_malicious = True
            
        # Benign media files (images, videos, audio, PDFs)
        elif (
            file_type.startswith(('image/', 'video/', 'audio/')) or
            file_type == 'application/pdf' or
            extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'mp3', 'mp4', 'wav', 'ogg', 'pdf']
        ):
            # Only categorize as benign if not decoded (decoded files might hide malicious content)
            if 'encoding' not in file:
                is_malicious = False
            else:
                is_malicious = True
        
        # Add to appropriate category
        if is_malicious:
            potentially_malicious.append(file)
        else:
            benign_media.append(file)
    
    return potentially_malicious, benign_media

# Set page configuration
st.set_page_config(
    page_title="Security File Inspector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"  # Hide sidebar initially
)

# Custom CSS for styling the UI
st.markdown("""
<style>
    /* Top navigation menu */
    .navigation-menu {
        display: flex;
        justify-content: center;
        gap: 20px;
        padding: 8px;
        margin-bottom: 15px;
        background-color: #f5f5f5;
        border-radius: 5px;
    }
    
    /* Results container */
    .results-container {
        background-color: #f9f9f9;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #ddd;
    }
    
    /* Make buttons full width */
    .stButton button {
        width: 100%;
    }
    
    /* Dropdown styling */
    .dropdown-container {
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    
    /* VirusTotal link box */
    .vt-link-box {
        background-color: #f0f8ff;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #b8daff;
        margin-top: 15px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
if 'extracted_files' not in st.session_state:
    st.session_state.extracted_files = []
if 'selected_file_index' not in st.session_state:
    st.session_state.selected_file_index = None
if 'vt_results' not in st.session_state:
    st.session_state.vt_results = None
if 'scan_id' not in st.session_state:
    st.session_state.scan_id = None
if 'api_key_missing' not in st.session_state:
    st.session_state.api_key_missing = False
if 'active_menu' not in st.session_state:
    st.session_state.active_menu = "File Scanner"
if 'user_api_key' not in st.session_state:
    st.session_state.user_api_key = ""
if 'show_all_files' not in st.session_state:
    st.session_state.show_all_files = False

# Get VirusTotal API key from environment variable or session state
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
if not VT_API_KEY and st.session_state.user_api_key:
    VT_API_KEY = st.session_state.user_api_key
    st.session_state.api_key_missing = False
elif not VT_API_KEY:
    st.session_state.api_key_missing = True

# Top horizontal navigation menu
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("File Scanner", use_container_width=True):
        st.session_state.active_menu = "File Scanner"
        st.rerun()
with col2:
    if st.button("About", use_container_width=True):
        st.session_state.active_menu = "About"
        st.rerun()
with col3:
    if st.button("Help", use_container_width=True):
        st.session_state.active_menu = "Help"
        st.rerun()

# Add visual indicator for active menu
st.markdown(f"""
<div style="text-align:center; margin-bottom:20px; padding:5px;">
    <span style="font-weight:bold; font-size:1.2rem; color:#4CAF50; border-bottom:2px solid #4CAF50; padding:5px 15px;">
        {st.session_state.active_menu}
    </span>
</div>
""", unsafe_allow_html=True)

st.title("Security File Inspector")

# Main content
if st.session_state.active_menu == "File Scanner":
    # Three-column layout
    left_col, middle_col, right_col = st.columns([1, 1, 1])
    
    with left_col:
        st.subheader("Input Options")
        
        # Initialize session state for input selection if not already present
        if 'active_input' not in st.session_state:
            st.session_state.active_input = None
        
        # Vertical layout for input options
        if st.button("📁 Upload File", use_container_width=True, key="btn_upload"):
            st.session_state.active_input = "upload"
            st.rerun()
        st.caption("Select a file from your device")
        
        st.markdown("<div style='margin: 8px 0;'></div>", unsafe_allow_html=True)
        
        if st.button("🔗 Enter URL", use_container_width=True, key="btn_url"):
            st.session_state.active_input = "url"
            st.rerun()
        st.caption("Enter a website URL")
        
        # Add a separator
        st.markdown("---")
        
        # File upload section - only show when selected
        uploaded_file = None
        url_input = ""
        text_input = ""
        
        if st.session_state.active_input == "upload":
            uploaded_file = st.file_uploader("Upload a file to analyze", type=None, key="file_upload")
            if uploaded_file is not None:
                st.success(f"File uploaded: {uploaded_file.name}")
        
        # URL input section - only show when selected
        elif st.session_state.active_input == "url":
            url_input = st.text_input("Enter a URL to analyze", key="url_input")
            if url_input:
                # Check if the URL is missing http/https prefix and add it
                if not url_input.startswith(('http://', 'https://')):
                    prefixed_url = 'http://' + url_input
                    # Validate with the prefix
                    if validators.url(prefixed_url):
                        url_input = prefixed_url
                        st.success(f"Added 'http://' prefix: {url_input}")
                    else:
                        st.error("Please enter a valid URL")
                else:
                    # Regular validation for URLs with http/https
                    if validators.url(url_input):
                        st.success("Valid URL entered")
                    else:
                        st.error("Please enter a valid URL")
        
        # Advanced options in expander
        with st.expander("Advanced Analysis Options"):
            recursion_depth = st.slider(
                "Maximum recursion depth", 
                min_value=0, 
                max_value=2, 
                value=1,
                help="Controls how deeply the tool will analyze nested files."
            )
            
            show_debug_info = st.checkbox(
                "Show debug information", 
                value=False,
                help="Display additional technical information during analysis"
            )
        
        # Scan button
        if st.button("Start Scan", type="primary", use_container_width=True):
            with st.spinner("Analyzing content..."):
                st.session_state.extracted_files = []
                st.session_state.selected_file_index = None
                st.session_state.vt_results = None
                st.session_state.scan_id = None
                st.session_state.show_debug = show_debug_info
                
                try:
                    # Process based on input type
                    if uploaded_file is not None:
                        content = uploaded_file.getvalue()
                        filename = uploaded_file.name
                        st.session_state.extracted_files = analyze_file(
                            content, 
                            filename,
                            recursion_depth=0,
                            max_recursion=recursion_depth
                        )
                    
                    elif url_input and validators.url(url_input):
                        content = download_from_url(url_input)
                        if content:
                            # First, analyze the HTML content for embedded files
                            filename = url_input.split("/")[-1] or "downloaded_file"
                            initial_files = analyze_file(
                                content, 
                                filename,
                                recursion_depth=0,
                                max_recursion=recursion_depth
                            )
                            
                            # Then extract and analyze web content components (CSS, JS, links, etc.)
                            web_components = extract_web_content(url_input, content)
                            
                            # Analyze each web component for hidden files
                            for component in web_components:
                                if component["source"] != "original":  # Skip the original HTML
                                    component_files = analyze_file(
                                        component["content"],
                                        component["name"],
                                        recursion_depth=0,
                                        max_recursion=recursion_depth
                                    )
                                    
                                    # Add component files, skipping the first one which is the component itself
                                    # We already have the component in web_components
                                    if len(component_files) > 1:
                                        initial_files.extend(component_files[1:])
                            
                            # Combine results but remove duplicates based on content hash
                            content_hashes = set()
                            unique_files = []
                            
                            # First, add all initial files (from analyze_file)
                            for file in initial_files:
                                file_hash = generate_file_hash(file["content"])["md5"]
                                if file_hash not in content_hashes:
                                    content_hashes.add(file_hash)
                                    unique_files.append(file)
                            
                            # Then add web components that aren't duplicates
                            for component in web_components:
                                file_hash = generate_file_hash(component["content"])["md5"]
                                if file_hash not in content_hashes:
                                    content_hashes.add(file_hash)
                                    unique_files.append(component)
                            
                            st.session_state.extracted_files = unique_files
                            
                            if st.session_state.show_debug:
                                st.info(f"Found {len(st.session_state.extracted_files)} unique files and content components")
                        else:
                            st.error("Failed to download content from URL")
                    
                    else:
                        st.warning("Please provide input via one of the methods above")
                
                except Exception as e:
                    if 'show_debug' in st.session_state and st.session_state.show_debug:
                        st.error(f"Error during analysis: {str(e)}")
                    else:
                        st.error("An error occurred during analysis. Try enabling debug mode for more details.")
        
        # Show input details if files are detected
        if st.session_state.extracted_files:
            st.markdown("---")
            st.markdown("### Input Details")
            # Display information about the original input
            if len(st.session_state.extracted_files) > 0:
                original_file = st.session_state.extracted_files[0]
                st.json({
                    "Name": original_file['name'],
                    "Type": original_file['type'],
                    "Size": f"{original_file['size']} bytes"
                })
    
    # Results section in middle column
    with middle_col:
        if st.session_state.extracted_files:
            st.markdown("### Analysis Results")
            
            # Get total count of detected files
            total_files = len(st.session_state.extracted_files)
            st.markdown(f"**Found {total_files} items during analysis**")
            
            # Filter out the original input file to avoid confusion in results display
            display_files = st.session_state.extracted_files.copy()
            
            # Remove the original input file
            if total_files > 1 and uploaded_file is not None:
                display_files = [f for f in display_files if f['name'] != uploaded_file.name]
                
                filtered_total = len(display_files)
                if filtered_total < total_files:
                    st.info(f"Showing {filtered_total} detected files (excluding original input)")
            
            # Categorize files as potentially malicious or benign
            potentially_malicious, benign_files = categorize_files(display_files)
            
            # Create tabs for file categories
            malicious_tab, benign_tab, all_tab = st.tabs(["Potentially Malicious", "Benign Media", "All Files"])
            
            with malicious_tab:
                if potentially_malicious:
                    st.markdown(f"**Found {len(potentially_malicious)} potentially malicious files or scripts**")
                    
                    # Create a more compact list view
                    malicious_file_options = []
                    malicious_file_indices = []
                    
                    # Build list of files and their indices
                    for file in potentially_malicious:
                        encoding_info = f", {file.get('encoding', 'N/A')}" if 'encoding' in file else ""
                        file_label = f"{file['name']} ({file['type']}{encoding_info})"
                        malicious_file_options.append(file_label)
                        
                        # Find the actual index in the full file list
                        actual_index = -1
                        for j, f in enumerate(st.session_state.extracted_files):
                            if f == file:  # Compare the file dictionaries
                                actual_index = j
                                break
                        
                        if actual_index != -1:
                            malicious_file_indices.append(actual_index)
                    
                    # Display as a simple selectable list
                    if malicious_file_options:
                        selected_index = st.selectbox(
                            "Select a file to view:",
                            range(len(malicious_file_options)),
                            format_func=lambda i: malicious_file_options[i],
                            key="malicious_file_selector"
                        )
                        
                        # View button for the selected file
                        if st.button("View Selected File", key="view_malicious_button", use_container_width=True):
                            st.session_state.selected_file_index = malicious_file_indices[selected_index]
                            st.rerun()
                else:
                    st.info("No potentially malicious files detected")
            
            with benign_tab:
                if benign_files:
                    st.markdown(f"**Found {len(benign_files)} benign media files**")
                    
                    # Create a more compact list view
                    benign_file_options = []
                    benign_file_indices = []
                    
                    # Build list of files and their indices
                    for file in benign_files:
                        encoding_info = f", {file.get('encoding', 'N/A')}" if 'encoding' in file else ""
                        file_label = f"{file['name']} ({file['type']}{encoding_info})"
                        benign_file_options.append(file_label)
                        
                        # Find the actual index in the full file list
                        actual_index = -1
                        for j, f in enumerate(st.session_state.extracted_files):
                            if f == file:  # Compare the file dictionaries
                                actual_index = j
                                break
                        
                        if actual_index != -1:
                            benign_file_indices.append(actual_index)
                    
                    # Display as a simple selectable list
                    if benign_file_options:
                        selected_index = st.selectbox(
                            "Select a file to view:",
                            range(len(benign_file_options)),
                            format_func=lambda i: benign_file_options[i],
                            key="benign_file_selector"
                        )
                        
                        # View button for the selected file
                        if st.button("View Selected File", key="view_benign_button", use_container_width=True):
                            st.session_state.selected_file_index = benign_file_indices[selected_index]
                            st.rerun()
                else:
                    st.info("No benign media files detected")
            
            with all_tab:
                # Use a simple list view for all files
                st.markdown(f"**All Files ({len(display_files)} files)**")
                
                # Create a more compact list view for all files
                file_options = []
                file_indices = []
                
                # Build list of all files and their indices
                for file in display_files:
                    encoding_info = f", {file.get('encoding', 'N/A')}" if 'encoding' in file else ""
                    file_label = f"{file['name']} ({file['type']}{encoding_info})"
                    file_options.append(file_label)
                    
                    # Find the actual index in the full file list
                    actual_index = -1
                    for j, f in enumerate(st.session_state.extracted_files):
                        if f == file:  # Compare the file dictionaries
                            actual_index = j
                            break
                    
                    if actual_index != -1:
                        file_indices.append(actual_index)
                
                # Display as a simple selectable list
                if file_options:
                    selected_index = st.selectbox(
                        "Select a file to view:",
                        range(len(file_options)),
                        format_func=lambda i: file_options[i],
                        key="all_file_selector"
                    )
                    
                    # View button for the selected file
                    if st.button("View Selected File", key="view_all_button", use_container_width=True):
                        st.session_state.selected_file_index = file_indices[selected_index]
                        st.rerun()
                    
                    # If no selection yet, select the first file
                    if st.session_state.selected_file_index is None and file_indices:
                        st.session_state.selected_file_index = file_indices[0]
                else:
                    st.info("No files found in this analysis.")
    
    # VirusTotal section in the right column
    with right_col:
        if st.session_state.extracted_files and st.session_state.selected_file_index is not None:
            selected_file = st.session_state.extracted_files[st.session_state.selected_file_index]
            content = selected_file['content']
            
            st.markdown("### VirusTotal Scan")
            st.markdown("Analysis results for selected file:")
            st.write(f"**Selected file:** {selected_file['name']}")
            
            # Generate file hash for VirusTotal search link
            file_hash = generate_file_hash(content)
            
            # Show file hashes and direct links
            st.markdown("#### File Hash Values")
            cols = st.columns(3)
            with cols[0]:
                st.markdown(f"**MD5:** `{file_hash['md5']}`")
                st.markdown(f"[Search on VirusTotal](https://www.virustotal.com/gui/file/{file_hash['md5']}/detection)")
            with cols[1]:
                st.markdown(f"**SHA-1:** `{file_hash['sha1']}`")
                st.markdown(f"[Search on VirusTotal](https://www.virustotal.com/gui/file/{file_hash['sha1']}/detection)")
            with cols[2]:
                st.markdown(f"**SHA-256:** `{file_hash['sha256']}`")
                st.markdown(f"[Search on VirusTotal](https://www.virustotal.com/gui/file/{file_hash['sha256']}/detection)")
            
            # Show API key input if no API key is available
            if st.session_state.api_key_missing:
                st.markdown("---")
                st.markdown("#### API Integration")
                st.write("You can integrate with VirusTotal API for direct scanning:")
                
                # API key input
                api_key_input = st.text_input(
                    "Enter your VirusTotal API key", 
                    type="password",
                    help="The API key will only be stored for this session"
                )
                
                if api_key_input:
                    # Save API key to session state
                    if st.button("Save API Key", use_container_width=True):
                        st.session_state.user_api_key = api_key_input
                        st.session_state.api_key_missing = False
                        st.success("API key saved for this session!")
                        st.rerun()
            
            # API-based scanning if API key is available
            elif not st.session_state.api_key_missing:
                st.markdown("---")
                st.markdown("#### API-based Scanning")
                st.write("API key detected. You can use direct API scanning:")
                
                if st.button("Scan with VirusTotal API", use_container_width=True):
                    with st.spinner("Uploading to VirusTotal..."):
                        try:
                            # Create a temporary file for the content
                            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{selected_file['name'].split('.')[-1]}") as temp_file:
                                if isinstance(content, str):
                                    temp_file.write(content.encode())
                                else:
                                    temp_file.write(content)
                                temp_path = temp_file.name
                            
                            # Upload to VirusTotal
                            scan_response = scan_file(temp_path, VT_API_KEY)
                            
                            # Clean up the temp file
                            os.unlink(temp_path)
                            
                            if scan_response and "scan_id" in scan_response:
                                st.session_state.scan_id = scan_response["scan_id"]
                                st.success("File uploaded to VirusTotal. Retrieving results...")
                                
                                # Wait for a bit to allow VirusTotal to process the file
                                time.sleep(3)
                                
                                # Get scan results
                                st.session_state.vt_results = get_scan_results(st.session_state.scan_id, VT_API_KEY)
                            else:
                                st.error("Failed to upload file to VirusTotal")
                        
                        except Exception as e:
                            if 'show_debug' in st.session_state and st.session_state.show_debug:
                                st.error(f"Error during VirusTotal scan: {str(e)}")
                            else:
                                st.error("Failed to scan with VirusTotal. Try enabling debug mode for more details.")
                
                # Display VirusTotal results if available
                if st.session_state.vt_results:
                    st.write("#### Scan Results")
                    
                    # Process and display results
                    if "positives" in st.session_state.vt_results and "total" in st.session_state.vt_results:
                        positives = st.session_state.vt_results["positives"]
                        total = st.session_state.vt_results["total"]
                        
                        # Create a progress bar to visualize detection ratio
                        st.progress(positives / total)
                        
                        if positives > 0:
                            st.error(f"⚠️ Detected as malicious by {positives} out of {total} antivirus engines")
                        else:
                            st.success(f"✅ Clean file - 0 detections out of {total} antivirus engines")
                        
                        # Display permalink if available
                        if "permalink" in st.session_state.vt_results:
                            st.markdown(f"[View detailed results on VirusTotal]({st.session_state.vt_results['permalink']})")
                        
                        # Display scan date
                        if "scan_date" in st.session_state.vt_results:
                            st.write(f"Scan date: {st.session_state.vt_results['scan_date']}")
                        
                        # Display detailed antivirus results
                        if "scans" in st.session_state.vt_results:
                            st.write("#### Antivirus Results")
                            
                            # Create a dataframe for better visualization
                            scans_data = []
                            for av_name, av_result in st.session_state.vt_results["scans"].items():
                                scans_data.append({
                                    "Antivirus": av_name,
                                    "Detected": av_result.get("detected", False),
                                    "Result": av_result.get("result", ""),
                                    "Version": av_result.get("version", ""),
                                    "Update": av_result.get("update", "")
                                })
                            
                            # Filter to show only detections if there are many
                            if positives > 0:
                                show_only_detections = st.checkbox("Show only detected threats", value=True)
                                if show_only_detections:
                                    scans_data = [scan for scan in scans_data if scan["Detected"]]
                            
                            # Display results table
                            if scans_data:
                                st.dataframe(scans_data)
                    else:
                        st.write("Scan results are still being processed. Please check back later.")
                        
                        # Provide a refresh button
                        if st.button("Refresh Results", use_container_width=True):
                            with st.spinner("Fetching updated results..."):
                                st.session_state.vt_results = get_scan_results(st.session_state.scan_id, VT_API_KEY)
                                st.rerun()
        elif st.session_state.extracted_files:
            st.markdown("### VirusTotal Scan")
            st.info("Please select a file from the Analysis Results section to view VirusTotal scan options.")
            
    # Show file details in the middle column when selected
    with middle_col:
        if st.session_state.selected_file_index is not None:
            selected_file = st.session_state.extracted_files[st.session_state.selected_file_index]
            
            # Display file details in a collapsible section
            with st.expander("File Details", expanded=True):
                st.json({
                    "Name": selected_file['name'],
                    "Type": selected_file['type'],
                    "Size": f"{selected_file['size']} bytes",
                    "Extension": selected_file.get('extension', 'N/A'),
                    "Encoding": selected_file.get('encoding', 'N/A')
                })
            
            # Preview section
            with st.expander("File Preview", expanded=True):
                content = selected_file['content']
                
                # Handle different file types
                if selected_file['type'] == 'application/pdf':
                    st.write("PDF document detected")
                    if content.startswith(b'%PDF'):
                        st.success("✅ Valid PDF structure detected")
                        # Download button
                        st.download_button(
                            label="Download PDF",
                            data=content,
                            file_name=selected_file['name'],
                            mime="application/pdf",
                            use_container_width=True
                        )
                    else:
                        st.warning("PDF type detected but no valid PDF header found")
                        
                elif selected_file['type'].startswith('image/'):
                    try:
                        st.image(content, caption=f"Image preview: {selected_file['name']}")
                        # Add download button
                        st.download_button(
                            label=f"Download Image",
                            data=content,
                            file_name=selected_file['name'],
                            mime=selected_file['type'],
                            use_container_width=True
                        )
                    except:
                        st.write("Failed to display image preview")
                        # Add download button for failed images
                        st.download_button(
                            label=f"Download Image",
                            data=content,
                            file_name=selected_file['name'],
                            mime=selected_file['type'],
                            use_container_width=True
                        )
                        
                elif isinstance(content, bytes) and selected_file['type'].startswith(('text/', 'application/json')):
                    try:
                        text_content = content.decode('utf-8')
                        st.code(text_content[:1000] + ('...' if len(text_content) > 1000 else ''))
                        # Add download button
                        st.download_button(
                            label=f"Download Text File",
                            data=content,
                            file_name=selected_file['name'],
                            mime=selected_file['type'],
                            use_container_width=True
                        )
                    except:
                        st.write("Binary content - preview not available")
                        # Add download button
                        st.download_button(
                            label=f"Download File",
                            data=content,
                            file_name=selected_file['name'],
                            mime=selected_file['type'],
                            use_container_width=True
                        )
                        
                elif isinstance(content, str):
                    st.code(content[:1000] + ('...' if len(content) > 1000 else ''))
                    # Add download button
                    st.download_button(
                        label=f"Download Text File",
                        data=content,
                        file_name=selected_file['name'],
                        mime="text/plain",
                        use_container_width=True
                    )
                    
                else:
                    st.write("Binary content - preview not available")
                    # Add download button
                    st.download_button(
                        label=f"Download File",
                        data=content,
                        file_name=selected_file['name'],
                        mime=selected_file['type'],
                        use_container_width=True
                    )

# About section
elif st.session_state.active_menu == "About":
    st.header("About This Tool")
    st.markdown("""
    ### Security File Inspector - File Encoding & Malware Detector
    
    This tool helps security professionals and curious users analyze files for:
    
    - **Hidden Content**: Detect files hidden through various encoding techniques
    - **Malware Detection**: Scan extracted files with VirusTotal for potential threats
    - **File Type Identification**: Automatically identify file types regardless of extensions
    
    ### Features
    
    - Multiple input methods: file upload or URL
    - Support for various encoding formats including Base64, Hex, UTF-8, and more
    - Automatic file type detection
    - Integration with VirusTotal for malware scanning
    - Detailed analysis and reporting
    
    ### Supported Encodings
    
    - Base64
    - Hex (Hexadecimal)
    - URL Encoding
    - ASCII85
    - Quoted-Printable
    - And more...
    """)

elif st.session_state.active_menu == "Help":
    st.header("Help & Instructions")
    st.markdown("""
    ### How to Use This Tool
    
    #### Input Methods
    
    1. **Upload File**: Click the "Browse files" button to select a file from your computer
    2. **Enter URL**: Paste a direct URL to a file you want to analyze
    
    #### Analysis Process
    
    1. Select your preferred input method and provide the content
    2. Click the "Start Scan" button to begin analysis
    3. Review the detected files in the results section
    4. Select any file to view its details and scan with VirusTotal
    
    #### VirusTotal Integration
    
    There are two ways to scan files with VirusTotal:
    
    1. **Without API Key**:
       - Download the detected file
       - Visit VirusTotal website
       - Upload the file manually or use the direct hash links provided
       
    2. **With API Key** (if configured):
       - Click the "Scan with VirusTotal API" button
       - View results directly in the application
    
    #### Advanced Options
    
    - **Recursion Depth**: Controls how deeply the tool searches for embedded files
      - Lower values (0-1): Reduce false positives, but might miss deeply hidden files
      - Higher values (2-3): More thorough scanning, but might detect more false positives
    - **Debug Mode**: Shows additional technical information to help troubleshoot issues
    
    #### Troubleshooting
    
    - If no files are detected, try a different input method
    - If too many false positives are detected, lower the recursion depth
    - Enable debug mode to see more detailed information about the analysis process
    """)

# Footer
st.markdown("---")
st.markdown("Security File Inspector | Built with Streamlit")
