import os
import requests
import time
import json

def scan_file(file_path, api_key):
    """
    Upload a file to VirusTotal for scanning
    
    Args:
        file_path (str): Path to the file to scan
        api_key (str): VirusTotal API key
        
    Returns:
        dict: Response from VirusTotal API or None if failed
    """
    if not api_key:
        return None
    
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    
    params = {"apikey": api_key}
    
    try:
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, files=files, params=params)
            
            if response.status_code == 200:
                return response.json()
            else:
                # Try with the larger file upload API if the file is too large
                if response.status_code == 413:
                    return get_upload_url(file_path, api_key)
                else:
                    print(f"Error: {response.status_code} - {response.text}")
                    return None
    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        return None

def get_upload_url(file_path, api_key):
    """
    Get a special URL for uploading larger files to VirusTotal
    
    Args:
        file_path (str): Path to the file to scan
        api_key (str): VirusTotal API key
        
    Returns:
        dict: Response from VirusTotal API or None if failed
    """
    url = "https://www.virustotal.com/vtapi/v2/file/scan/upload_url"
    
    params = {"apikey": api_key}
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            upload_url = response.json()["upload_url"]
            
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                upload_response = requests.post(upload_url, files=files)
                
                if upload_response.status_code == 200:
                    return upload_response.json()
                else:
                    print(f"Error uploading to special URL: {upload_response.status_code} - {upload_response.text}")
                    return None
        else:
            print(f"Error getting upload URL: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error in large file upload: {str(e)}")
        return None

def get_scan_results(scan_id, api_key):
    """
    Get the results of a VirusTotal scan
    
    Args:
        scan_id (str): The scan ID returned by VirusTotal
        api_key (str): VirusTotal API key
        
    Returns:
        dict: Scan results from VirusTotal API or None if failed
    """
    if not api_key or not scan_id:
        return None
    
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    
    params = {
        "apikey": api_key,
        "resource": scan_id
    }
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            result = response.json()
            
            # Check if the scan is complete
            if result.get("response_code") == 1:
                return result
            else:
                # Scan is still processing
                return {"status": "processing"}
        else:
            print(f"Error getting scan results: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error getting scan results: {str(e)}")
        return None

def search_hash(file_hash, api_key):
    """
    Search for a file by its hash in VirusTotal
    
    Args:
        file_hash (str): The file hash (MD5, SHA-1, or SHA-256)
        api_key (str): VirusTotal API key
        
    Returns:
        dict: Scan results from VirusTotal API or None if failed
    """
    if not api_key or not file_hash:
        return None
    
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    
    params = {
        "apikey": api_key,
        "resource": file_hash
    }
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get("response_code") == 1:
                return result
            else:
                return {"status": "not_found"}
        else:
            print(f"Error searching hash: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error searching hash: {str(e)}")
        return None
