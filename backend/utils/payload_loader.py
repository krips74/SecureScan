import os


def load_payloads_from_file(filepath: str = None) -> list:
    """
    Load XSS payloads from a file
    
    Args:
        filepath: Path to the payload file. If None, uses default location.
    
    Returns:
        list: List of payload strings
    """
    if filepath is None:
        # Default to scanners/xss-payload.txt
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = os.path.join(current_dir, 'scanners', 'xss-payload.txt')
    
    payloads = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    payloads.append(line)
    except FileNotFoundError:
        print(f"[!] Warning: Payload file not found at {filepath}")
        print("[!] Using default payloads")
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "' onerror='alert(1)'",
            "\"><script>alert(1)</script>"
        ]
    
    return payloads
