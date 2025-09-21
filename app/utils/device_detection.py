"""Device detection utilities."""

import re
from typing import Optional, Tuple


def detect_client_type(user_agent: Optional[str], accept_header: Optional[str] = None) -> str:
    """Detect client type from User-Agent and Accept headers."""
    
    if not user_agent:
        return "unknown"
    
    user_agent = user_agent.lower()
    
    # Mobile apps (iOS/Android native)
    mobile_patterns = [
        r'okhttp',  # Android OkHttp
        r'alamofire',  # iOS Alamofire
        r'afnetworking',  # iOS AFNetworking
        r'urlsession',  # iOS URLSession
        r'android.*app',
        r'ios.*app',
        r'flutter',
        r'dart/',
        r'kotlin',
        r'swift/',
    ]
    
    for pattern in mobile_patterns:
        if re.search(pattern, user_agent):
            return "mobile"
    
    # CLI/Scripts/Integrations
    cli_patterns = [
        r'curl',
        r'wget',
        r'httpie',
        r'python-requests',
        r'python-urllib',
        r'postman',
        r'insomnia',
        r'cli',
        r'script',
        r'bot',
        r'automated',
        r'integration',
    ]
    
    for pattern in cli_patterns:
        if re.search(pattern, user_agent):
            return "api"
    
    # Browsers
    browser_patterns = [
        r'mozilla',
        r'webkit',
        r'chrome',
        r'safari',
        r'firefox',
        r'edge',
        r'opera',
        r'msie',
    ]
    
    for pattern in browser_patterns:
        if re.search(pattern, user_agent):
            return "web"
    
    return "api"  # Default to API client for unknown


def should_use_cookies(client_type: str) -> bool:
    """Determine if client should use cookies for session management."""
    return client_type == "web"


def should_use_csrf(client_type: str) -> bool:
    """Determine if client needs CSRF protection."""
    return client_type == "web"


def get_device_info(user_agent: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Extract device name and type from User-Agent."""
    
    if not user_agent:
        return None, None
    
    user_agent_lower = user_agent.lower()
    
    # Device type detection
    device_type = None
    device_name = None
    
    # Mobile devices
    if any(pattern in user_agent_lower for pattern in ['iphone', 'ios']):
        device_type = "iOS"
        device_name = "iPhone/iPad"
    elif 'android' in user_agent_lower:
        device_type = "Android"
        device_name = "Android Device"
    elif any(pattern in user_agent_lower for pattern in ['windows', 'win32', 'win64']):
        device_type = "Desktop"
        device_name = "Windows PC"
    elif any(pattern in user_agent_lower for pattern in ['macintosh', 'mac os']):
        device_type = "Desktop"
        device_name = "Mac"
    elif 'linux' in user_agent_lower:
        device_type = "Desktop"
        device_name = "Linux PC"
    
    # Browser detection for device name refinement
    if device_type == "Desktop":
        if 'chrome' in user_agent_lower:
            device_name += " (Chrome)"
        elif 'firefox' in user_agent_lower:
            device_name += " (Firefox)"
        elif 'safari' in user_agent_lower:
            device_name += " (Safari)"
        elif 'edge' in user_agent_lower:
            device_name += " (Edge)"
    
    return device_name, device_type
