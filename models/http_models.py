from typing import Dict, Optional
from pydantic import BaseModel, Field

class HttpRequest(BaseModel):
    """Model representing an HTTP request."""
    method: str = Field(description="HTTP method (e.g., GET, POST)")
    url: str = Field(description="Full URL of the request")
    path: str = Field(description="Path component of the URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    query_parameters: Dict[str, str] = Field(default_factory=dict, description="Query parameters")
    body: Optional[str] = Field(default=None, description="Request body")
    raw_request: Optional[str] = Field(default=None, description="Raw HTTP request string")

class HttpResponse(BaseModel):
    """Model representing an HTTP response."""
    status_code: int = Field(description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP response headers")
    body: Optional[str] = Field(default=None, description="Response body")
    mime_type: Optional[str] = Field(default=None, description="Inferred MIME type from Content-Type")
    raw_response: Optional[str] = Field(default=None, description="Raw HTTP response string")

class ProxyEntry(BaseModel):
    """Model representing a proxy history entry in Burp Suite."""
    id: int = Field(description="Internal Burp proxy history ID")
    host: str = Field(description="Target host")
    port: int = Field(description="Target port")
    protocol: str = Field(description="Protocol (http/https)")
    request: HttpRequest
    response: Optional[HttpResponse] = None
    time: str = Field(description="Time the request was made")
    in_scope: bool = Field(default=False, description="Whether the target is in scope")
