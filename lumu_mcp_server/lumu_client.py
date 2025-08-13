"""Lumu Defender API client."""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import httpx

logger = logging.getLogger(__name__)


class LumuDefenderClient:
    """Client for interacting with Lumu Defender API."""
    
    BASE_URL = "https://defender.lumu.io/api"
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the Lumu Defender client.
        
        Args:
            api_key: Lumu Defender API key. If not provided, will try to get from environment.
        """
        self.api_key = api_key or os.getenv("LUMU_DEFENDER_API_KEY")
        if not self.api_key:
            raise ValueError("Lumu Defender API key is required. Set LUMU_DEFENDER_API_KEY environment variable or pass api_key parameter.")
        
        self.client = httpx.Client(timeout=30.0)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()
    
    async def get_incidents(
        self,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        status: Optional[List[str]] = None,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Retrieve incidents from Lumu Defender.
        
        Args:
            from_date: Search start date. Default is 7 days before current date.
            to_date: Search end date. Default is current date.
            status: Incident status filter. Options: "open", "muted", "closed"
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
        
        Returns:
            Dictionary containing the incidents data.
        """
        # Set default dates if not provided
        if to_date is None:
            to_date = datetime.now(timezone.utc)
        if from_date is None:
            from_date = to_date - timedelta(days=7)
        
        # Build request payload with proper millisecond formatting
        payload = {
            "fromDate": from_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "toDate": to_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        }
        
        # Add optional filters
        if status:
            # Validate status values
            valid_statuses = {"open", "muted", "closed"}
            invalid = set(status) - valid_statuses
            if invalid:
                raise ValueError(f"Invalid status values: {invalid}. Must be one of {valid_statuses}")
            payload["status"] = status
        
        if adversary_types:
            # Validate adversary types
            valid_types = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}
            invalid = set(adversary_types) - valid_types
            if invalid:
                raise ValueError(f"Invalid adversary types: {invalid}. Must be one of {valid_types}")
            payload["adversary-types"] = adversary_types
        
        if labels:
            payload["labels"] = labels
        
        # Make API request
        url = f"{self.BASE_URL}/incidents/all"
        params = {"key": self.api_key}
        
        logger.info(f"Fetching incidents from {from_date} to {to_date}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']
                logger.info(f"Retrieved {len(data.get('incidents', []))} incidents")
                return data
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise ValueError("Invalid API key or unauthorized access")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request parameters: {e.response.text}")
                else:
                    raise Exception(f"API request failed: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """Retrieve details of a specific incident.
        
        Args:
            incident_id: The UUID of the incident to retrieve.
        
        Returns:
            Dictionary containing the incident details.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/details"
        params = {"key": self.api_key}
        
        logger.info(f"Fetching details for incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Retrieved details for incident {incident_id}")
                return {"incident": data}  # Wrap in incident key for consistency
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_open_incidents(
        self,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Retrieve open incidents from Lumu Defender.
        
        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
        
        Returns:
            Dictionary containing the open incidents data.
        """
        url = f"{self.BASE_URL}/incidents/open"
        params = {"key": self.api_key}
        
        # Build request payload
        payload = {}
        
        # Add optional filters
        if adversary_types:
            # Validate adversary types
            valid_types = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}
            invalid = set(adversary_types) - valid_types
            if invalid:
                raise ValueError(f"Invalid adversary types: {invalid}. Must be one of {valid_types}")
            payload["adversary-types"] = adversary_types
        
        if labels:
            payload["labels"] = labels
        
        logger.info(f"Fetching open incidents")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']
                logger.info(f"Retrieved {len(data.get('incidents', []))} open incidents")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_muted_incidents(
        self,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Retrieve muted incidents from Lumu Defender.
        
        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
        
        Returns:
            Dictionary containing the muted incidents data.
        """
        url = f"{self.BASE_URL}/incidents/muted"
        params = {"key": self.api_key}
        
        # Build request payload
        payload = {}
        
        # Add optional filters
        if adversary_types:
            # Validate adversary types
            valid_types = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}
            invalid = set(adversary_types) - valid_types
            if invalid:
                raise ValueError(f"Invalid adversary types: {invalid}. Must be one of {valid_types}")
            payload["adversary-types"] = adversary_types
        
        if labels:
            payload["labels"] = labels
        
        logger.info(f"Fetching muted incidents")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']
                logger.info(f"Retrieved {len(data.get('incidents', []))} muted incidents")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_closed_incidents(
        self,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Retrieve closed incidents from Lumu Defender.
        
        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
        
        Returns:
            Dictionary containing the closed incidents data.
        """
        url = f"{self.BASE_URL}/incidents/closed"
        params = {"key": self.api_key}
        
        # Build request payload
        payload = {}
        
        # Add optional filters
        if adversary_types:
            # Validate adversary types
            valid_types = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}
            invalid = set(adversary_types) - valid_types
            if invalid:
                raise ValueError(f"Invalid adversary types: {invalid}. Must be one of {valid_types}")
            payload["adversary-types"] = adversary_types
        
        if labels:
            payload["labels"] = labels
        
        logger.info(f"Fetching closed incidents")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']
                logger.info(f"Retrieved {len(data.get('incidents', []))} closed incidents")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_incident_endpoints(
        self,
        incident_id: str,
        endpoints: Optional[List[str]] = None,
        labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Retrieve endpoints by incident from Lumu Defender.
        
        Args:
            incident_id: The UUID of the incident.
            endpoints: List of endpoint IPs or names to filter by.
            labels: Label IDs filter.
        
        Returns:
            Dictionary containing the incident endpoints data.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/endpoints-contacts"
        params = {"key": self.api_key}
        
        # Build request payload
        payload = {}
        
        if endpoints:
            payload["endpoints"] = endpoints
        
        if labels:
            payload["labels"] = labels
        
        logger.info(f"Fetching endpoints for incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Retrieved endpoints for incident {incident_id}")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def mark_incident_as_read(self, incident_id: str) -> Dict[str, Any]:
        """Mark an incident as read.
        
        Args:
            incident_id: The UUID of the incident to mark as read.
        
        Returns:
            Dictionary containing the response.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/mark-as-read"
        params = {"key": self.api_key}
        
        logger.info(f"Marking incident {incident_id} as read")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json={})
                response.raise_for_status()
                
                # Check if response has content
                if response.content:
                    data = response.json()
                else:
                    data = {"success": True, "message": "Incident marked as read successfully"}
                
                logger.info(f"Incident {incident_id} marked as read")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def mute_incident(self, incident_id: str, comment: str = "") -> Dict[str, Any]:
        """Mute an incident.
        
        Args:
            incident_id: The UUID of the incident to mute.
            comment: Optional comment for muting the incident.
        
        Returns:
            Dictionary containing the response.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/mute"
        params = {"key": self.api_key}
        payload = {"comment": comment}
        
        logger.info(f"Muting incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                # Check if response has content
                if response.content:
                    data = response.json()
                else:
                    data = {"success": True, "message": "Incident muted successfully"}
                
                logger.info(f"Incident {incident_id} muted")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def unmute_incident(self, incident_id: str, comment: str = "") -> Dict[str, Any]:
        """Unmute an incident.
        
        Args:
            incident_id: The UUID of the incident to unmute.
            comment: Optional comment for unmuting the incident.
        
        Returns:
            Dictionary containing the response.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/unmute"
        params = {"key": self.api_key}
        payload = {"comment": comment}
        
        logger.info(f"Unmuting incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                # Check if response has content
                if response.content:
                    data = response.json()
                else:
                    data = {"success": True, "message": "Incident unmuted successfully"}
                
                logger.info(f"Incident {incident_id} unmuted")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_incident_updates(
        self,
        offset: int = 0,
        items: int = 50,
        time: int = 5
    ) -> Dict[str, Any]:
        """Get real-time updates on incident operations.
        
        Args:
            offset: Starting offset for pagination (default: 0)
            items: Number of items to return (default: 50)
            time: Time window in minutes for updates (default: 5)
        
        Returns:
            Dictionary containing the incident updates.
        """
        url = f"{self.BASE_URL}/incidents/open-incidents/updates"
        params = {
            "key": self.api_key,
            "offset": offset,
            "items": items,
            "time": time
        }
        
        logger.info(f"Fetching incident updates (offset={offset}, items={items}, time={time})")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Retrieved {len(data.get('updates', []))} incident updates")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request parameters. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def close_incident(self, incident_id: str, comment: str = "") -> Dict[str, Any]:
        """Close an incident.
        
        Args:
            incident_id: The UUID of the incident to close.
            comment: Optional comment for closing the incident.
        
        Returns:
            Dictionary containing the response.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/close"
        params = {"key": self.api_key}
        payload = {"comment": comment}
        
        logger.info(f"Closing incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                # Check if response has content
                if response.content:
                    data = response.json()
                else:
                    data = {"success": True, "message": "Incident closed successfully"}
                
                logger.info(f"Incident {incident_id} closed")
                return data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"API Error - Status: {e.response.status_code}, Response: {e.response.text}")
                if e.response.status_code == 401:
                    raise ValueError(f"Invalid API key or unauthorized access. API Response: {e.response.text}")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found. API Response (404): {e.response.text}")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request. API Response (400): {e.response.text}")
                else:
                    raise Exception(f"API request failed with status {e.response.status_code}. Response: {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def get_incident_context(
        self, 
        incident_id: str, 
        hash_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Retrieve context of a specific incident.
        
        Args:
            incident_id: The UUID of the incident.
            hash_type: Optional hash type for filtering context.
        
        Returns:
            Dictionary containing the incident context.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/context"
        params = {"key": self.api_key}
        if hash_type:
            params["hash"] = hash_type
        
        logger.info(f"Fetching context for incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Retrieved context for incident {incident_id}")
                return {"context": data}  # Wrap in context key for consistency
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise ValueError("Invalid API key or unauthorized access")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request: {e.response.text}")
                else:
                    raise Exception(f"API request failed: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")
    
    async def comment_incident(self, incident_id: str, comment: str) -> Dict[str, Any]:
        """Add a comment to a specific incident.
        
        Args:
            incident_id: The UUID of the incident to comment on.
            comment: The comment text to add.
        
        Returns:
            Dictionary containing the response.
        """
        url = f"{self.BASE_URL}/incidents/{incident_id}/comment"
        params = {"key": self.api_key}
        payload = {"comment": comment}
        
        logger.info(f"Adding comment to incident {incident_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    url, 
                    params=params, 
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                
                # Check if response has content
                if response.content:
                    data = response.json()
                else:
                    data = {"success": True, "message": "Comment added successfully"}
                
                logger.info(f"Comment added to incident {incident_id}")
                return data
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise ValueError("Invalid API key or unauthorized access")
                elif e.response.status_code == 404:
                    raise ValueError(f"Incident {incident_id} not found")
                elif e.response.status_code == 400:
                    raise ValueError(f"Invalid request: {e.response.text}")
                else:
                    raise Exception(f"API request failed: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                raise Exception(f"Network error while connecting to Lumu API: {str(e)}")