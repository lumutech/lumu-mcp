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
    
    # Maximum date range allowed by Lumu API (in days)
    MAX_DATE_RANGE_DAYS = 90

    def _validate_date_range(self, from_date: datetime, to_date: datetime) -> None:
        """Validate date range constraints.

        Args:
            from_date: Start date for the query.
            to_date: End date for the query.

        Raises:
            ValueError: If date range is invalid.
        """
        if to_date < from_date:
            raise ValueError("to_date must be after from_date")

        # Allow a small buffer for timezone differences (1 day)
        max_future = datetime.now(timezone.utc) + timedelta(days=1)
        if to_date > max_future:
            raise ValueError("to_date cannot be in the future")

        range_days = (to_date - from_date).days
        if range_days > self.MAX_DATE_RANGE_DAYS:
            raise ValueError(
                f"Date range of {range_days} days exceeds maximum of {self.MAX_DATE_RANGE_DAYS} days. "
                f"Use fetch_all=True with automatic chunking for larger date ranges."
            )

    async def get_incidents(
        self,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        status: Optional[List[str]] = None,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None,
        page: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Retrieve incidents from Lumu Defender.

        Args:
            from_date: Search start date. Default is 7 days before current date.
            to_date: Search end date. Default is current date.
            status: Incident status filter. Options: "open", "muted", "closed"
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            page: Page number for pagination (0-indexed). Default is 0.
            limit: Number of items per page. Default is 50, max is 100.

        Returns:
            Dictionary containing the incidents data with pagination info.
        """
        # Set default dates if not provided
        if to_date is None:
            to_date = datetime.now(timezone.utc)
        if from_date is None:
            from_date = to_date - timedelta(days=7)

        # Validate date range
        self._validate_date_range(from_date, to_date)

        # Ensure limit is within bounds
        limit = max(1, min(limit, 100))

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
        # Pagination parameters go in query string, not body
        # API uses 1-indexed pages and 'items' instead of 'limit'
        params = {
            "key": self.api_key,
            "page": page + 1,  # Convert 0-indexed to 1-indexed
            "items": limit
        }

        logger.info(f"Fetching incidents from {from_date} to {to_date} (page={page + 1}, items={limit})")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()
                
                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']

                incidents_count = len(data.get('incidents', []))
                logger.info(f"Retrieved {incidents_count} incidents (page={page}, limit={limit})")

                # Add pagination metadata
                data['pagination'] = {
                    'page': page,
                    'limit': limit,
                    'returned': incidents_count,
                    'has_more': incidents_count >= limit
                }

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

    async def get_all_incidents(
        self,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        status: Optional[List[str]] = None,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None,
        max_pages: int = 100
    ) -> Dict[str, Any]:
        """Retrieve ALL incidents with automatic pagination.

        This method automatically paginates through all results to retrieve
        the complete list of incidents matching the criteria.

        Args:
            from_date: Search start date. Default is 7 days before current date.
            to_date: Search end date. Default is current date.
            status: Incident status filter. Options: "open", "muted", "closed"
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            max_pages: Maximum number of pages to fetch (safety limit). Default is 100.

        Returns:
            Dictionary containing all incidents and pagination summary.
        """
        all_incidents = []
        page = 0
        limit = 100  # Max per request for efficiency

        logger.info(f"Fetching all incidents with auto-pagination...")

        while page < max_pages:
            result = await self.get_incidents(
                from_date=from_date,
                to_date=to_date,
                status=status,
                adversary_types=adversary_types,
                labels=labels,
                page=page,
                limit=limit
            )

            incidents = result.get("incidents", [])
            all_incidents.extend(incidents)

            pagination = result.get("pagination", {})
            has_more = pagination.get("has_more", False)

            logger.info(f"Page {page}: retrieved {len(incidents)} incidents (total so far: {len(all_incidents)})")

            if not has_more or len(incidents) < limit:
                break

            page += 1

        logger.info(f"Completed fetching all incidents: {len(all_incidents)} total across {page + 1} pages")

        return {
            "incidents": all_incidents,
            "total": len(all_incidents),
            "pages_fetched": page + 1,
            "pagination": {
                "complete": page < max_pages,
                "total_items": len(all_incidents)
            }
        }

    async def get_all_incidents_chunked(
        self,
        from_date: datetime,
        to_date: datetime,
        status: Optional[List[str]] = None,
        adversary_types: Optional[List[str]] = None,
        labels: Optional[List[int]] = None,
        chunk_days: int = 30
    ) -> Dict[str, Any]:
        """Retrieve incidents across large date ranges by chunking into smaller queries.

        This method handles date ranges larger than the API's maximum (90 days) by
        breaking them into smaller chunks and aggregating the results.

        Args:
            from_date: Search start date (required).
            to_date: Search end date (required).
            status: Incident status filter. Options: "open", "muted", "closed"
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            chunk_days: Size of each date chunk in days. Default is 30.

        Returns:
            Dictionary containing all incidents (deduplicated) and summary.
        """
        all_incidents = []
        current_start = from_date
        chunks_processed = 0

        total_days = (to_date - from_date).days
        logger.info(f"Fetching incidents for {total_days} days in {chunk_days}-day chunks...")

        while current_start < to_date:
            current_end = min(current_start + timedelta(days=chunk_days), to_date)

            logger.info(f"Processing chunk {chunks_processed + 1}: {current_start.date()} to {current_end.date()}")

            result = await self.get_all_incidents(
                from_date=current_start,
                to_date=current_end,
                status=status,
                adversary_types=adversary_types,
                labels=labels
            )

            chunk_incidents = result.get("incidents", [])
            all_incidents.extend(chunk_incidents)
            chunks_processed += 1

            logger.info(f"Chunk {chunks_processed}: retrieved {len(chunk_incidents)} incidents")

            current_start = current_end

        # Deduplicate incidents by ID (in case of overlap at chunk boundaries)
        seen_ids = set()
        unique_incidents = []
        duplicates_removed = 0

        for incident in all_incidents:
            incident_id = incident.get("id")
            if incident_id and incident_id not in seen_ids:
                seen_ids.add(incident_id)
                unique_incidents.append(incident)
            else:
                duplicates_removed += 1

        logger.info(f"Completed chunked fetch: {len(unique_incidents)} unique incidents "
                   f"({duplicates_removed} duplicates removed) across {chunks_processed} chunks")

        return {
            "incidents": unique_incidents,
            "total": len(unique_incidents),
            "chunks_processed": chunks_processed,
            "duplicates_removed": duplicates_removed,
            "date_range": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
                "days": total_days
            }
        }

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
        labels: Optional[List[int]] = None,
        page: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Retrieve open incidents from Lumu Defender.

        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            page: Page number for pagination (0-indexed). Default is 0.
            limit: Number of items per page. Default is 50, max is 100.

        Returns:
            Dictionary containing the open incidents data with pagination info.
        """
        # Ensure limit is within bounds
        limit = max(1, min(limit, 100))

        url = f"{self.BASE_URL}/incidents/open"
        # Pagination parameters go in query string
        # API uses 1-indexed pages and 'items' parameter
        params = {
            "key": self.api_key,
            "page": page + 1,  # Convert 0-indexed to 1-indexed
            "items": limit
        }
        
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

        logger.info(f"Fetching open incidents (page={page + 1}, items={limit})")

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()

                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']

                incidents_count = len(data.get('incidents', []))
                logger.info(f"Retrieved {incidents_count} open incidents (page={page + 1})")

                # Add pagination metadata
                data['pagination'] = {
                    'page': page,
                    'limit': limit,
                    'returned': incidents_count,
                    'has_more': incidents_count >= limit
                }

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
        labels: Optional[List[int]] = None,
        page: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Retrieve muted incidents from Lumu Defender.

        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            page: Page number for pagination (0-indexed). Default is 0.
            limit: Number of items per page. Default is 50, max is 100.

        Returns:
            Dictionary containing the muted incidents data with pagination info.
        """
        # Ensure limit is within bounds
        limit = max(1, min(limit, 100))

        url = f"{self.BASE_URL}/incidents/muted"
        # Pagination parameters go in query string
        # API uses 1-indexed pages and 'items' parameter
        params = {
            "key": self.api_key,
            "page": page + 1,  # Convert 0-indexed to 1-indexed
            "items": limit
        }

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

        logger.info(f"Fetching muted incidents (page={page + 1}, items={limit})")

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()

                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']

                incidents_count = len(data.get('incidents', []))
                logger.info(f"Retrieved {incidents_count} muted incidents (page={page + 1})")

                # Add pagination metadata
                data['pagination'] = {
                    'page': page,
                    'limit': limit,
                    'returned': incidents_count,
                    'has_more': incidents_count >= limit
                }

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
        labels: Optional[List[int]] = None,
        page: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Retrieve closed incidents from Lumu Defender.

        Args:
            adversary_types: Adversary types filter. Options: "C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"
            labels: Label IDs filter.
            page: Page number for pagination (0-indexed). Default is 0.
            limit: Number of items per page. Default is 50, max is 100.

        Returns:
            Dictionary containing the closed incidents data with pagination info.
        """
        # Ensure limit is within bounds
        limit = max(1, min(limit, 100))

        url = f"{self.BASE_URL}/incidents/closed"
        # Pagination parameters go in query string
        # API uses 1-indexed pages and 'items' parameter
        params = {
            "key": self.api_key,
            "page": page + 1,  # Convert 0-indexed to 1-indexed
            "items": limit
        }

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

        logger.info(f"Fetching closed incidents (page={page + 1}, items={limit})")

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, params=params, json=payload)
                response.raise_for_status()

                data = response.json()
                # API returns incidents in 'items' array, normalize to 'incidents' for consistency
                if 'items' in data and 'incidents' not in data:
                    data['incidents'] = data['items']

                incidents_count = len(data.get('incidents', []))
                logger.info(f"Retrieved {incidents_count} closed incidents (page={page + 1})")

                # Add pagination metadata
                data['pagination'] = {
                    'page': page,
                    'limit': limit,
                    'returned': incidents_count,
                    'has_more': incidents_count >= limit
                }

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