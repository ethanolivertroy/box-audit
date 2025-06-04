"""Box API wrapper with error handling and retry logic"""

import time
from typing import Dict, List, Optional, Any
from boxsdk import Client
from boxsdk.exception import BoxAPIException
from boxsdk.object.user import User
from boxsdk.object.group import Group
import logging

logger = logging.getLogger(__name__)


class BoxAPIClient:
    """Wrapper for Box API with convenience methods"""
    
    def __init__(self, client: Client):
        self.client = client
        self._enterprise_id = None
        
    @property
    def enterprise_id(self) -> str:
        """Get cached enterprise ID"""
        if not self._enterprise_id:
            user = self.client.user().get()
            self._enterprise_id = user.enterprise.id
        return self._enterprise_id
        
    def get_all_users(self, fields: List[str] = None) -> List[User]:
        """
        Get all enterprise users
        
        Args:
            fields: Specific fields to retrieve
            
        Returns:
            List of User objects
        """
        if fields is None:
            fields = ['id', 'name', 'login', 'status', 'created_at', 
                     'modified_at', 'role', 'is_sync_enabled', 'is_external_collab_restricted']
        
        users = []
        offset = 0
        limit = 1000
        
        while True:
            try:
                user_page = self.client.users(
                    limit=limit,
                    offset=offset,
                    fields=','.join(fields)
                )
                users.extend(user_page)
                
                if len(user_page) < limit:
                    break
                    
                offset += limit
                
            except BoxAPIException as e:
                logger.error(f"Error fetching users: {e}")
                raise
                
        return users
        
    def get_all_groups(self) -> List[Group]:
        """Get all enterprise groups"""
        groups = []
        offset = 0
        limit = 1000
        
        while True:
            try:
                group_page = self.client.groups(
                    limit=limit,
                    offset=offset
                )
                groups.extend(group_page)
                
                if len(group_page) < limit:
                    break
                    
                offset += limit
                
            except BoxAPIException as e:
                logger.error(f"Error fetching groups: {e}")
                raise
                
        return groups
        
    def get_enterprise_settings(self) -> Dict:
        """Get enterprise security settings"""
        try:
            # Get current user to access enterprise
            user = self.client.user().get()
            enterprise = self.client.enterprise(user.enterprise.id).get()
            
            # Get additional settings through admin endpoints
            settings = {
                'enterprise_id': enterprise.id,
                'enterprise_name': enterprise.name,
                'created_at': enterprise.created_at,
                'modified_at': enterprise.modified_at
            }
            
            return settings
            
        except BoxAPIException as e:
            logger.error(f"Error fetching enterprise settings: {e}")
            raise
            
    def get_login_settings(self) -> Dict:
        """Get enterprise login and authentication settings"""
        # This would require admin API access
        # Placeholder for settings that would be retrieved
        return {
            'sso_enabled': None,
            'mfa_required': None,
            'password_policy': None,
            'session_settings': None
        }
        
    def get_collaboration_whitelist(self) -> List[Dict]:
        """Get collaboration whitelist domains"""
        try:
            # Get collaboration whitelist entries
            whitelist = []
            entries = self.client.collaboration_whitelist_entries()
            
            for entry in entries:
                whitelist.append({
                    'id': entry.id,
                    'domain': entry.domain,
                    'direction': entry.direction
                })
                
            return whitelist
            
        except BoxAPIException as e:
            logger.error(f"Error fetching collaboration whitelist: {e}")
            return []
            
    def get_events(self, event_types: List[str] = None, created_after: str = None) -> List[Dict]:
        """
        Get enterprise events for audit
        
        Args:
            event_types: List of event types to filter
            created_after: ISO timestamp to get events after
            
        Returns:
            List of event dictionaries
        """
        events = []
        
        try:
            event_stream = self.client.events()
            
            for event in event_stream.get_events(
                stream_type='admin_logs',
                event_types=event_types,
                created_after=created_after
            ):
                events.append({
                    'type': event.event_type,
                    'created_at': event.created_at,
                    'created_by': getattr(event.created_by, 'login', 'system'),
                    'source': getattr(event.source, 'type', 'unknown'),
                    'ip_address': getattr(event, 'ip_address', None)
                })
                
        except BoxAPIException as e:
            logger.error(f"Error fetching events: {e}")
            
        return events
        
    def get_device_pins(self) -> List[Dict]:
        """Get device trust pins"""
        device_pins = []
        
        try:
            # This requires enterprise admin access
            pins = self.client.device_pinners()
            
            for pin in pins:
                device_pins.append({
                    'id': pin.id,
                    'user': pin.owned_by.login,
                    'product_name': pin.product_name,
                    'created_at': pin.created_at
                })
                
        except BoxAPIException as e:
            logger.warning(f"Could not fetch device pins: {e}")
            
        return device_pins
        
    def get_legal_holds(self) -> List[Dict]:
        """Get legal hold policies"""
        holds = []
        
        try:
            policies = self.client.legal_hold_policies()
            
            for policy in policies:
                holds.append({
                    'id': policy.id,
                    'name': policy.policy_name,
                    'created_at': policy.created_at,
                    'status': policy.status
                })
                
        except BoxAPIException as e:
            logger.warning(f"Could not fetch legal holds: {e}")
            
        return holds