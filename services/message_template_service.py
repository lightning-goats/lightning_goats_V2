import logging
import random
from typing import Dict, Optional, List, Union
import json

from services.database_service import DatabaseService

logger = logging.getLogger(__name__)

class MessageTemplateService:
    """Service for managing message templates."""
    
    def __init__(self, database_service: DatabaseService):
        self.database = database_service
        self.cache = {}
        
    async def get_template(self, category: str, key: Optional[int] = None) -> Union[str, Dict[int, str], List[str]]:
        """
        Get a message template or all templates in a category from the database.
        
        Uses in-memory cache first, then database.
        """
        # Special handling for thank_you_variations which is a list not a dict
        if category == "thank_you_variations":
            try:
                variations = await self.database.get_message_template("thank_you_variations")
                if variations:
                    return [v for k, v in sorted(variations.items())]
                logger.warning(f"No thank_you_variations found in database")
                return []
            except Exception as e:
                logger.error(f"Error fetching thank you variations: {e}")
                return []
        
        # Normal template handling
        if key is not None:
            # Try cache first
            cache_key = f"{category}:{key}"
            if cache_key in self.cache:
                return self.cache[cache_key]
                
            # Try database
            try:
                template = await self.database.get_message_template(category, key)
                if template:
                    self.cache[cache_key] = template
                    return template
                logger.warning(f"Template {category}:{key} not found in database")
            except Exception as e:
                logger.error(f"Error fetching template {category}:{key}: {e}")
                
            # Return error message if template not found
            return f"Template {category}:{key} not found"
        else:
            # Get all templates for category
            try:
                templates = await self.database.get_message_template(category)
                if templates:
                    # Update cache
                    for k, v in templates.items():
                        self.cache[f"{category}:{k}"] = v
                    return templates
                logger.warning(f"No templates found for category: {category}")
                return {}
            except Exception as e:
                logger.error(f"Error fetching templates for {category}: {e}")
                return {}
            
    async def get_random_template(self, category: str) -> str:
        """Get a random template from a category."""
        templates = await self.get_template(category)
        if not templates:
            return f"No templates found for {category}"
            
        template_key = random.choice(list(templates.keys()))
        return templates[template_key]
        
    async def initialize_default_templates(self):
        """
        Check if required templates exist in the database.
        
        This method should be called during application startup to ensure
        essential templates are available.
        """
        try:
            # Check if essential templates exist
            categories = [
                "cyber_herd", "cyber_herd_info", "cyber_herd_treats", 
                "sats_received", "feeder_triggered", 
                "thank_you_variations", "dm_missing_nip05", "dm_invalid_nip05"  # NIP-05 related templates
            ]
            
            missing_categories = []
            for category in categories:
                templates = await self.database.get_message_template(category)
                if not templates:
                    missing_categories.append(category)
            
            # Special handling for difference_variations
            difference_templates = await self.database.get_message_template("difference_variations")
            if not difference_templates:
                logger.info("Adding default difference_variations templates")
                # Define the difference variation templates
                default_difference_templates = {
                    1: "Donate {difference} sats to feed the goats!",
                    2: "The goats need {difference} more sats to get fed!",
                    3: "Feed our hungry goats with {difference} sats!",
                    4: "Just {difference} sats away from feeding time!",
                    5: "The goats are hungry! {difference} more sats to go!"
                }
                
                # Save templates to database
                for key, template in default_difference_templates.items():
                    await self.database.save_message_template("difference_variations", key, template)
                    logger.info(f"Added difference template {key}: {template}")
                
                # Clear cache to ensure templates are reloaded
                self.cache.clear()
            
            if missing_categories:
                logger.warning(f"Missing templates for categories: {', '.join(missing_categories)}. "
                              f"Please run migration script to populate templates.")
            else:
                logger.info("All required message templates found in database")
                
        except Exception as e:
            logger.error(f"Failed to check templates: {e}")
