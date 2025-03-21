#!/usr/bin/env python3
import asyncio
import logging
import os
import sys

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def add_dm_templates():
    """Add DM message templates to the database."""
    # Initialize database connection
    db_service = DatabaseService('sqlite:///cyberherd.db')
    await db_service.connect()
    
    try:
        # Define DM templates with multiple variations
        template_categories = {
            "dm_missing_nip05": {
                1: "It looks like you don't have a NIP-05 identifier. If you'd like a {display_name}@lightning-goats.com NIP‑05 address, sign up at https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                2: "Hey there! To join the CyberHerd, you need a NIP-05 identifier. You can get your own {display_name}@lightning-goats.com address by signing up here: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                3: "Missing NIP-05 identifier detected. Want to be part of the CyberHerd? Get your custom {display_name}@lightning-goats.com identifier: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                4: "The goats noticed you're missing a NIP-05 identifier! Join the herd with your own {display_name}@lightning-goats.com address. Sign up now: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                5: "Welcome! To join the CyberHerd, you'll need a NIP-05 identifier. Get your personal {display_name}@lightning-goats.com address here: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
            },
            "dm_invalid_nip05": {
                1: "Your NIP-05 identifier has failed validation. This could be a temporary glitch. You can retry joining the cyberherd. If validation keeps failing, contact your NIP05 provider. If you'd like a {display_name}@lightning-goats.com NIP‑05 address, please sign up at https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                2: "Oops! We couldn't validate your NIP-05 identifier. Try again or consider getting a {display_name}@lightning-goats.com address at https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                3: "NIP-05 validation failed. This might be temporary - please try again. Alternatively, join with a {display_name}@lightning-goats.com identifier: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                4: "The goats couldn't verify your NIP-05! If the issue persists, contact your provider or get a new {display_name}@lightning-goats.com identifier here: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz",
                5: "Your NIP-05 identifier didn't pass verification. You can try again, check with your provider, or get a reliable {display_name}@lightning-goats.com address: https://lnb.bolverker.com/nostrnip5/signup/eGrBG7HWLJTiYyhxgEpMwz"
            }
        }
        
        # Process each template category
        for category, templates in template_categories.items():
            # Check if templates already exist
            existing_templates = await db_service.get_message_template(category)
            if existing_templates:
                logger.info(f"{category} templates already exist:")
                for key, template in existing_templates.items():
                    logger.info(f"  {key}: {template}")
                
                response = input(f"Do you want to overwrite existing {category} templates? (y/n): ").lower()
                if response != 'y':
                    logger.info(f"Skipping {category}. No changes made.")
                    continue
            
            # Process templates in this category
            logger.info(f"Adding templates for category: {category}")
            for key, template in templates.items():
                # Optionally allow customization
                new_template = input(f"Template {key} [{template}]: ")
                if new_template:
                    templates[key] = new_template
                
                # Save to database
                await db_service.save_message_template(category, key, templates[key])
                logger.info(f"Added template {category}:{key}")
        
        logger.info("All DM templates added successfully!")
        
    except Exception as e:
        logger.error(f"Error adding DM templates: {e}")
    finally:
        await db_service.disconnect()

if __name__ == "__main__":
    asyncio.run(add_dm_templates())
