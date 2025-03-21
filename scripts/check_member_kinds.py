#!/usr/bin/env python3
import asyncio
import logging
import os
import sys
import sqlite3
import json

# Add parent directory to path so we can import from services
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.database_service import DatabaseService
from services.payment_service import PaymentService

logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def check_member_kinds():
    """Check and report on member kinds and LNbits splits."""
    # Database file path
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cyberherd.db')
    if not os.path.exists(db_path):
        alt_path = input(f"Database file not found at {db_path}. Enter correct path: ")
        if alt_path and os.path.exists(alt_path):
            db_path = alt_path
        else:
            logger.error("Valid database file path required")
            return
    
    # Initialize services
    db_service = DatabaseService(f'sqlite:///{db_path}')
    await db_service.connect()
    
    payment_service = PaymentService(
        lnbits_url=os.getenv('LNBITS_URL'),
        herd_key=os.getenv('HERD_KEY'),
        cyberherd_key=os.getenv('CYBERHERD_KEY'),
        hex_key=os.getenv('HEX_KEY'),
        nos_sec=os.getenv('NOS_SEC')
    )
    
    # Create HTTP client
    import httpx
    http_client = httpx.AsyncClient(http2=True)
    await payment_service.initialize(http_client)
    
    try:
        # Get all members with their kinds
        logger.info("Fetching cyberherd members...")
        members = await db_service.get_cyberherd_list()
        
        # Check LNbits targets
        logger.info("Fetching LNbits targets...")
        lnbits_targets = await payment_service.fetch_cyberherd_targets()
        
        # Create lookup dict for LNbits targets
        lnbits_dict = {}
        if lnbits_targets and "targets" in lnbits_targets:
            for target in lnbits_targets["targets"]:
                if "wallet" in target and target["wallet"] != os.getenv('PREDEFINED_WALLET_ADDRESS'):
                    lnbits_dict[target["wallet"]] = target
        
        # Print report
        logger.info(f"Found {len(members)} members and {len(lnbits_dict)} LNbits targets")
        
        print("\n--- CYBERHERD MEMBER REPORT ---\n")
        
        # Check for members with kind 7 reactions
        kind7_members = []
        for member in members:
            if not isinstance(member, dict):
                member = dict(member)
            
            kinds_str = member.get('kinds', '')
            kinds = set()
            if kinds_str:
                try:
                    kinds = {int(k.strip()) for k in kinds_str.split(',') if k.strip().isdigit()}
                except:
                    pass
            
            if 7 in kinds:
                kind7_members.append(member)
                lud16 = member.get('lud16', '')
                in_lnbits = lud16 in lnbits_dict
                
                print(f"Member with kind 7: {member.get('display_name')} ({lud16})")
                print(f"  Kinds: {kinds_str}")
                print(f"  Payouts: {member.get('payouts')}")
                if in_lnbits:
                    print(f"  LNbits Target: {lnbits_dict[lud16].get('percent')}% (wallet: {lud16})")
                else:
                    print("  WARNING: Not found in LNbits targets!")
                print()
        
        print(f"\nTotal members with kind 7: {len(kind7_members)}")
        
        # Check for discrepancies between database and LNbits
        print("\n--- DISCREPANCY REPORT ---\n")
        
        for member in members:
            if not isinstance(member, dict):
                member = dict(member)
                
            lud16 = member.get('lud16')
            if lud16 and lud16 not in lnbits_dict:
                print(f"Member {member.get('display_name')} ({lud16}) exists in database but not in LNbits!")
        
        for wallet, target in lnbits_dict.items():
            # Check if wallet exists in members
            found = False
            for member in members:
                if not isinstance(member, dict):
                    member = dict(member)
                if member.get('lud16') == wallet:
                    found = True
                    break
            
            if not found:
                print(f"Wallet {wallet} exists in LNbits targets but not in database!")
        
        # Option to fix issues
        print("\nWould you like to fix any issues found? (y/n)")
        fix = input().lower()
        if fix == 'y':
            print("1. Resync all LNbits targets from database")
            print("2. Fix specific member")
            print("3. Cancel")
            
            choice = input("Choose an option (1-3): ")
            
            if choice == '1':
                # Get wallet key
                from services.cyberherd_service import CyberHerdService
                
                # Create cyberherd service
                cyberherd_service = CyberHerdService(
                    database_service=db_service,
                    payment_service=payment_service,
                    messaging_service=None,
                    predefined_wallet_address=os.getenv('PREDEFINED_WALLET_ADDRESS'),
                    predefined_wallet_alias=os.getenv('PREDEFINED_WALLET_ALIAS'),
                    predefined_wallet_reset_percent=int(os.getenv('PREDEFINED_WALLET_PERCENT_RESET', '90'))
                )
                
                print("Updating LNbits targets from database...")
                result = await cyberherd_service.update_lnbits_targets()
                if result:
                    print("Successfully updated LNbits targets!")
                else:
                    print("Failed to update LNbits targets")
                    
            elif choice == '2':
                print("Enter lightning address of member to fix:")
                lud16 = input().strip()
                
                if not lud16:
                    print("Lightning address cannot be empty")
                    return
                    
                # Find member in database
                member = await db_service.get_cyberherd_member_by_lud16(lud16)
                if not member:
                    print(f"Member with lightning address {lud16} not found in database")
                    return
                
                print(f"Found member: {member.get('display_name')}")
                print(f"Kinds: {member.get('kinds')}")
                print(f"Payouts: {member.get('payouts')}")
                
                # Ask to add kind 7 if not present
                kinds = member.get('kinds', '')
                kinds_set = {int(k.strip()) for k in kinds.split(',') if k.strip().isdigit()} if kinds else set()
                
                if 7 not in kinds_set:
                    print("Member doesn't have kind 7. Add it? (y/n)")
                    add_kind7 = input().lower()
                    if add_kind7 == 'y':
                        kinds_set.add(7)
                        new_kinds = ','.join(map(str, sorted(kinds_set)))
                        print(f"Updating kinds to: {new_kinds}")
                        
                        # Update kinds in database
                        # This is a simplified update - actual implementation would depend on your database_service
                        conn = sqlite3.connect(db_path)
                        cur = conn.cursor()
                        try:
                            cur.execute(
                                "UPDATE cyber_herd SET kinds = ? WHERE lud16 = ?",
                                (new_kinds, lud16)
                            )
                            conn.commit()
                            print("Updated kinds successfully")
                            
                            # Update member in database service cache if needed
                            member['kinds'] = new_kinds
                        except Exception as e:
                            print(f"Error updating member: {e}")
                        finally:
                            conn.close()
                
                # Add to LNbits targets
                from services.cyberherd_service import CyberHerdService
                
                # Create cyberherd service
                cyberherd_service = CyberHerdService(
                    database_service=db_service,
                    payment_service=payment_service,
                    messaging_service=None,
                    predefined_wallet_address=os.getenv('PREDEFINED_WALLET_ADDRESS'),
                    predefined_wallet_alias=os.getenv('PREDEFINED_WALLET_ALIAS'),
                    predefined_wallet_reset_percent=int(os.getenv('PREDEFINED_WALLET_PERCENT_RESET', '90'))
                )
                
                print("Updating member in LNbits targets...")
                target_data = [{
                    'wallet': lud16,
                    'alias': member.get('display_name', member.get('pubkey', 'Unknown')),
                    'payouts': float(member.get('payouts', 0.0))
                }]
                
                result = await cyberherd_service.update_lnbits_targets(target_data)
                if result:
                    print("Successfully updated member in LNbits targets!")
                else:
                    print("Failed to update member in LNbits targets")
                
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
    finally:
        await db_service.disconnect()
        await http_client.aclose()
        await payment_service.close()

if __name__ == "__main__":
    asyncio.run(check_member_kinds())
