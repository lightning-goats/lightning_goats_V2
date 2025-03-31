from typing import Dict, Any, Optional, List, Union # Added Union
from fastapi import APIRouter, HTTPException, Depends, Header, Request, Response, Body, Query
from fastapi.responses import JSONResponse # Import JSONResponse
import logging
# import httpx # Not used directly in this file anymore
import datetime # Ensure datetime is imported if used (e.g., default expirations, though not directly here now)

# Service for L402 tokens
from services.l402_service import L402Service

# Initialize logger
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/l402",
    tags=["l402"],
    responses={
        404: {"description": "Not found"},
        401: {"description": "Unauthorized"},
        402: {"description": "Payment Required"}, # Already defined, but relevant
        403: {"description": "Forbidden"},
        500: {"description": "Internal Server Error"},
    },
)

# Reference to the L402 service
_l402_service: Optional[L402Service] = None

def initialize_services(l402_service: L402Service):
    """Initialize the services needed for this router."""
    global _l402_service
    _l402_service = l402_service
    logger.info("L402 routes initialized with L402 service.")

# Dependency to get L402 service
async def get_l402_service() -> L402Service:
    if _l402_service is None:
        logger.error("L402Service requested but not initialized.")
        raise HTTPException(status_code=500, detail="L402Service not initialized")
    return _l402_service

# Dependency to handle L402 authentication
async def l402_auth_dependency(
    request: Request,
    # response: Response, # No longer needed directly in signature for this approach
    l402_service: L402Service = Depends(get_l402_service),
    authorization: Optional[str] = Header(None)
) -> Union[Dict[str, Any], JSONResponse]: # Return type can now be JSONResponse too
    """
    Perform LSAT authentication check based on Authorization header.
    Returns 402 JSONResponse with challenge if no valid header is found.
    Returns verified token data dictionary if authentication succeeds.
    Raises HTTPException for other errors (400, 401, 403, 500).
    """
    if not authorization:
        # No authorization header, initiate LSAT challenge
        logger.info("No Authorization header found. Initiating LSAT challenge")
        path_parts = request.url.path.strip('/').split('/')
        # Assuming format like /l402/protected/{resource_id}
        resource_id = path_parts[-1] if len(path_parts) > 2 and path_parts[-2] == 'protected' else None

        if not resource_id:
             logger.error(f"Cannot determine resource ID from path: {request.url.path}")
             # Use HTTPException for actual errors
             raise HTTPException(status_code=400, detail="Cannot determine resource ID from path")

        amount = l402_service.default_price # Use default price from service (e.g., 1 sat)

        invoice_data = await l402_service.create_invoice_and_token(
            resource_id=resource_id,
            amount=amount
        )

        # Check for errors during invoice/token creation
        if "error" in invoice_data or "challenge" not in invoice_data:
            error_msg = invoice_data.get('error', 'Unknown error')
            status_code = invoice_data.get('status_code', 500)
            logger.error(f"Failed to generate challenge (Status: {status_code}): {error_msg}")
            # Use HTTPException for internal errors during challenge generation
            raise HTTPException(status_code=status_code, detail=f"Failed to generate payment challenge: {error_msg}")

        challenge_header_value = invoice_data["challenge"]
        logger.debug(f"Returning 402 JSONResponse with WWW-Authenticate: {challenge_header_value}")

        # *** FIX: Return JSONResponse directly instead of raising HTTPException for 402 ***
        return JSONResponse(
            status_code=402,
            # Include details useful for the client in the body
            content={
                "detail": "Payment Required",
                "invoice": invoice_data.get("invoice"),
                "payment_hash": invoice_data.get("payment_hash"),
                "amount": invoice_data.get("amount"),
                "token_id": invoice_data.get("token_id"), # Include token ID if helpful
                "expires_at": invoice_data.get("expires_at") # Include expiry if helpful
                },
            headers={"WWW-Authenticate": challenge_header_value}
        )
        # *** End of FIX ***

    # --- Authorization header exists ---
    logger.info("Authorization header found, attempting LSAT verification.")
    is_valid, verification_result = await l402_service.verify_lsat(authorization)

    if not is_valid:
        error_detail = verification_result.get("error", "Invalid LSAT token")
        # Use status code provided by verify_lsat if available (e.g., 400, 401), default 401
        status_code = verification_result.get("status_code", 401)
        logger.warning(f"LSAT verification failed: {error_detail} (Status: {status_code})")
        # Use HTTPException for auth errors (401)
        raise HTTPException(status_code=status_code, detail=error_detail)

    # --- LSAT is valid ---
    logger.info(f"LSAT verification successful for token ID: {verification_result.get('token_id')}")

    # --- Check resource scope ---
    requested_resource_id = request.url.path.split('/')[-1] # Re-extract for safety
    token_resource_id = verification_result.get("resource_id")

    if token_resource_id != requested_resource_id:
         logger.warning(f"Forbidden: LSAT token resource '{token_resource_id}' does not match requested resource '{requested_resource_id}'")
         # Use HTTPException for permissions errors (403)
         raise HTTPException(status_code=403, detail=f"Token not valid for resource '{requested_resource_id}'")

    # If we reach here, auth is successful, return the verified data dictionary
    return verification_result

# --- Endpoints ---

@router.get("/protected/{resource_id}",
            summary="Access Protected Resource",
            description="Access a resource protected by LSAT. Requires 'Authorization: LSAT <mac>:<pre>' header. Issues 402 challenge if no valid token.")
async def protected_resource_example(
    resource_id: str,
    # The dependency might now return a JSONResponse OR the verified dict
    auth_result: Union[Dict[str, Any], JSONResponse] = Depends(l402_auth_dependency),
    l402_service: L402Service = Depends(get_l402_service) # Inject service for notifications etc.
):
    """
    A protected resource that requires standard LSAT authentication.
    The l402_auth_dependency handles the challenge/verification flow.
    It might return a 402 JSONResponse directly, which needs to be returned by this route.
    """
    # *** Check if the dependency returned the 402 response ***
    if isinstance(auth_result, JSONResponse):
        # If the dependency already created the 402 response, just return it
        logger.debug("Propagating 402 JSONResponse from dependency.")
        return auth_result
    # *** End Check ***

    # Otherwise, auth_result is the verified_token_data dictionary
    verified_token_data = auth_result

    # If we get here, authentication was successful
    logger.info(f"Access granted to protected resource '{resource_id}' for token ID '{verified_token_data.get('token_id', 'N/A')}'")

    try:
        # Determine content based on resource ID
        content = f"This is the super secret protected content for resource: {resource_id}."
        if resource_id == "basic-feed":
            content = "Lightning Goats Camera Switch Access"
        elif resource_id == "premium-feed":
            content = "Lightning Goats Advertising Access"

        expires_at = verified_token_data.get("expires_at", 0)
        user_id = verified_token_data.get('user_id') or 'anonymous'

        # Send notification (non-critical, don't fail request if this errors)
        try:
             await l402_service.send_resource_access_notification(
                 user_id, resource_id, verified_token_data
             )
        except Exception as notify_err:
             logger.warning(f"Failed to send resource access notification: {notify_err}")


        # Return the actual resource content
        return {
            "resource_id": resource_id,
            "content": content,
            "access_expires": expires_at,
            "token_id": verified_token_data.get('token_id'),
            "user_id": user_id,
        }
    except Exception as e:
        logger.exception(f"Error generating response for protected resource '{resource_id}': {e}")
        # Use HTTPException for internal server errors within the route logic itself
        raise HTTPException(status_code=500, detail="Internal server error processing resource")


@router.post("/invoice", summary="Request Invoice and Challenge (Alternative Flow)")
async def create_invoice_challenge(
    # ... (parameters: resource_id, amount, expiry, user_id, metadata) ...
    resource_id: str = Body(..., description="ID of the resource to access"),
    amount: Optional[int] = Body(None, description="Amount in satoshis (uses default if not specified)"),
    expiry: Optional[int] = Body(None, description="Time in seconds until token expires (uses default if not specified)"),
    user_id: Optional[str] = Body(None, description="Optional user identifier"),
    metadata: Dict[str, Any] = Body({}, description="Optional metadata to include with the token"),
    l402_service: L402Service = Depends(get_l402_service)
):
    """
    Manually requests a Lightning invoice and associated token details
    needed to construct an LSAT challenge later. This is an alternative
    to triggering the 402 response by accessing the protected resource directly.
    """
    try:
        result = await l402_service.create_invoice_and_token(
            resource_id=resource_id,
            amount=amount,
            expiry=expiry,
            user_id=user_id,
            metadata=metadata
        )

        if "error" in result:
            status_code = result.get("status_code", 500)
            raise HTTPException(status_code=status_code, detail=result["error"])

        # Return details needed by client
        return {
            "token_id": result.get("token_id"),
            "invoice": result.get("invoice"),
            "payment_hash": result.get("payment_hash"),
            "amount": result.get("amount"),
            "expires_at": result.get("expires_at"),
            # "challenge": result.get("challenge") # Usually not needed in body if obtained via 402 header
        }

    except HTTPException:
        raise # Re-raise exceptions from service
    except Exception as e:
        logger.error(f"Error creating invoice challenge via POST /invoice: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/payment/{payment_hash_or_id}", summary="Check Payment Status & Get Preimage")
async def check_payment_status_and_get_preimage(
    payment_hash_or_id: str,
    l402_service: L402Service = Depends(get_l402_service)
):
    """
    Checks if the payment associated with a payment_hash (or token_id)
    has been settled. If settled, returns the preimage required to
    construct the final LSAT. Clients poll this endpoint after paying the invoice.
    """
    # --- Logic remains the same, relying on L402Service ---
    try:
        logger.debug(f"Checking payment status for hash or ID: {payment_hash_or_id[:20]}...")

        # Determine if input is likely a token_id or payment_hash
        is_token_id = len(payment_hash_or_id) == 36 and '-' in payment_hash_or_id
        is_payment_hash = len(payment_hash_or_id) == 64 and all(c in '0123456789abcdefABCDEF' for c in payment_hash_or_id)

        token_id = None
        payment_hash = None

        if is_token_id:
            token_id = payment_hash_or_id
            token = await l402_service.database_service.get_l402_token(token_id)
            if not token:
                raise HTTPException(status_code=404, detail=f"Token with ID {token_id} not found.")
            payment_hash = token['payment_hash']
            logger.info(f"Checking payment for token ID {token_id}, using payment hash: {payment_hash[:10]}...")
        elif is_payment_hash:
            payment_hash = payment_hash_or_id
            logger.info(f"Checking payment for payment hash: {payment_hash[:10]}...")
            # Find associated token ID for context/update if needed
            tokens = await l402_service.database_service.get_l402_tokens({'payment_hash': payment_hash})
            if tokens: token_id = tokens[0]['token_id']
        else:
             # Handle BOLT11 or other invalid inputs
             if payment_hash_or_id.startswith("lnbc"):
                 try:
                     # Use service method to extract hash
                     extracted_hash = await l402_service.extract_payment_hash(payment_hash_or_id)
                     if not extracted_hash: raise ValueError("Could not extract payment hash from invoice")
                     payment_hash = extracted_hash
                     logger.info(f"Checking payment for invoice, using payment hash: {payment_hash[:10]}...")
                     tokens = await l402_service.database_service.get_l402_tokens({'payment_hash': payment_hash})
                     if tokens: token_id = tokens[0]['token_id']
                 except Exception as e:
                     logger.warning(f"Invalid input or failed invoice decode/hash extraction for '{payment_hash_or_id[:20]}...': {e}")
                     raise HTTPException(status_code=400, detail=f"Invalid format or failed invoice processing.")
             else:
                 raise HTTPException(status_code=400, detail="Invalid format: Provide payment hash, token ID, or BOLT11 invoice.")

        # Now we have a payment_hash, check status and get preimage
        payment_info = await l402_service.get_payment_status_and_preimage(payment_hash)

        # Handle potential None return from service if checks fail critically
        if payment_info is None:
             logger.error(f"Critical error checking payment status/preimage for {payment_hash[:10]}... Service returned None.")
             raise HTTPException(status_code=500, detail="Internal error checking payment status.")


        status = payment_info.get("status")
        preimage = payment_info.get("preimage")
        message = payment_info.get("message")
        error = payment_info.get("error")

        if status == "paid" and preimage:
            logger.info(f"Payment confirmed for hash {payment_hash[:10]}... Preimage available.")
            if token_id:
                # Ensure DB is updated (might be redundant)
                await l402_service.database_service.update_l402_token_status(token_id, {'is_paid': True})
            return {"status": "paid", "preimage": preimage}
        elif status == "paid":
             logger.warning(f"Payment confirmed for hash {payment_hash[:10]}... but preimage *not* available.")
             if token_id: await l402_service.database_service.update_l402_token_status(token_id, {'is_paid': True})
             # Still return paid, client might need manual preimage entry
             return {"status": "paid", "preimage": None, "message": "Payment confirmed, but preimage could not be retrieved automatically."}
        elif status == "pending":
            logger.debug(f"Payment pending for hash {payment_hash[:10]}...")
            return {"status": "pending", "message": message or "Payment not settled yet."}
        elif status == "not_found":
             logger.warning(f"Payment/Invoice {payment_hash[:10]}... not found.")
             # Return 404 specifically for not found
             raise HTTPException(status_code=404, detail=message or "Payment or invoice not found.")
        elif status == "expired":
             logger.warning(f"Invoice {payment_hash[:10]}... has expired.")
             # Could return 410 Gone, or just a specific status
             return {"status": "expired", "message": message or "Invoice expired."}
        elif status == "error":
            logger.error(f"Error checking payment status for hash {payment_hash[:10]}...: {error} - {message}")
            # Determine status code based on error type if possible
            status_code = 500 if "internal" in (error or "").lower() else 503 # 503 Service Unavailable if payment service failed
            raise HTTPException(status_code=status_code, detail=message or error or "Failed to check payment status")
        else: # Handle other unknown statuses
            logger.warning(f"Payment status for hash {payment_hash[:10]}... is '{status}'. Message: {message}")
            return {"status": status or "unknown", "message": message or f"Payment status: {status}"}

    except HTTPException:
        raise # Re-raise existing HTTP exceptions
    except Exception as e:
        logger.error(f"Unexpected error in GET /payment/{payment_hash_or_id[:20]}...': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/extract_hash", summary="Extract Payment Hash from Invoice (Helper)")
async def extract_payment_hash_from_invoice_endpoint(
    invoice: str = Query(..., description="BOLT11 invoice string"),
    l402_service: L402Service = Depends(get_l402_service)
):
    """
    Helper endpoint to extract the payment hash from a BOLT11 invoice.
    Useful for clients that cannot easily decode invoices themselves.
    """
    # --- Logic remains the same, relying on L402Service ---
    try:
        payment_hash = await l402_service.extract_payment_hash(invoice)
        if not payment_hash:
             raise HTTPException(status_code=400, detail="Could not extract payment hash from the provided invoice string.")

        return {"payment_hash": payment_hash, "invoice_provided": invoice}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error extracting payment hash from invoice '{invoice[:30]}...': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# --- Other endpoints (verify, refresh, tokens) are less critical for the main flow fix ---
# --- but should be reviewed for consistency if used ---

@router.get("/verify", summary="Verify LSAT (Debug/Alternative Flow)", deprecated=True)
async def verify_lsat_endpoint(
    response: Response, # Keep Response for direct status/header setting
    l402_service: L402Service = Depends(get_l402_service),
    authorization: Optional[str] = Header(None, description="Authorization header with LSAT token (LSAT macaroon_b64:preimage)")
):
    """DEPRECATED: Verifies an LSAT token. Standard flow uses the protected resource endpoint."""
    # ... (implementation largely unchanged, might need status code adjustments) ...
    if not authorization:
        response.status_code = 402
        response.headers["WWW-Authenticate"] = f'LSAT realm="lightning-goats.com", service="general"'
        return {"error": "Payment required", "message": "Provide LSAT in Authorization header or request an invoice"}

    is_valid, verification_result = await l402_service.verify_lsat(authorization)

    if not is_valid:
        error_detail = verification_result.get("error", "Invalid LSAT token")
        status_code = verification_result.get("status_code", 401)
        response.status_code = status_code
        return {"status": "invalid", "error": error_detail}

    return { "status": "success", "token": { # Return minimal info
            "token_id": verification_result.get("token_id"),
            "resource_id": verification_result.get("resource_id"),
            "user_id": verification_result.get("user_id"),
            "expires_at": verification_result.get("expires_at"),
        }
    }

@router.post("/refresh", summary="Refresh LSAT Expiry (Requires Existing Valid LSAT)")
async def refresh_lsat(
    # response: Response, # Don't need Response object here unless setting custom headers
    new_expiry_seconds: Optional[int] = Body(None, description="New expiry time in seconds from now (uses default if not specified)"),
    l402_service: L402Service = Depends(get_l402_service),
    # Require existing valid LSAT for authorization
    auth_result: Union[Dict[str, Any], JSONResponse] = Depends(l402_auth_dependency)
):
    """
    Refreshes the expiry time of an existing *paid* and *valid* LSAT.
    Requires the original valid LSAT in the Authorization header for authorization.
    Returns a *new* LSAT string (new macaroon, same preimage) with the updated expiry.
    """
    # Check if auth dependency returned a 402 response (meaning no valid LSAT provided)
    if isinstance(auth_result, JSONResponse):
         # Re-raise as a standard 401 because refresh requires prior auth
         raise HTTPException(status_code=401, detail="Authorization header with existing valid LSAT required for refresh")

    # Auth was successful, auth_result is the verified_token_data
    verified_token_data = auth_result
    token_id = verified_token_data.get("token_id")
    original_preimage = verified_token_data.get("preimage")

    if not token_id or not original_preimage:
         logger.error(f"Cannot refresh LSAT: Missing token_id or preimage in verification result for token {token_id}")
         raise HTTPException(status_code=500, detail="Internal error during token refresh setup")

    try:
        refresh_result = await l402_service.refresh_token(token_id, new_expiry_seconds)

        if "error" in refresh_result:
            status_code = refresh_result.get("status_code", 400)
            raise HTTPException(status_code=status_code, detail=refresh_result["error"])

        # Construct the new full LSAT string
        new_macaroon_b64 = refresh_result["macaroon_b64"]
        new_lsat = f"LSAT {new_macaroon_b64}:{original_preimage}"

        return {
            "message": "LSAT refreshed successfully",
            "new_lsat": new_lsat,
            "token_id": token_id,
            "new_expires_at": refresh_result["expires_at"]
        }

    except HTTPException: raise
    except Exception as e:
        logger.error(f"Error refreshing LSAT token {token_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error during refresh: {str(e)}")


@router.get("/tokens", summary="List Active LSAT Tokens (Admin/Debug)")
async def get_active_tokens(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    include_expired: bool = Query(False, description="Include expired but paid tokens"),
    l402_service: L402Service = Depends(get_l402_service)
):
    """Get active (paid and optionally non-expired) LSAT tokens."""
    # --- Logic remains the same, relying on L402Service ---
    try:
        tokens = await l402_service.get_tokens(user_id, resource_id, include_expired=include_expired)
        # Avoid leaking sensitive data like full macaroons or preimages
        safe_tokens = [{k: v for k, v in token.items() if k not in ['macaroon', 'preimage', 'secret_key']} for token in tokens]
        return {"tokens": safe_tokens, "count": len(safe_tokens)}

    except Exception as e:
        logger.error(f"Error fetching tokens: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")