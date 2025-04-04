from fastapi import APIRouter, HTTPException, Depends, Query, Body
import sys
import os

# Add parent directory to path to import communications module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from communications import calendar_to_whatsapp

router = APIRouter(
    prefix="/api/calendar",
    tags=["calendar"],
    responses={404: {"description": "Not found"}},
)

@router.post("/send-summary")
async def send_calendar_summary(
    days_ahead: int = Query(0, description="Number of days ahead to send summary for"),
    method: str = Query("whatsapp", description="Messaging method to use (whatsapp, sms, or both)"),
    recipient: str = Query(None, description="Optional recipient phone number")
):
    """
    Send a calendar summary via WhatsApp or SMS
    """
    try:
        # Validate method
        if method not in ["whatsapp", "sms", "both"]:
            raise HTTPException(status_code=400, detail="Method must be 'whatsapp', 'sms', or 'both'")
        
        # Call the calendar_to_whatsapp module to send the summary
        results = calendar_to_whatsapp.send_calendar_summary(
            days_ahead=days_ahead,
            method=method,
            recipient=recipient
        )
        
        # Return the results
        return {
            "success": True,
            "results": results,
            "whatsapp": results.get("whatsapp"),
            "sms": results.get("sms")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending calendar summary: {str(e)}")


@router.get("/subscriptions")
async def list_subscriptions():
    """
    List all calendar subscriptions
    """
    try:
        subscriptions = calendar_to_whatsapp.list_subscription_calendars()
        return subscriptions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing calendar subscriptions: {str(e)}")


@router.post("/subscription")
async def add_subscription(
    name: str = Body(..., description="Name of the calendar"),
    url: str = Body(..., description="URL of the iCal calendar feed")
):
    """
    Add a new calendar subscription
    """
    try:
        success = calendar_to_whatsapp.add_subscription_calendar(name, url)
        if success:
            return {"success": True, "message": f"Successfully added calendar subscription: {name}"}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to add calendar subscription: {name}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding calendar subscription: {str(e)}")


@router.delete("/subscription")
async def remove_subscription(
    url_or_name: str = Body(..., embed=True, description="URL or name of the calendar to remove")
):
    """
    Remove a calendar subscription by URL or name
    """
    try:
        success = calendar_to_whatsapp.remove_subscription_calendar(url_or_name)
        if success:
            return {"success": True, "message": f"Successfully removed calendar subscription: {url_or_name}"}
        else:
            raise HTTPException(status_code=404, detail=f"Calendar subscription not found: {url_or_name}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error removing calendar subscription: {str(e)}")