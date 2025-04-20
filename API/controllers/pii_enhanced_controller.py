# api/controllers/pii_enhanced_controller.py
"""
PII Data controller for the GUARD application.

This module provides FastAPI endpoints for retrieving and managing PII data.
"""

import logging
from typing import Dict, Any, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel, Field

from api.auth.middleware import auth_required
from api.data.database import DatabaseHandler
import os

# Configure logging
logger = logging.getLogger("api.controllers.pii")
logger.setLevel(logging.INFO)

# Set up performance monitoring
import time
from functools import wraps

def timing_decorator(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        logger.info(f"Function {func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper

# Create router
router = APIRouter(prefix="/pii", tags=["PII Data"])

# Create database handler
if os.environ.get("USE_MOCK_DB", "false").lower() == "true":
    # Mock database for development
    class MockDatabaseHandler:
        def __init__(self):
            self.items = {}
            self.logger = logging.getLogger("api.data.mock_database")
            self.logger.info("Using mock database handler")
        
        def get_all_items(self, user):
            self.logger.info(f"Getting all items for user: {user}")
            user_items = [item for item in self.items.values() if item.get('user') == user]
            return True, user_items
        
        def get_item_by_id(self, item_id):
            self.logger.info(f"Getting item by ID: {item_id}")
            if item_id in self.items:
                return True, self.items[item_id]
            return False, "Item not found"
        
        def decrypt_item(self, item):
            # In mock, no encryption is used
            return True, item
        
        def create_item(self, item, user_id, auth_type):
            import uuid
            from datetime import datetime
            
            item_id = str(uuid.uuid4())
            self.logger.info(f"Creating item with ID: {item_id}")
            
            # Convert to dict if it's a Pydantic model
            if hasattr(item, "dict"):
                item_dict = item.dict()
            else:
                item_dict = item
                
            # Create item in mock database
            self.items[item_id] = {
                '_id': item_id,
                'Category': item_dict.get("category"),
                'Type': item_dict.get("type"),
                'PII': item_dict.get("pii"),
                'created_at': datetime.now().isoformat(),
                'user': user_id
            }
            
            return True, self.items[item_id]
        
        def update_item(self, item, user_id, auth_type):
            # Convert to dict if it's a Pydantic model
            if hasattr(item, "dict"):
                item_dict = item.dict()
            else:
                item_dict = item
                
            item_id = item_dict.get("id")
            self.logger.info(f"Updating item with ID: {item_id}")
            
            if item_id not in self.items:
                return False, "Item not found"
            
            # Update fields
            if item_dict.get("category") is not None:
                self.items[item_id]['Category'] = item_dict.get("category")
                
            if item_dict.get("type") is not None:
                self.items[item_id]['Type'] = item_dict.get("type")
                
            if item_dict.get("pii") is not None:
                self.items[item_id]['PII'] = item_dict.get("pii")
                
            # Update metadata
            self.items[item_id]['updated_at'] = datetime.now().isoformat()
            self.items[item_id]['updated_by'] = user_id
            
            return True, self.items[item_id]
        
        def delete_item(self, item, user_id, auth_type):
            # Convert to dict if it's a Pydantic model
            if hasattr(item, "dict"):
                item_dict = item.dict()
            else:
                item_dict = item
                
            item_id = item_dict.get("id")
            self.logger.info(f"Deleting item with ID: {item_id}")
            
            if item_id not in self.items:
                return False, "Item not found"
            
            # Delete the item
            deleted_item = self.items.pop(item_id)
            
            return True, deleted_item
            
    db_handler = MockDatabaseHandler()
    
    # Add some sample data for testing
    import uuid
    from datetime import datetime
    
    # Sample user ID
    user_id = 'keshavaone'
    
    # Sample data items
    sample_items = [
        {
            "category": "Financial",
            "type": "Credit Card",
            "pii": [
                {"name": "Card Number", "value": "4111-1111-1111-1111"},
                {"name": "Expiry", "value": "12/25"},
                {"name": "CVV", "value": "123"}
            ]
        },
        {
            "category": "Personal",
            "type": "Home Address",
            "pii": [
                {"name": "Street", "value": "123 Main St"},
                {"name": "City", "value": "New York"},
                {"name": "State", "value": "NY"},
                {"name": "Zip", "value": "10001"}
            ]
        },
        {
            "category": "Medical",
            "type": "Insurance",
            "pii": [
                {"name": "Policy Number", "value": "MED1234567"},
                {"name": "Provider", "value": "BlueCross"},
                {"name": "Type", "value": "Health"},
                {"name": "Group Number", "value": "G-12345"}
            ]
        },
        {
            "category": "Accounts",
            "type": "Email",
            "pii": [
                {"name": "Email", "value": "john.doe@example.com"},
                {"name": "Password", "value": "SecureP@ssword123"},
                {"name": "Recovery Email", "value": "backup@example.com"}
            ]
        }
    ]
    
    # Add items to mock database
    for item in sample_items:
        # Convert PII data to JSON string
        import json
        pii_data_str = json.dumps(item["pii"])
        
        # Create and add item
        item_id = str(uuid.uuid4())
        db_handler.items[item_id] = {
            '_id': item_id,
            'Category': item["category"],
            'Type': item["type"],
            'PII': pii_data_str,
            'created_at': datetime.now().isoformat(),
            'user': user_id
        }
    
    logger.info(f"Added {len(sample_items)} sample PII items to mock database for testing")
else:
    # Use real database handler for production
    db_handler = DatabaseHandler()

class PiiDataItem(BaseModel):
    """PII data field model."""
    name: str
    value: str

class PiiItemCreate(BaseModel):
    """Model for creating a new PII item."""
    category: str
    type: str
    piiData: List[Dict[str, str]]

class PiiItemUpdate(BaseModel):
    """Model for updating an existing PII item."""
    category: Optional[str] = None
    type: Optional[str] = None
    piiData: Optional[List[Dict[str, str]]] = None

@router.get("/", response_model=List[Dict[str, Any]])
@timing_decorator
async def get_all_pii_data(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    category: Optional[str] = Query(None, description="Filter by category"),
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get all PII data items.
    
    This endpoint supports pagination and filtering by category.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting all PII data for user: {user_info.get('sub')} from {client_ip}")
        print(f"GET /pii/ API CALL - client: {client_ip}, user: {user_info.get('sub')}")
        
        # Get user ID from the token with fallbacks
        user_id = user_info.get('sub', '')
        print(f"Original user_id from token: {user_id}")
        
        # Extract the actual ID from potential formats like "cognito:user123" or "oidc:alice@example.com"
        if ':' in user_id:
            user_id = user_id.split(':')[-1]
        
        # If user_id is empty or None, use a fallback
        if not user_id:
            user_id = "keshavaone"  # Hardcoded known user from scan results
            print(f"Using fallback user_id: {user_id}")
        else:
            print(f"Using extracted user_id: {user_id}")
        
        # Get all items for this user
        success, items = db_handler.get_all_items(user_id)
        
        if not success:
            logger.error(f"Database error: {items}")
            print(f"Database error: {items}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Database error"
            )
        
        # Filter by category if specified
        if category:
            items = [item for item in items if item.get('Category') == category]
        
        # Count total items after filtering
        total_items = len(items)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_items = items[start_idx:end_idx]
        
        # ... (imports and earlier parts of the function remain unchanged)

        # Decrypt and transform items
        transformed_items = []
        for item in paginated_items:
            # Debug print: raw item
            print(f"Raw item before decryption: {item}")
            
            # Decrypt the item from the DB
            success, decrypted_item = db_handler.decrypt_item(item)
            if not success:
                logger.warning(f"Failed to decrypt item: {item.get('_id')}")
                print(f"Failed to decrypt item: {item.get('_id')}, skipping")
                continue
                
            print(f"Decrypted item: {decrypted_item}")
                
            try:
                # Find the PII field (common keys: 'PII', 'pii', 'Data', etc.)
                pii_field = None
                for possible_field in ['PII', 'pii', 'Data']:
                    if possible_field in decrypted_item:
                        pii_field = possible_field
                        break
                
                if pii_field:
                    print(f"Using PII field: {pii_field}")
                    pii_data = decrypted_item.get(pii_field, '[]')
                else:
                    print("No PII field found in item")
                    pii_data = '[]'
                
                # Ensure pii_data is a string for further processing
                if not isinstance(pii_data, str):
                    pii_data = str(pii_data)

                # Parse PII data from string to structured format
                if isinstance(pii_data, str):
                    print("Parsing string PII data")
                    
                    # First try to detect Z0FB encrypted PII data for special handling
                    if pii_field == 'PII' and pii_data.startswith('Z0FB'):
                        try:
                            print("Detected encrypted PII data in Z0FB format, attempting specialized decryption")
                            from api.encryption import get_kms_handler
                            handler = get_kms_handler()
                            if handler and hasattr(handler, 'decrypt_pii_data'):
                                decrypted_data = handler.decrypt_pii_data(pii_data)
                                if decrypted_data:
                                    print("Successfully decrypted PII data directly in controller")
                                    pii_data = decrypted_data
                                    print(f"Decrypted data: {pii_data[:50]}...")
                                else:
                                    print("decrypt_pii_data returned None")
                            else:
                                print("KMS handler not available or missing decrypt_pii_data method")
                        except Exception as decrypt_error:
                            print(f"Error decrypting PII data: {decrypt_error}")
                    
                    # Try JSON parsing first
                    try:
                        import json
                        pii_fields = json.loads(pii_data)
                        print(f"Successfully parsed JSON data: {type(pii_fields)}")
                        if not isinstance(pii_fields, list):
                            if isinstance(pii_fields, dict):
                                # If it already has a name/value format, use that
                                if 'name' in pii_fields and 'value' in pii_fields:
                                    pii_fields = [pii_fields]
                                # Check for nested JSON strings in values
                                elif any(isinstance(v, str) and (v.startswith('[') or v.startswith('{')) for v in pii_fields.values()):
                                    nested_fields = []
                                    print("Entered dict instance check for nested JSON values")
                                    for k, v in pii_fields.items():
                                        if isinstance(v, str) and (v.startswith('[') or v.startswith('{')):
                                            try:
                                                parsed_v = json.loads(v)
                                                nested_fields.append({"Item Name": k, "Data": json.dumps(parsed_v, indent=2)})
                                            except:
                                                nested_fields.append({"Item Name": k, "Data": v})
                                        else:
                                            nested_fields.append({"Item Name": k, "Data": v})
                                    pii_fields = nested_fields
                                else:
                                    pii_fields = [{"Item Name": k, "Data": v} for k, v in pii_fields.items()]
                            elif isinstance(pii_fields, (str, int, float, bool)):
                                pii_fields = [{"Item Name": "Data", "Data": pii_fields}]
                            else:
                                pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                    except json.JSONDecodeError:
                        print("JSON parsing failed, trying ast.literal_eval")
                        import ast
                        try:
                            pii_fields = ast.literal_eval(pii_data)
                            if not isinstance(pii_fields, list):
                                pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                        except (ValueError, SyntaxError):
                            print("All parsing failed, using raw data")
                            pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                else:
                    print(f"Using non-string PII data: {type(pii_data)}")
                    pii_fields = pii_data
                
                # Process each PII field ensuring that value is a string before calling startswith
                formatted_pii_data = []
                for field in pii_fields:
                    if isinstance(field, dict):
                        name = field.get("Item Name", field.get("name", field.get("key", "")))
                        value = field.get("Data", field.get("value", field.get("val", "")))
                        # If not found, use first key/value pair if possible
                        if not name and not value and len(field) > 0:
                            first_key = next(iter(field))
                            name = first_key
                            value = field[first_key]
                        
                        # Ensure value is a string before using string methods
                        if not isinstance(value, str):
                            value = str(value)
                        
                        json_object = None
                        if value.startswith('{') or value.startswith('['):
                            try:
                                import json
                                json_object = json.loads(value)
                                if isinstance(json_object, (dict, list)):
                                    value = json.dumps(json_object, indent=2)
                                    print(f"Formatted nested JSON for field '{name}'")
                            except Exception as e:
                                print(f"Failed to parse JSON for field '{name}': {e}")
                        
                        field_data = {"name": name, "value": value}
                        if json_object is not None:
                            field_data["isJson"] = True
                        formatted_pii_data.append(field_data)
                    elif isinstance(field, (str, int, float, bool)):
                        formatted_pii_data.append({"name": "Value", "value": str(field)})
                
                # Fallback if no formatted data
                if not formatted_pii_data and isinstance(pii_data, str):
                    try:
                        import json
                        if pii_data.startswith('{') or pii_data.startswith('['):
                            parsed_json = json.loads(pii_data)
                            if isinstance(parsed_json, dict):
                                for k, v in parsed_json.items():
                                    formatted_pii_data.append({"name": k, "value": str(v)})
                            elif isinstance(parsed_json, list):
                                for item in parsed_json:
                                    for k, v in item.items():
                                        formatted_pii_data.append({"name": k, "value": str(v)})
                            else:
                                formatted_pii_data.append({"name": "JSON Data", "value": json.dumps(parsed_json, indent=2)})
                    except json.JSONDecodeError:
                        formatted_pii_data.append({"name": "Data", "value": pii_data})
                
                print(f"Formatted PII data: {formatted_pii_data}")
                
                # Metadata and final UI item creation
                security_level = "high"
                if decrypted_item.get('Category') == "Personal":
                    security_level = "medium"
                elif "password" in decrypted_item.get('Type', '').lower() or "account" in decrypted_item.get('Type', '').lower():
                    security_level = "high"
                
                created_at = decrypted_item.get('created_at', '')
                updated_at = decrypted_item.get('updated_at', '')
                last_updated = "just now"
                if updated_at or created_at:
                    from datetime import datetime
                    import pytz
                    timestamp_str = updated_at if updated_at else created_at
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        timestamp = timestamp.replace(tzinfo=pytz.UTC)
                        now = datetime.now(pytz.UTC)
                        diff = now - timestamp
                        if diff.days > 30:
                            months = diff.days // 30
                            last_updated = f"{months} month{'s' if months > 1 else ''} ago"
                        elif diff.days > 0:
                            last_updated = f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
                        elif diff.seconds // 3600 > 0:
                            hours = diff.seconds // 3600
                            last_updated = f"{hours} hour{'s' if hours > 1 else ''} ago"
                        else:
                            minutes = (diff.seconds // 60) % 60
                            last_updated = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                    except Exception:
                        last_updated = "unknown"
                
                category = None
                item_type = None
                for key in decrypted_item.keys():
                    if key.lower() == 'category':
                        val = decrypted_item[key]
                        if isinstance(val, dict) and 'S' in val:
                            category = val['S']
                        else:
                            category = val
                    elif key.lower() == 'type':
                        val = decrypted_item[key]
                        if isinstance(val, dict) and 'S' in val:
                            item_type = val['S']
                        else:
                            item_type = val
                
                item_id = decrypted_item.get('_id', decrypted_item.get('id', str(uuid.uuid4())))
                print(f"Creating UI item with ID: {item_id}, Category: {category}, Type: {item_type}")
                
                ui_item = {
                    "id": item_id,
                    "category": category or decrypted_item.get('Category') or "Unknown",
                    "type": item_type or decrypted_item.get('Type') or "Data",
                    "securityLevel": security_level,
                    "lastUpdated": last_updated,
                    "piiData": formatted_pii_data,
                    "createdAt": created_at,
                    "updatedAt": updated_at,
                    "createdBy": decrypted_item.get('created_by', user_id),
                    "accessCount": decrypted_item.get('access_count', 0)
                }
                print('UI Item', ui_item)
                transformed_items.append(ui_item)
            except Exception as e:
                logger.warning(f"Error transforming item {item.get('_id')}: {e}")
                continue

# ... (pagination metadata and final response code remains unchanged)

        
                
        # Create pagination metadata
        pagination = {
            "page": page,
            "limit": limit,
            "total": total_items,
            "pages": (total_items + limit - 1) // limit
        }
        
        # Add pagination headers
        request.state.pagination = pagination
        
        # Final processing for Data column decryption
        for item in transformed_items:
            # Check for special handling of Data fields in PII data
            for field in item.get('piiData', []):
                if isinstance(field.get('value'), str) and field.get('value').startswith('{') or field.get('value').startswith('['):
                    try:
                        import json
                        json_value = json.loads(field['value'])
                        # Format JSON for better readability in the UI
                        field['value'] = json.dumps(json_value, indent=2)
                        field['isJson'] = True
                    except:
                        # Not valid JSON, keep as is
                        pass
        
        # Print the response for debugging - avoid printing the entire response which could be large
        print(f"PII Data Response: {len(transformed_items)} items processed")
        if transformed_items:
            print(f"First item ID: {transformed_items[0].get('id')}, Category: {transformed_items[0].get('category')}")
        
        # Process the API response - use JSONResponse for consistent format
        from fastapi.responses import JSONResponse
        
        # Ensure we have proper item formatting
        for item in transformed_items:
            # Make sure piiData exists and is a list 
            if 'piiData' not in item or item['piiData'] is None:
                item['piiData'] = []
            elif not isinstance(item['piiData'], list):
                # Convert non-list piiData to list format
                if isinstance(item['piiData'], str):
                    try:
                        # Try to parse as JSON
                        import json
                        parsed = json.loads(item['piiData'])
                        if isinstance(parsed, list):
                            item['piiData'] = parsed
                        elif isinstance(parsed, dict):
                            item['piiData'] = [{"name": k, "value": v} for k, v in parsed.items()]
                        else:
                            item['piiData'] = [{"name": "Data", "value": item['piiData']}]
                    except:
                        item['piiData'] = [{"name": "Data", "value": item['piiData']}]
                else:
                    item['piiData'] = [{"name": "Data", "value": str(item['piiData'])}]
                    
            # Ensure each piiData item has name and value
            for i, field in enumerate(item['piiData']):
                if not isinstance(field, dict):
                    item['piiData'][i] = {"name": f"Item {i+1}", "value": str(field)}
                elif 'name' not in field:
                    field['name'] = f"Item {i+1}"
                elif 'value' not in field:
                    field['value'] = ""
        
        # Print the final processed response structure (first item only)
        if transformed_items:
            print(f"Final response structure (first item):")
            first_item = transformed_items[0]
            print('FIRST ITEM', first_item)
            print(f"  id: {first_item.get('id')}")
            print(f"  category: {first_item.get('category')}")
            print(f"  type: {first_item.get('type')}")
            print(f"  piiData count: {len(first_item.get('piiData', []))}")
            if first_item.get('piiData'):
                first_field = first_item['piiData'][0]
                print(f"  first field: {first_field.get('name')} = {first_field.get('value', '')[:30]}")
        
        return JSONResponse(
            status_code=200,
            content={"success": True, "data": transformed_items}
        )
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting all PII data: {e}")
        print(f"Error getting all PII data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.get("/{item_id}", response_model=Dict[str, Any])
@timing_decorator
async def get_pii_item(
    request: Request,
    item_id: str,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Get a specific PII data item by ID.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Getting PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        
        # Get user ID from the token
        user_id = user_info.get('sub').split(':')[-1]
        
        # Get the item
        success, item = db_handler.get_item_by_id(item_id)
        
        if not success:
            logger.error(f"Database error or item not found: {item}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Item not found"
            )
        
        # Decrypt the item
        success, decrypted_item = db_handler.decrypt_item(item)
        if not success:
            logger.error(f"Failed to decrypt item: {item_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Decryption error"
            )
        
        # Format for React UI (similar to get_all_pii_data)
        try:
            # Parse PII data from string to structured format
            pii_data = decrypted_item.get('PII', '[]')
            
            # Check for encrypted PII data
            if isinstance(pii_data, str) and pii_data.startswith('Z0FB'):
                try:
                    print(f"Detected encrypted PII data in Z0FB format for item {item_id}, attempting specialized decryption")
                    from api.encryption import get_kms_handler
                    handler = get_kms_handler()
                    if handler and hasattr(handler, 'decrypt_pii_data'):
                        decrypted_data = handler.decrypt_pii_data(pii_data)
                        
                        if decrypted_data:
                            print(f"Successfully decrypted PII data directly in single item controller")
                            pii_data = decrypted_data
                            print(f"Decrypted data: {pii_data[:50]}...")
                        else:
                            print("decrypt_pii_data returned None")
                    else:
                        print("KMS handler not available or missing decrypt_pii_data method")
                except Exception as decrypt_error:
                    print(f"Error decrypting PII data in single item: {decrypt_error}")
            
            # Continue with normal processing
            if isinstance(pii_data, str):
                # Try JSON first
                import json
                try:
                    pii_fields = json.loads(pii_data)
                    print(f"Successfully parsed PII JSON data for item {item_id}")
                    
                    # Handle different data shapes
                    if not isinstance(pii_fields, list):
                        if isinstance(pii_fields, dict):
                            # Convert to list format
                            pii_fields = [{"Item Name": k, "Data": v} for k, v in pii_fields.items()]
                        else:
                            pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                except json.JSONDecodeError:
                    # Fall back to ast
                    import ast
                    try:
                        pii_fields = ast.literal_eval(pii_data)
                        if not isinstance(pii_fields, list):
                            pii_fields = [{"Item Name": "Data", "Data": pii_data}]
                    except (ValueError, SyntaxError):
                        pii_fields = [{"Item Name": "Data", "Data": pii_data}]
            else:
                pii_fields = pii_data
            
            # Determine security level based on data type
            security_level = "high"  # Default for financial, medical
            if decrypted_item.get('Category') == "Personal":
                security_level = "medium"
            elif "password" in decrypted_item.get('Type', '').lower() or "account" in decrypted_item.get('Type', '').lower():
                security_level = "high"
            
            # Get metadata
            created_at = decrypted_item.get('created_at', '')
            updated_at = decrypted_item.get('updated_at', '')
            
            # Calculate "last updated" in human-readable format
            last_updated = "just now"
            if updated_at or created_at:
                from datetime import datetime
                import pytz
                
                # Use updated_at if available, otherwise created_at
                timestamp_str = updated_at if updated_at else created_at
                
                try:
                    # Parse ISO format
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    timestamp = timestamp.replace(tzinfo=pytz.UTC)
                    
                    # Calculate time difference
                    now = datetime.now(pytz.UTC)
                    diff = now - timestamp
                    
                    if diff.days > 30:
                        months = diff.days // 30
                        last_updated = f"{months} month{'s' if months > 1 else ''} ago"
                    elif diff.days > 0:
                        last_updated = f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
                    elif diff.seconds // 3600 > 0:
                        hours = diff.seconds // 3600
                        last_updated = f"{hours} hour{'s' if hours > 1 else ''} ago"
                    else:
                        minutes = (diff.seconds // 60) % 60
                        last_updated = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                except (ValueError, AttributeError):
                    last_updated = "unknown"
            
            # Create UI-friendly format
            ui_item = {
                "id": decrypted_item.get('_id'),
                "category": decrypted_item.get('Category'),
                "type": decrypted_item.get('Type'),
                "securityLevel": security_level,
                "lastUpdated": last_updated,
                "piiData": [
                    {"name": field.get("Item Name", ""), "value": field.get("Data", "")}
                    for field in pii_fields
                ],
                "createdAt": created_at,
                "updatedAt": updated_at,
                "createdBy": decrypted_item.get('created_by', user_id),
                "accessCount": decrypted_item.get('access_count', 0)
            }
            
            # Update access count if the method exists
            if hasattr(db_handler, 'increment_access_count'):
                db_handler.increment_access_count(item_id, user_id)
            
            # Final processing for JSON fields
            for field in ui_item.get('piiData', []):
                if isinstance(field.get('value'), str) and (field.get('value').startswith('{') or field.get('value').startswith('[')):
                    try:
                        import json
                        json_value = json.loads(field['value'])
                        # Format JSON for better readability in the UI
                        field['value'] = json.dumps(json_value, indent=2)
                        field['isJson'] = True
                    except:
                        # Not valid JSON, keep as is
                        pass
            
            # If piiData is empty and we have raw PII, try one more time
            if (not ui_item.get('piiData') or len(ui_item.get('piiData', [])) == 0) and decrypted_item.get('PII'):
                pii_raw = decrypted_item.get('PII')
                print(f"PII data fields are empty, making one last attempt to parse raw PII: {pii_raw[:50]}...")
                try:
                    import json
                    if isinstance(pii_raw, str):
                        parsed_data = json.loads(pii_raw)
                        if isinstance(parsed_data, list):
                            ui_item['piiData'] = [{"name": "Item " + str(i+1), "value": json.dumps(item, indent=2)} for i, item in enumerate(parsed_data)]
                        elif isinstance(parsed_data, dict):
                            ui_item['piiData'] = [{"name": k, "value": json.dumps(v, indent=2)} for k, v in parsed_data.items()]
                        else:
                            ui_item['piiData'] = [{"name": "Raw Data", "value": pii_raw}]
                        
                        # Mark JSON fields
                        for field in ui_item.get('piiData', []):
                            try:
                                json.loads(field['value'])
                                field['isJson'] = True
                            except:
                                pass
                                
                        print(f"Final piiData items: {len(ui_item.get('piiData', []))}")
                except Exception as parse_error:
                    print(f"Final parsing attempt failed: {parse_error}")
            
            # Ensure proper formatting for piiData 
            if 'piiData' not in ui_item or ui_item['piiData'] is None:
                ui_item['piiData'] = []
            elif not isinstance(ui_item['piiData'], list):
                # Convert non-list piiData to list format
                if isinstance(ui_item['piiData'], str):
                    try:
                        # Try to parse as JSON
                        import json
                        parsed = json.loads(ui_item['piiData'])
                        if isinstance(parsed, list):
                            ui_item['piiData'] = parsed
                        elif isinstance(parsed, dict):
                            ui_item['piiData'] = [{"name": k, "value": v} for k, v in parsed.items()]
                        else:
                            ui_item['piiData'] = [{"name": "Data", "value": ui_item['piiData']}]
                    except:
                        ui_item['piiData'] = [{"name": "Data", "value": ui_item['piiData']}]
                else:
                    ui_item['piiData'] = [{"name": "Data", "value": str(ui_item['piiData'])}]

            # Ensure each piiData item has name and value
            for i, field in enumerate(ui_item['piiData']):
                if not isinstance(field, dict):
                    ui_item['piiData'][i] = {"name": f"Item {i+1}", "value": str(field)}
                elif 'name' not in field:
                    field['name'] = f"Item {i+1}"
                elif 'value' not in field:
                    field['value'] = ""
            
            # Print what we're returning
            print(f"Returning item with id: {ui_item.get('id')}")
            print(f"piiData count: {len(ui_item.get('piiData', []))}")
            if ui_item.get('piiData'):
                for i, field in enumerate(ui_item['piiData'][:3]):  # Show up to first 3 fields
                    print(f"  field {i+1}: {field.get('name')} = {field.get('value', '')[:30]}")
                if len(ui_item['piiData']) > 3:
                    print(f"  ... and {len(ui_item['piiData']) - 3} more fields")
            
            # Return formatted response
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=200,
                content={"success": True, "data": ui_item}
            )
            
        except Exception as e:
            logger.error(f"Error transforming item {item_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Error transforming item data"
            )
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error getting PII item {item_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.post("/", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any])
@timing_decorator
async def create_pii_item(
    request: Request,
    item_data: PiiItemCreate,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Create a new PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Creating new PII item for user: {user_info.get('sub')} from {client_ip}")
        
        # Get user ID from the token
        user_id = user_info.get('sub').split(':')[-1]
        
        # Convert to database format
        from api.data.models import PIIItemCreate as DbPiiItemCreate
        
        # Convert the PII data to a string
        import json
        pii_data_str = json.dumps([
            {"Item Name": field.get("name", ""), "Data": field.get("value", "")}
            for field in item_data.piiData
        ])
        
        # Create a database PIIItemCreate object
        db_item = DbPiiItemCreate(
            category=item_data.category,
            type=item_data.type,
            pii=pii_data_str
        )
        
        # Create the item in the database
        success, result = db_handler.create_item(db_item, user_id, "api")
        
        if success:
            item_id = result.get("_id")
        
        if not success:
            logger.error(f"Database error creating item: {item_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Error creating item"
            )
        
        # Return the created item ID
        return {"id": item_id, "message": "Item created successfully"}
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error creating PII item: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.put("/{item_id}", response_model=Dict[str, Any])
async def update_pii_item(
    request: Request,
    item_id: str,
    item_update: PiiItemUpdate,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Update an existing PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Updating PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        
        # Get user ID from the token
        user_id = user_info.get('sub').split(':')[-1]
        
        # Get the existing item first
        success, existing_item = db_handler.get_item_by_id(item_id)
        
        if not success:
            logger.error(f"Item not found or database error: {existing_item}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Item not found"
            )
        
        # Decrypt the item to update
        success, decrypted_item = db_handler.decrypt_item(existing_item)
        if not success:
            logger.error(f"Failed to decrypt item: {item_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Decryption error"
            )
        
        # Create the update object
        from api.data.models import PIIItemUpdate as DbPiiItemUpdate
        
        # Convert the PII data to a string if provided
        pii_data_str = None
        if item_update.piiData is not None:
            import json
            pii_data_str = json.dumps([
                {"Item Name": field.get("name", ""), "Data": field.get("value", "")}
                for field in item_update.piiData
            ])
        
        # Create database update object
        db_update = DbPiiItemUpdate(
            id=item_id,
            category=item_update.category,
            type=item_update.type,
            pii=pii_data_str
        )
        
        # Update the item
        success, result = db_handler.update_item(db_update, user_id, "api")
        
        if not success:
            logger.error(f"Database error updating item: {result}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                    detail="Error updating item"
                )
        
        # Return success message
        return {"id": item_id, "message": "Item updated successfully"}
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error updating PII item {item_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )

@router.delete("/{item_id}", response_model=Dict[str, str])
async def delete_pii_item(
    request: Request,
    item_id: str,
    user_info: Dict[str, Any] = Depends(auth_required)
):
    """
    Delete a PII data item.
    """
    try:
        # Get client IP for audit logging
        client_ip = request.client.host if request.client else "unknown"
        
        # Log the request
        logger.info(f"Deleting PII item {item_id} for user: {user_info.get('sub')} from {client_ip}")
        
        # Get user ID from the token
        user_id = user_info.get('sub').split(':')[-1]
        
        # Create delete item object
        from api.data.models import PIIItemDelete
        delete_item = PIIItemDelete(id=item_id)
        
        # Delete the item
        success, result = db_handler.delete_item(delete_item, user_id, "api")
        
        if not success:
            logger.error(f"Database error deleting item: {result}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Error deleting item"
            )
        
        # Return success message
        return {"message": "Item deleted successfully"}
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log and convert other exceptions to HTTP exceptions
        logger.error(f"Error deleting PII item {item_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error"
        )