"""
Enhanced delete handler for the GUARD application.

This module provides a standardized approach to deleting data items
with robust error handling, authentication validation, and proper
user feedback.
"""

import logging
import traceback
import json
from typing import Dict, Any, Optional, Callable
from PyQt5.QtWidgets import QMessageBox, QApplication, QProgressDialog
from PyQt5.QtCore import Qt

logger = logging.getLogger('delete_handler')


class DeleteHandler:
    """
    Enhanced delete handler with robust error handling and multi-approach deletion.
    """

    @staticmethod
    def delete_item(parent, item_data: Dict[str, Any],
                    agent=None, auth_service=None, auth_manager=None,
                    api_client=None, on_success=None,
                    log_callback: Optional[Callable] = None) -> bool:
        """
        Delete an item with comprehensive error handling and multiple fallback approaches.

        Args:
            parent: Parent widget for dialogs
            item_data: Dictionary containing the item data (must include '_id')
            agent: Agent instance for direct API access
            auth_service: Authentication service
            auth_manager: Authentication manager
            api_client: API client instance
            on_success: Callback function to execute after successful deletion
            log_callback: Callback function for logging

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        # Validate item data
        if not item_data or not isinstance(item_data, dict):
            QMessageBox.warning(parent, "Delete Error", "Invalid item data")
            return False

        # Ensure we have an ID to delete
        item_id = item_data.get('_id')
        if not item_id:
            QMessageBox.warning(parent, "Delete Error",
                                "Cannot delete: Missing ID in item data")
            return False

        # Log deletion attempt
        if log_callback:
            log_callback(f"Attempting to delete item with ID: {item_id}")
        logger.info(f"Attempting to delete item: {item_id}")

        # Confirm deletion with user
        category = item_data.get('Category', 'Unknown')
        type_ = item_data.get('Type', 'Unknown')
        message = (
            f"Are you sure you want to delete this item?\n\n"
            f"ID: {item_id}\n"
            f"Category: {category}\n"
            f"Type: {type_}\n\n"
            f"This action cannot be undone."
        )

        reply = QMessageBox.question(
            parent, "Confirm Deletion", message,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            return False

        # Show progress dialog
        progress = QProgressDialog(
            "Deleting item...", "Cancel", 0, 100, parent)
        progress.setWindowTitle("Delete Item")
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(10)
        progress.show()
        QApplication.processEvents()

        try:
            # Try each deletion method in order of preference
            success, error_message = False, ""

            # Method 1: Use API client if available
            if api_client:
                if log_callback:
                    log_callback("Using API client for deletion")
                logger.info(f"Attempting deletion with API client: {item_id}")
                progress.setValue(30)
                QApplication.processEvents()

                try:
                    success, result = api_client.sync_delete_pii_item(
                        item_id=item_id,
                        category=category,
                        type_=type_
                    )

                    if success:
                        if log_callback:
                            log_callback(
                                f"API client: Item {item_id} deleted successfully")
                        logger.info(
                            f"Successfully deleted item {item_id} with API client")
                    else:
                        error_message = f"API client error: {result}"
                        if log_callback:
                            log_callback(
                                f"API client deletion failed: {error_message}")
                        logger.warning(
                            f"API client deletion failed: {error_message}")
                        # Continue to next method
                except Exception as e:
                    error_message = f"API client exception: {str(e)}"
                    if log_callback:
                        log_callback(f"API client error: {error_message}")
                    logger.error(f"API client error: {traceback.format_exc()}")
                    # Continue to next method

            # Method 2: Use agent directly
            if not success and agent:
                if log_callback:
                    log_callback("Using direct agent for deletion")
                logger.info(
                    f"Attempting deletion with direct agent: {item_id}")
                progress.setValue(40)
                QApplication.processEvents()

                try:
                    # Ensure data has everything needed for deletion
                    delete_data = {
                        "_id": item_id,
                        "Category": category,
                        "Type": type_
                    }

                    result = agent.delete_one_data(delete_data)

                    # Handle various result types
                    if result is True:
                        success = True
                        if log_callback:
                            log_callback(
                                f"Agent: Item {item_id} deleted successfully")
                        logger.info(
                            f"Successfully deleted item {item_id} with agent")
                    elif isinstance(result, Exception):
                        error_message = f"Agent error: {str(result)}"
                        if log_callback:
                            log_callback(
                                f"Agent deletion failed: {error_message}")
                        logger.warning(
                            f"Agent deletion failed: {error_message}")
                        # Continue to next method
                    elif isinstance(result, dict) and 'error' in result:
                        error_message = f"Agent error: {result['error']}"
                        if log_callback:
                            log_callback(
                                f"Agent deletion failed: {error_message}")
                        logger.warning(
                            f"Agent deletion failed: {error_message}")
                        # Continue to next method
                    else:
                        # Assume success for other result types
                        success = True
                        if log_callback:
                            log_callback(
                                f"Agent: Item {item_id} deleted successfully")
                        logger.info(
                            f"Successfully deleted item {item_id} with agent (result: {result})")
                except Exception as e:
                    error_message = f"Agent exception: {str(e)}"
                    if log_callback:
                        log_callback(f"Agent error: {error_message}")
                    logger.error(f"Agent error: {traceback.format_exc()}")
                    # Continue to next method

            # Method 3: Use auth service
            if not success and auth_service:
                if log_callback:
                    log_callback("Using auth service for deletion")
                logger.info(
                    f"Attempting deletion with auth service: {item_id}")
                progress.setValue(50)
                QApplication.processEvents()

                try:
                    # Prepare delete data
                    delete_data = {
                        "_id": item_id,
                        "Category": category,
                        "Type": type_
                    }

                    # Check if auth service has synchronous method
                    if hasattr(auth_service, 'make_synchronous_request'):
                        success, result = auth_service.make_synchronous_request(
                            method="DELETE",
                            endpoint="pii",
                            data=delete_data
                        )
                    elif hasattr(auth_service, 'make_authenticated_request'):
                        # Handle async method if necessary
                        import inspect
                        if inspect.iscoroutinefunction(auth_service.make_authenticated_request):
                            import asyncio
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                success, result = loop.run_until_complete(
                                    auth_service.make_authenticated_request(
                                        method="DELETE",
                                        endpoint="pii",
                                        data=delete_data
                                    )
                                )
                            finally:
                                loop.close()
                        else:
                            success, result = auth_service.make_authenticated_request(
                                method="DELETE",
                                endpoint="pii",
                                data=delete_data
                            )
                    else:
                        error_message = "Auth service has no suitable request method"
                        if log_callback:
                            log_callback(error_message)
                        logger.warning(error_message)
                        # Continue to next method

                    if success:
                        if log_callback:
                            log_callback(
                                f"Auth service: Item {item_id} deleted successfully")
                        logger.info(
                            f"Successfully deleted item {item_id} with auth service")
                    else:
                        result_str = str(result)
                        if isinstance(result, dict):
                            result_str = json.dumps(result)
                        error_message = f"Auth service error: {result_str}"
                        if log_callback:
                            log_callback(
                                f"Auth service deletion failed: {error_message}")
                        logger.warning(
                            f"Auth service deletion failed: {error_message}")
                        # Continue to next method
                except Exception as e:
                    error_message = f"Auth service exception: {str(e)}"
                    if log_callback:
                        log_callback(f"Auth service error: {error_message}")
                    logger.error(
                        f"Auth service error: {traceback.format_exc()}")
                    # Continue to next method

            # Method 4: Use auth manager
            if not success and auth_manager and hasattr(auth_manager, 'token') and auth_manager.token:
                if log_callback:
                    log_callback("Using auth manager for deletion")
                logger.info(
                    f"Attempting deletion with auth manager: {item_id}")
                progress.setValue(60)
                QApplication.processEvents()

                try:
                    # Prepare delete data
                    delete_data = {
                        "_id": item_id,
                        "Category": category,
                        "Type": type_
                    }

                    # Make authenticated request
                    success, result = auth_manager.make_authenticated_request(
                        method="DELETE",
                        endpoint="pii",
                        data=delete_data
                    )

                    if success:
                        if log_callback:
                            log_callback(
                                f"Auth manager: Item {item_id} deleted successfully")
                        logger.info(
                            f"Successfully deleted item {item_id} with auth manager")
                    else:
                        result_str = str(result)
                        if isinstance(result, dict):
                            result_str = json.dumps(result)
                        error_message = f"Auth manager error: {result_str}"
                        if log_callback:
                            log_callback(
                                f"Auth manager deletion failed: {error_message}")
                        logger.warning(
                            f"Auth manager deletion failed: {error_message}")
                except Exception as e:
                    error_message = f"Auth manager exception: {str(e)}"
                    if log_callback:
                        log_callback(f"Auth manager error: {error_message}")
                    logger.error(
                        f"Auth manager error: {traceback.format_exc()}")

            # Finalize based on deletion success
            progress.setValue(80)
            QApplication.processEvents()

            if success:
                progress.setValue(100)
                QApplication.processEvents()

                QMessageBox.information(
                    parent,
                    "Success",
                    "Item deleted successfully"
                )

                # Call success callback if provided
                if on_success:
                    on_success()

                return True
            else:
                # All methods failed
                progress.close()

                error_dialog = QMessageBox(parent)
                error_dialog.setWindowTitle("Delete Error")
                error_dialog.setIcon(QMessageBox.Critical)

                if error_message:
                    error_dialog.setText(
                        f"Failed to delete item: {error_message}")
                else:
                    error_dialog.setText(
                        "Failed to delete item: No deletion method available")

                error_dialog.setInformativeText(
                    "Please check your connection and try again. If the problem persists, "
                    "contact your system administrator."
                )

                error_dialog.setStandardButtons(QMessageBox.Ok)
                error_dialog.exec_()

                return False
        except Exception as e:
            # Handle unexpected errors
            progress.close()

            logger.error(
                f"Unexpected error during deletion: {traceback.format_exc()}")
            if log_callback:
                log_callback(f"Unexpected error during deletion: {str(e)}")

            QMessageBox.critical(
                parent,
                "Critical Error",
                f"An unexpected error occurred while deleting the item:\n\n{str(e)}"
            )

            return False
        finally:
            # Ensure progress dialog is closed
            try:
                progress.close()
            except:
                pass
