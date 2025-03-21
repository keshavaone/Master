"""
Compatibility module for ensuring backward compatibility with code that
expects a global Agent instance.

This module provides functions and tools to maintain compatibility with
existing code while transitioning to the new per-user Agent model.
"""

import logging
import API.CONSTANTS as CONSTANTS
from typing import Optional
from functools import wraps

# Configure logging
logger = logging.getLogger("api.compat")

# Reference to the global agent from main.py
global_agent = None

def initialize_global_agent_reference(agent_ref):
    """
    Initialize the global agent reference.
    
    This function should be called during application startup to set the
    reference to the global agent from main.py.
    
    Args:
        agent_ref: Reference to the global agent
    """
    global global_agent
    global_agent = agent_ref
    logger.info("Global agent reference initialized")

def get_agent() -> Optional:
    """
    Get the global agent for backward compatibility.
    
    Returns:
        The global agent or None if not initialized
    """
    if global_agent is None:
        logger.warning("Attempted to access global agent but it is not initialized")
    return global_agent

def with_agent(f):
    """
    Decorator for functions that require an agent.
    
    This decorator ensures that functions that expect an agent parameter
    will receive one, even if not explicitly provided.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'agent' not in kwargs:
            kwargs['agent'] = get_agent()
        return f(*args, **kwargs)
    return wrapper

def create_default_agent():
    """
    Create a default agent for testing and development.
    
    This function should only be used in development or testing environments.
    
    Returns:
        A new Agent instance
    """
    from API.Backend import Agent
    
    logger.warning("Creating default agent - should only be used in development!")
    agent = Agent(s3=CONSTANTS.AWS_S3, file_name=CONSTANTS.AWS_FILE)
    
    # Set a default auth context
    if hasattr(agent, 'set_auth_context'):
        agent.set_auth_context(
            user_id="default-dev-user",
            auth_type="development",
            client_ip=None
        )
    elif hasattr(agent, 'auth_context'):
        agent.auth_context = {
            "user_id": "default-dev-user",
            "auth_type": "development"
        }
        
    return agent