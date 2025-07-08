import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Startup script for Azure App Service"""
    try:
        logger.info("Starting UltimateScanner application...")
        
        # Set environment variables
        port = int(os.environ.get('PORT', 8000))
        logger.info(f"Using port: {port}")
        
        # Import and run the Flask app
        from app import app
        logger.info("Flask app imported successfully")
        
        # Run the application
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False,
            threaded=True
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
