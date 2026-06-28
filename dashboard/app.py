import logging
from flask import Flask
from dashboard.routes import main

# Configure logging for the Flask app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "siem-dashboard-secret"
    app.register_blueprint(main)
    return app

# Add this at the very bottom so it can run directly as a module!
if __name__ == "__main__":
    app = create_app()
    logger.info("\n" + "="*60)
    logger.info(" [+] INITIALIZING SIEM SECURITY DASHBOARD FRONTEND")
    logger.info(" [+] Target Portal: http://127.0.0.1:5000")
    logger.info("="*60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)