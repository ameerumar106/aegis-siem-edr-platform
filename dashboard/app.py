from flask import Flask
from dashboard.routes import main

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "siem-dashboard-secret"
    app.register_blueprint(main)
    return app

# Add this at the very bottom so it can run directly as a module!
if __name__ == "__main__":
    app = create_app()
    print("\n" + "="*60)
    print(" [+] INITIALIZING SIEM SECURITY DASHBOARD FRONTEND")
    print(" [+] Target Portal: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)