##########################################
# Main Interface of the 1st Delivery for the
# Cryptography & Computer Security Subject
#
# Authors:
#   - Aarón Espasandín Geselmann
#   - Alejandra Galán Arróspide
##########################################
from packages.AppAccess import AppAccess

if __name__ == "__main__":
    # App Access receives the path to the JSON file that
    # acts as a database for the application
    app_access = AppAccess("database.json")

    # Uncomment the following line to empty the database
    # app_access.initialize_json()

    # Execute the CLI interface
    app_access.run()
