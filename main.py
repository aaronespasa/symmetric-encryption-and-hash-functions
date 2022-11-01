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
    app_access = AppAccess("database.json")
    # app_access.initialize_json()
    app_access.run()
