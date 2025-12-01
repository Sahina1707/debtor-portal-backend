"""
MongoDB Database Connection
"""
from pymongo import MongoClient, ASCENDING, DESCENDING, TEXT
from django.conf import settings
import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
MONGODB_NAME = os.getenv('MONGODB_NAME', 'debtor_portal')

client = None
db = None


def get_database():
    """Get MongoDB database connection"""
    global client, db

    if client is None:
        client = MongoClient(MONGODB_URI)
        db = client[MONGODB_NAME]

    return db


def get_debtors_collection():
    """Get debtors collection"""
    database = get_database()
    return database['debtors']


def get_admins_collection():
    """Get admins collection"""
    database = get_database()
    return database['admins']


def get_notifications_collection():
    """Get notifications collection"""
    database = get_database()
    return database['notifications']


def get_settings_collection():
    """Get settings collection for app configuration"""
    database = get_database()
    return database['settings']


def get_upload_history_collection():
    """Get upload history collection for tracking file uploads"""
    database = get_database()
    return database['upload_history']


def get_system_settings_collection():
    """Get system settings collection for super admin configuration"""
    database = get_database()
    return database['system_settings']


def get_debtor_images_collection():
    """Get debtor images collection for storing account images"""
    database = get_database()
    return database['debtor_images']


def init_admin_user():
    """Initialize default admin user if not exists"""
    admins = get_admins_collection()

    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')

    existing_admin = admins.find_one({'username': admin_username})

    if not existing_admin:
        import bcrypt
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

        admins.insert_one({
            'username': admin_username,
            'password': hashed_password.decode('utf-8'),
            'role': 'admin'
        })
        print(f"Admin user '{admin_username}' created successfully!")
    else:
        print(f"Admin user '{admin_username}' already exists.")


def init_super_admin():
    """Initialize default super admin user if not exists"""
    admins = get_admins_collection()

    super_admin_username = os.getenv('SUPER_ADMIN_USERNAME', 'superadmin')
    super_admin_password = os.getenv('SUPER_ADMIN_PASSWORD', 'superadmin123')

    existing_super_admin = admins.find_one({'username': super_admin_username})

    if not existing_super_admin:
        import bcrypt
        hashed_password = bcrypt.hashpw(super_admin_password.encode('utf-8'), bcrypt.gensalt())

        admins.insert_one({
            'username': super_admin_username,
            'password': hashed_password.decode('utf-8'),
            'role': 'super_admin'
        })
        print(f"Super admin user '{super_admin_username}' created successfully!")
    else:
        print(f"Super admin user '{super_admin_username}' already exists.")


def init_system_settings():
    """Initialize default system settings if not exists, or update missing fields"""
    system_settings = get_system_settings_collection()

    existing_settings = system_settings.find_one({'key': 'app_settings'})

    default_settings = {
        'key': 'app_settings',
        # Admin Portal Tab Settings
        'admin_tabs': {
            'upload_data': True,
            'view_accounts': True,
            'debtor_requests': True,
            'upload_history': True,
            'settings': True,
        },
        # Image Upload Feature
        'enable_image_upload': False,
        # Debtor Portal Feature Settings
        'debtor_features': {
            'make_payment': True,
            'not_ready_to_pay': True,
            'line_qr_support': True,
            'update_contact': True,
        },
        # Bank Account Details for Payment (Thai Bank Transfer)
        'bank_account': {
            'bank_name': '',
            'account_name': '',
            'account_number': '',
            'promptpay_id': '',
        },
        'notification_email': '',
        'updated_at': None
    }

    if not existing_settings:
        system_settings.insert_one(default_settings)
        print("Default system settings initialized!")
    else:
        # Check for missing fields and add them
        updates = {}
        if 'bank_account' not in existing_settings:
            updates['bank_account'] = default_settings['bank_account']
            print("Adding missing bank_account field to settings")
        if 'notification_email' not in existing_settings:
            updates['notification_email'] = default_settings['notification_email']
            print("Adding missing notification_email field to settings")

        if updates:
            system_settings.update_one(
                {'key': 'app_settings'},
                {'$set': updates}
            )
            print(f"Updated settings with missing fields: {list(updates.keys())}")
        else:
            print("System settings already exist and are complete.")


def create_indexes():
    """Create MongoDB indexes for optimal query performance"""
    try:
        # Debtors collection indexes
        debtors = get_debtors_collection()
        debtors.create_index([('account_number', ASCENDING)], unique=True, background=True)
        debtors.create_index([('national_id', ASCENDING)], background=True)
        debtors.create_index([('case_id', ASCENDING)], background=True)
        debtors.create_index([('upload_id', ASCENDING)], background=True)
        debtors.create_index([('created_at', DESCENDING)], background=True)
        debtors.create_index([('updated_at', DESCENDING)], background=True)
        # Text index for search
        debtors.create_index([
            ('name', TEXT),
            ('account_number', TEXT),
            ('national_id', TEXT),
            ('case_id', TEXT),
            ('email', TEXT)
        ], background=True, name='debtors_text_search')

        # Notifications collection indexes
        notifications = get_notifications_collection()
        notifications.create_index([('created_at', DESCENDING)], background=True)
        notifications.create_index([('read', ASCENDING)], background=True)
        notifications.create_index([('type', ASCENDING)], background=True)

        # Upload history collection indexes
        upload_history = get_upload_history_collection()
        # Use sparse=True to ignore documents with null upload_id
        upload_history.create_index([('upload_id', ASCENDING)], unique=True, sparse=True, background=True)
        upload_history.create_index([('uploaded_at', DESCENDING)], background=True)

        # Admins collection indexes
        admins = get_admins_collection()
        admins.create_index([('username', ASCENDING)], unique=True, background=True)

        print("MongoDB indexes created successfully!")
    except Exception as e:
        print(f"Error creating indexes (may already exist): {e}")


# Initialize admin user and indexes when module loads
try:
    init_admin_user()
    init_super_admin()
    init_system_settings()
    create_indexes()
except Exception as e:
    print(f"Could not initialize: {e}")
