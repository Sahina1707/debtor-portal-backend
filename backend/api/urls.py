"""
API URL Configuration
"""
from django.urls import path
from . import views

urlpatterns = [
    # Admin endpoints
    path('admin/login/', views.admin_login, name='admin_login'),
    path('admin/verify-otp/', views.verify_admin_otp, name='verify_admin_otp'),
    path('admin/upload/', views.upload_file, name='upload_file'),
    path('admin/debtors/', views.get_all_debtors, name='get_all_debtors'),
    path('admin/debtor/<str:account_number>/', views.delete_debtor, name='delete_debtor'),
    path('admin/notifications/', views.get_notifications, name='get_notifications'),
    path('admin/notifications/<str:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
    path('admin/notifications/read-all/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('admin/qr-code/', views.upload_qr_code, name='upload_qr_code'),
    path('admin/qr-code/delete/', views.delete_qr_code, name='delete_qr_code'),
    path('admin/upload-history/', views.get_upload_history, name='get_upload_history'),
    path('admin/upload-history/<str:upload_id>/download/', views.download_upload_file, name='download_upload_file'),
    path('admin/images/upload/', views.upload_debtor_images, name='upload_debtor_images'),
    path('admin/images/batch/', views.get_debtor_images_batch, name='get_debtor_images_batch'),
    path('admin/images/<str:account_number>/', views.get_debtor_image, name='get_debtor_image'),
    path('admin/images/<str:account_number>/file/', views.serve_debtor_image, name='serve_debtor_image'),
    path('admin/images/<str:account_number>/delete/', views.delete_debtor_image, name='delete_debtor_image'),

    # Super Admin endpoints
    path('superadmin/settings/', views.get_system_settings, name='get_system_settings'),
    path('superadmin/settings/update/', views.update_system_settings, name='update_system_settings'),

    # Public endpoints
    path('settings/qr-code/', views.get_qr_code, name='get_qr_code'),
    path('settings/system/', views.get_system_settings, name='get_public_system_settings'),

    # Debtor portal endpoints
    path('debtor/login/', views.debtor_login, name='debtor_login'),
    path('debtor/verify-otp/', views.verify_otp, name='verify_otp'),
    path('debtor/pdpa-consent/', views.save_pdpa_consent, name='save_pdpa_consent'),
    path('debtor/payment-consent/', views.save_payment_consent, name='save_payment_consent'),
    path('debtor/accounts/', views.get_all_debtor_accounts, name='get_all_debtor_accounts'),
    path('debtor/account/<str:account_number>/', views.get_debtor_account, name='get_debtor_account'),
    path('debtor/account/<str:account_number>/contact/', views.update_debtor_contact, name='update_debtor_contact'),
    path('debtor/payment-interest/', views.send_payment_interest_notification, name='send_payment_interest_notification'),
    path('debtor/not-ready-to-pay/', views.send_not_ready_to_pay_notification, name='send_not_ready_to_pay_notification'),
    path('debtor/image/<str:account_number>/', views.get_debtor_image, name='get_debtor_image_public'),

    # Health check
    path('health/', views.health_check, name='health_check'),

    # Test endpoints (for debugging)
    path('test/email/', views.test_email, name='test_email'),

    # Receipt endpoints (admin only)
    path('admin/receipts/<str:filename>/', views.serve_payment_receipt, name='serve_payment_receipt'),
]



