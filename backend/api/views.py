"""
API Views for Debtor Portal
"""
import json
import random
import string
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import BytesIO

import bcrypt
import jwt
import pandas as pd
import numpy as np
from bson import ObjectId
from django.conf import settings
from django.core.mail import send_mail
from django.http import JsonResponse, FileResponse, Http404, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

# PDF QR Code Extraction imports (optional - graceful fallback if not installed)
PDF_PROCESSING_AVAILABLE = False
OCR_AVAILABLE = False

try:
    import fitz  # PyMuPDF
    import cv2
    from PIL import Image
    from pyzbar.pyzbar import decode as decode_qr
    PDF_PROCESSING_AVAILABLE = True

    # Tesseract OCR is optional - barcode extraction is primary method
    try:
        import pytesseract
        # Configure Tesseract path for Windows (adjust path as needed for deployment)
        import os
        if os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
            pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        OCR_AVAILABLE = True
        print("[OK] PDF processing available with OCR support")
    except ImportError:
        print("[OK] PDF processing available (OCR disabled - Tesseract not installed)")

except ImportError as e:
    print(f"Warning: PDF processing libraries not installed ({e}). PDF QR extraction disabled.")

# Bangkok timezone (UTC+7)
BANGKOK_TZ = timezone(timedelta(hours=7))

def format_thai_currency(amount):
    """Format amount in Thai Baht"""
    return f"฿{amount:,.2f}"

def get_bangkok_time():
    """Get current time in Bangkok timezone"""
    return datetime.now(BANGKOK_TZ).strftime('%Y-%m-%d %H:%M:%S')

# Email templates for both languages
EMAIL_TEMPLATES = {
    'en': {
        'otp_subject': 'Your OTP for Debtor Portal Login',
        'otp_body': """
Dear Customer,

Your One-Time Password (OTP) for logging into the Debtor Self-Service Portal is:

    {otp}

This OTP is valid for 5 minutes. Please do not share this code with anyone.

You have {account_count} account(s) linked to your National ID.

If you did not request this OTP, please ignore this email.

Best regards,
Collections Team
""",
        'payment_subject': 'Payment Notification - Account {account_number} - Transaction: {transaction_number}',
        'payment_body': """
PAYMENT NOTIFICATION
====================

A customer has submitted a payment through the Self-Service Portal.

CUSTOMER DETAILS
----------------
Account Number: {account_number}
Name: {name}
National ID: {national_id}
Phone: {phone}
Email: {email}

DEBT INFORMATION
----------------
Original Creditor: {original_creditor}
Debt Type: {debt_type}
Outstanding Balance: {outstanding_balance}
Loan Contract Date: {loan_contract_date}

PAYMENT DETAILS
---------------
Payment Type: {payment_type}
Payment Amount: {payment_amount}
Transaction Number: {transaction_number}

TIMESTAMP
---------
Date/Time: {timestamp} (Bangkok)

---
This is an automated notification from the Debtor Self-Service Portal.
Please verify the transaction and update the payment status.
""",
        'not_ready_subject': 'Need Support to Pay - Account {account_number}',
        'not_ready_body': """
NEED SUPPORT TO PAY NOTIFICATION
================================

A customer needs support to make a payment.

CUSTOMER DETAILS
----------------
Account Number: {account_number}
Name: {name}
National ID: {national_id}
Phone: {phone}
Email: {email}

DEBT INFORMATION
----------------
Original Creditor: {original_creditor}
Debt Type: {debt_type}
Outstanding Balance: {outstanding_balance}
Loan Contract Date: {loan_contract_date}

REASON FOR SUPPORT REQUEST
--------------------------
Reason: {reason}

Customer Notes:
{notes}

CONTACT PREFERENCES
-------------------
Preferred Date: {preferred_contact_date}
Preferred Time: {preferred_contact_time}
Preferred Contact Method: {preferred_contact_method}

TIMESTAMP
---------
Date/Time: {timestamp} (Bangkok)

---
This is an automated notification from the Debtor Self-Service Portal.
Please review this case and follow up with the customer as appropriate.
"""
    },
    'th': {
        'otp_subject': 'รหัส OTP สำหรับเข้าสู่ระบบพอร์ทัลลูกหนี้',
        'otp_body': """
เรียน ลูกค้า

รหัสผ่านครั้งเดียว (OTP) สำหรับเข้าสู่ระบบพอร์ทัลบริการตนเองสำหรับลูกหนี้ของคุณคือ:

    {otp}

รหัส OTP นี้ใช้ได้ภายใน 5 นาที กรุณาอย่าแชร์รหัสนี้กับผู้อื่น

คุณมี {account_count} บัญชีที่เชื่อมโยงกับเลขประจำตัวประชาชนของคุณ

หากคุณไม่ได้ขอรหัส OTP นี้ กรุณาเพิกเฉยอีเมลนี้

ด้วยความเคารพ
ทีมเรียกเก็บหนี้
""",
        'payment_subject': 'แจ้งเตือนการชำระเงิน - บัญชี {account_number} - ธุรกรรม: {transaction_number}',
        'payment_body': """
แจ้งเตือนการชำระเงิน
====================

ลูกค้าได้ส่งการชำระเงินผ่านพอร์ทัลบริการตนเอง

รายละเอียดลูกค้า
----------------
เลขที่บัญชี: {account_number}
ชื่อ: {name}
เลขประจำตัวประชาชน: {national_id}
โทรศัพท์: {phone}
อีเมล: {email}

ข้อมูลหนี้
----------------
เจ้าหนี้เดิม: {original_creditor}
ประเภทหนี้: {debt_type}
ยอดคงค้าง: {outstanding_balance}
วันที่ทำสัญญาเงินกู้: {loan_contract_date}

รายละเอียดการชำระเงิน
---------------
ประเภทการชำระ: {payment_type}
จำนวนเงินที่ชำระ: {payment_amount}
เลขที่ธุรกรรม: {transaction_number}

เวลา
---------
วันที่/เวลา: {timestamp} (กรุงเทพฯ)

---
นี่คือการแจ้งเตือนอัตโนมัติจากพอร์ทัลบริการตนเองสำหรับลูกหนี้
กรุณาตรวจสอบธุรกรรมและอัปเดตสถานะการชำระเงิน
""",
        'not_ready_subject': 'ต้องการความช่วยเหลือในการชำระ - บัญชี {account_number}',
        'not_ready_body': """
แจ้งเตือนต้องการความช่วยเหลือในการชำระเงิน
==========================================

ลูกค้าต้องการความช่วยเหลือในการชำระเงิน

รายละเอียดลูกค้า
----------------
เลขที่บัญชี: {account_number}
ชื่อ: {name}
เลขประจำตัวประชาชน: {national_id}
โทรศัพท์: {phone}
อีเมล: {email}

ข้อมูลหนี้
----------------
เจ้าหนี้เดิม: {original_creditor}
ประเภทหนี้: {debt_type}
ยอดคงค้าง: {outstanding_balance}
วันที่ทำสัญญาเงินกู้: {loan_contract_date}

เหตุผลที่ต้องการความช่วยเหลือ
----------------------------
เหตุผล: {reason}

หมายเหตุจากลูกค้า:
{notes}

ความต้องการในการติดต่อ
----------------------
วันที่ต้องการให้ติดต่อ: {preferred_contact_date}
เวลาที่ต้องการให้ติดต่อ: {preferred_contact_time}
ช่องทางการติดต่อที่ต้องการ: {preferred_contact_method}

เวลา
---------
วันที่/เวลา: {timestamp} (กรุงเทพฯ)

---
นี่คือการแจ้งเตือนอัตโนมัติจากพอร์ทัลบริการตนเองสำหรับลูกหนี้
กรุณาตรวจสอบกรณีนี้และติดตามลูกค้าตามความเหมาะสม
"""
    }
}

def get_email_template(template_key, language='en'):
    """Get email template in the specified language, fallback to English"""
    lang = language if language in EMAIL_TEMPLATES else 'en'
    return EMAIL_TEMPLATES[lang].get(template_key, EMAIL_TEMPLATES['en'].get(template_key, ''))

from .database import (
    get_debtors_collection,
    get_admins_collection,
    get_notifications_collection,
    get_settings_collection,
    get_upload_history_collection,
    get_system_settings_collection,
    get_debtor_images_collection
)
import base64

# File storage directories (file system based for scalability)
MEDIA_DIR = Path(settings.BASE_DIR).parent / 'media'
IMAGES_DIR = MEDIA_DIR / 'debtor_images'
UPLOADS_DIR = MEDIA_DIR / 'uploads'
RECEIPTS_DIR = MEDIA_DIR / 'payment_receipts'

# Create directories if they don't exist
IMAGES_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================
# PDF QR CODE EXTRACTION FUNCTIONS
# ============================================

def extract_ref1_from_barcode(barcode_data):
    """Extracts Ref1 number from barcode data string.
    Barcode format: |010556503082900 202111000201554 3820100052883 0
    The second number (15 digits) is the Ref1 (account number).
    First number is the biller ID, second is Ref1, third is Ref2.
    """
    if not barcode_data:
        return None

    try:
        print(f"Extracting Ref1 from barcode: {barcode_data}")
        # Remove leading pipe and split by space
        parts = barcode_data.replace('|', '').strip().split()

        # Collect all 15-digit numbers
        fifteen_digit_numbers = [part for part in parts if len(part) == 15 and part.isdigit()]

        # The second 15-digit number is Ref1 (index 1)
        if len(fifteen_digit_numbers) >= 2:
            ref1 = fifteen_digit_numbers[1]
            print(f"[OK] Ref1 extracted from barcode (2nd 15-digit): {ref1}")
            return ref1

        # Fallback: if only one 15-digit number, use it
        if len(fifteen_digit_numbers) == 1:
            ref1 = fifteen_digit_numbers[0]
            print(f"[OK] Ref1 extracted from barcode (only 15-digit): {ref1}")
            return ref1

        # Fallback: look for any number between 10-20 digits
        for part in parts:
            if 10 <= len(part) <= 20 and part.isdigit():
                print(f"[OK] Ref1 extracted from barcode (fallback): {part}")
                return part

        print("✗ Ref1 not found in barcode data")
        return None
    except Exception as e:
        print(f"Barcode parsing error: {e}")
        return None


def extract_ref1_from_image(img):
    """Extracts Ref1 number from OCR text (requires Tesseract)"""
    if not OCR_AVAILABLE:
        print("OCR not available - skipping image text extraction")
        return None

    try:
        # Use English only - Thai traineddata may not be installed
        text = pytesseract.image_to_string(img, lang="eng")
        print(f"OCR Text: {text[:500]}...")  # Debug - first 500 chars

        # Try different patterns for Ref1
        patterns = [
            r"\(Ref1\)[^\d]*(\d{10,20})",  # (Ref1) followed by digits - exact format in PDF
            r"Ref1[)\s]*(\d{10,20})",  # Ref1) or Ref1 followed by digits
            r"เลขท[ีi]่?บ[ัa]ญช[ีi][^\d]*(\d{10,20})",  # Thai: เลขที่บัญชี followed by digits
            r"Ref1[^\d]*(\d{6,20})",  # Ref1 followed by digits
            r"Ref\.?\s*1[^\d]*(\d{6,20})",  # Ref.1 or Ref 1
            r"Reference\s*1?[^\d]*(\d{6,20})",  # Reference or Reference1
            r"REF1[^\d]*(\d{6,20})",  # REF1 uppercase
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                ref1 = match.group(1)
                print(f"[OK] Ref1 extracted via OCR: {ref1}")
                return ref1

        # Fallback: Look for a 15-digit number (common Ref1 format)
        long_numbers = re.findall(r'\b(\d{15})\b', text)
        if long_numbers:
            ref1 = long_numbers[0]
            print(f"[OK] Ref1 extracted via OCR (fallback 15-digit): {ref1}")
            return ref1

        print("✗ Ref1 not found in OCR text")
        return None
    except Exception as e:
        print(f"OCR Error: {e}")
        return None


def process_pdf_for_qr(pdf_file):
    """
    Process a PDF file to extract QR codes and their associated Ref1 (account numbers).
    PDF Format: Each page has 2 identical sections (For Customer / For Bank).
    We process only the top section to avoid duplicates.
    Returns a list of tuples: [(account_number, qr_image_bytes), ...]
    """
    if not PDF_PROCESSING_AVAILABLE:
        return [], ["PDF processing libraries not installed"]

    results = []
    errors = []

    try:
        # Read PDF content
        pdf_content = pdf_file.read()
        doc = fitz.open(stream=pdf_content, filetype="pdf")

        print(f"Processing PDF with {len(doc)} pages")

        for page_no in range(len(doc)):
            page = doc[page_no]
            # Render page at 300 DPI for better OCR
            pix = page.get_pixmap(dpi=300)
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)

            h, w = img.size[1], img.size[0]

            # The PDF has 2 identical sections per page. Process only top half (For Customer)
            top_half = img.crop((0, 0, w, int(h * 0.50)))
            top_h = top_half.size[1]

            # QR/Barcode area: Bottom-left portion of the top half
            qr_crop = top_half.crop((0, int(top_h * 0.55), int(w * 0.60), top_h))

            # STEP 1: Detect barcode/QR code (primary method - no Tesseract needed)
            opencv_img = cv2.cvtColor(np.array(qr_crop), cv2.COLOR_RGB2BGR)
            qr_codes = decode_qr(opencv_img)

            qr_img = None
            barcode_data = None

            if qr_codes:
                qr = qr_codes[0]
                barcode_data = qr.data.decode('utf-8') if qr.data else None
                print(f"Barcode/QR detected in crop. Data: {barcode_data}")
                x, y, wbox, hbox = qr.rect
                # Add padding around barcode for better scanning
                padding = 20
                x1 = max(0, x - padding)
                y1 = max(0, y - padding)
                x2 = min(opencv_img.shape[1], x + wbox + padding)
                y2 = min(opencv_img.shape[0], y + hbox + padding)
                qr_img = opencv_img[y1:y2, x1:x2]
            else:
                # Try with the full top half if no barcode found in cropped area
                print("Barcode not found in crop, trying full top half...")
                opencv_full = cv2.cvtColor(np.array(top_half), cv2.COLOR_RGB2BGR)
                qr_codes = decode_qr(opencv_full)
                if qr_codes:
                    qr = qr_codes[0]
                    barcode_data = qr.data.decode('utf-8') if qr.data else None
                    print(f"Barcode/QR detected in full image. Data: {barcode_data}")
                    x, y, wbox, hbox = qr.rect
                    padding = 20
                    x1 = max(0, x - padding)
                    y1 = max(0, y - padding)
                    x2 = min(opencv_full.shape[1], x + wbox + padding)
                    y2 = min(opencv_full.shape[0], y + hbox + padding)
                    qr_img = opencv_full[y1:y2, x1:x2]
                else:
                    errors.append(f"Page {page_no + 1}: No barcode/QR detected")
                    continue

            # STEP 2: Extract Ref1 from barcode data (PRIMARY - no Tesseract needed)
            # Barcode format: |010556503082900 202111000201554 3820100052883 0
            ref1_value = extract_ref1_from_barcode(barcode_data)

            # STEP 3: If barcode extraction failed, try OCR as fallback (requires Tesseract)
            if not ref1_value and OCR_AVAILABLE:
                print("Barcode extraction failed, trying OCR fallback...")
                # Crop the right side where Ref1 text is located
                ref_crop = top_half.crop((int(w * 0.45), int(top_h * 0.10), w, int(top_h * 0.50)))
                ref1_value = extract_ref1_from_image(ref_crop)

                # If still not found, try full top half
                if not ref1_value:
                    ref1_value = extract_ref1_from_image(top_half)

            if ref1_value and qr_img is not None:
                # Encode QR image to PNG (better quality than JPG for QR codes)
                _, buffer = cv2.imencode('.png', qr_img)
                qr_bytes = buffer.tobytes()
                results.append((ref1_value, qr_bytes))
                print(f"[OK] Page {page_no + 1}: Extracted QR for account {ref1_value}")
            elif qr_img is not None:
                errors.append(f"Page {page_no + 1}: QR found but Ref1 not detected")
            else:
                errors.append(f"Page {page_no + 1}: Processing failed")

        doc.close()

    except Exception as e:
        errors.append(f"PDF processing error: {str(e)}")
        print(f"PDF processing error: {e}")
        import traceback
        traceback.print_exc()

    return results, errors


# Secret key for JWT
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = 'HS256'

# Store OTPs temporarily (in production, use Redis or database)
otp_store = {}


def create_notification(notification_type, title, message, debtor_data, metadata=None):
    """Create a notification for admin portal"""
    notifications = get_notifications_collection()

    notification = {
        'type': notification_type,  # 'payment_request', 'not_ready_to_pay'
        'title': title,
        'message': message,
        'debtor': {
            'account_number': debtor_data.get('account_number', 'N/A'),
            'name': debtor_data.get('name', 'N/A'),
            'phone': debtor_data.get('phone', 'N/A'),
            'email': debtor_data.get('email', 'N/A'),
            'outstanding_balance': debtor_data.get('outstanding_balance', 0),
        },
        'metadata': metadata or {},
        'read': False,
        'created_at': datetime.utcnow(),
    }

    result = notifications.insert_one(notification)
    notification['_id'] = str(result.inserted_id)
    return notification


def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))


def create_jwt_token(payload, expires_hours=24):
    """Create JWT token"""
    payload['exp'] = datetime.utcnow() + timedelta(hours=expires_hours)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        print("JWT Error: Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"JWT Error: Invalid token - {e}")
        return None


@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint"""
    return JsonResponse({'status': 'ok', 'message': 'API is running'})


@csrf_exempt
@require_http_methods(["POST"])
def admin_login(request):
    """Admin login endpoint - simple username/password authentication"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Username and password are required'}, status=400)

        admins = get_admins_collection()
        admin = admins.find_one({'username': username})

        if not admin:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
            role = admin.get('role', 'admin')
            token = create_jwt_token({'username': username, 'role': role}, expires_hours=72)
            return JsonResponse({
                'success': True,
                'token': token,
                'username': username,
                'role': role
            })
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def verify_admin_otp(request):
    """Verify admin login OTP"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        otp = data.get('otp')

        if not username or not otp:
            return JsonResponse({'error': 'Username and OTP are required'}, status=400)

        admins = get_admins_collection()
        admin = admins.find_one({'username': username})

        if not admin:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        stored_otp = admin.get('otp')
        otp_expiry = admin.get('otp_expiry')

        if not stored_otp or not otp_expiry:
            return JsonResponse({'error': 'No OTP found. Please login again.'}, status=400)

        # Check OTP expiry
        if datetime.utcnow() > otp_expiry:
            return JsonResponse({'error': 'OTP has expired. Please login again.'}, status=400)

        # Verify OTP
        if otp != stored_otp:
            return JsonResponse({'error': 'Invalid OTP'}, status=401)

        # Clear OTP and mark as verified
        admins.update_one(
            {'username': username},
            {'$unset': {'otp': '', 'otp_expiry': ''}, '$set': {'otp_verified': True}}
        )

        # Generate token
        role = admin.get('role', 'admin')
        token = create_jwt_token({'username': username, 'role': role}, expires_hours=72)

        return JsonResponse({
            'success': True,
            'token': token,
            'username': username,
            'role': role
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def generate_upload_id():
    """Generate a unique Upload ID in format UPL-YYYYMMDD-NNN"""
    upload_history = get_upload_history_collection()
    today = datetime.utcnow().strftime('%Y%m%d')

    # Find the highest sequence number for today
    today_prefix = f'UPL-{today}-'
    latest = upload_history.find_one(
        {'upload_id': {'$regex': f'^{today_prefix}'}},
        sort=[('upload_id', -1)]
    )

    if latest and latest.get('upload_id'):
        # Extract sequence number and increment
        try:
            seq = int(latest['upload_id'].split('-')[-1]) + 1
        except:
            seq = 1
    else:
        seq = 1

    return f'UPL-{today}-{seq:03d}'


def generate_case_id():
    """Generate a unique Case ID in format CASE-NNNNN"""
    debtors = get_debtors_collection()

    # Find the highest case_id
    latest = debtors.find_one(
        {'case_id': {'$exists': True, '$ne': None}},
        sort=[('case_id', -1)]
    )

    if latest and latest.get('case_id'):
        # Extract sequence number and increment
        try:
            seq = int(latest['case_id'].split('-')[-1]) + 1
        except:
            seq = 1
    else:
        seq = 1

    return f'CASE-{seq:05d}'


@csrf_exempt
@require_http_methods(["POST"])
def upload_file(request):
    """Upload Excel or CSV file with debtor data"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Get uploaded file
        if 'file' not in request.FILES:
            return JsonResponse({'error': 'No file uploaded'}, status=400)

        file = request.FILES['file']
        filename = file.name.lower()
        original_filename = file.name  # Keep original name with case

        # Generate Upload ID for this batch
        upload_id = generate_upload_id()

        # Read file content
        file_content = file.read()
        file_size = len(file_content)

        # Create BytesIO object for pandas to read
        from io import BytesIO
        file_buffer = BytesIO(file_content)

        # Determine file extension
        file_ext = Path(original_filename).suffix.lower()

        # Save file to disk with upload_id as filename
        saved_filename = f"{upload_id}{file_ext}"
        saved_file_path = UPLOADS_DIR / saved_filename
        with open(saved_file_path, 'wb') as f:
            f.write(file_content)

        # Read file based on extension
        if filename.endswith('.csv'):
            df = pd.read_csv(file_buffer)
        elif filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file_buffer)
        else:
            return JsonResponse({'error': 'Unsupported file format. Please upload .csv, .xlsx, or .xls file'}, status=400)

        # Expected columns mapping
        column_mapping = {
            'Account Number': 'account_number',
            'National ID': 'national_id',
            'Original Creditor': 'original_creditor',
            'Outstanding Balance': 'outstanding_balance',
            'Debt Type': 'debt_type',
            'Loan CONTRACT DATE': 'loan_contract_date',
            'Name': 'name',
            'Phone': 'phone',
            'Email': 'email'
        }

        # Validate required columns
        required_columns = list(column_mapping.keys())
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            return JsonResponse({
                'error': f'Missing required columns: {", ".join(missing_columns)}'
            }, status=400)

        # Rename columns
        df = df.rename(columns=column_mapping)

        # Convert to records
        records = df.to_dict('records')

        # Process each record
        debtors = get_debtors_collection()
        inserted_count = 0
        updated_count = 0

        for record in records:
            # Clean and format data
            account_number = str(record.get('account_number', '')).strip()

            if not account_number:
                continue

            # Check if debtor already exists
            existing_debtor = debtors.find_one({'account_number': account_number})

            debtor_data = {
                'account_number': account_number,
                'national_id': str(record.get('national_id', '')).strip(),
                'original_creditor': str(record.get('original_creditor', '')).strip(),
                'outstanding_balance': float(record.get('outstanding_balance', 0)),
                'debt_type': str(record.get('debt_type', '')).strip(),
                'loan_contract_date': str(record.get('loan_contract_date', '')).strip(),
                'name': str(record.get('name', '')).strip(),
                'phone': str(record.get('phone', '')).strip(),
                'email': str(record.get('email', '')).strip(),
                'upload_id': upload_id,  # Link to upload batch
                'updated_at': datetime.utcnow(),
            }

            # Set on insert fields
            set_on_insert = {
                'created_at': datetime.utcnow(),
            }

            # Generate case_id only for new records
            if not existing_debtor:
                set_on_insert['case_id'] = generate_case_id()

            # Upsert (update if exists, insert if not)
            result = debtors.update_one(
                {'account_number': account_number},
                {'$set': debtor_data, '$setOnInsert': set_on_insert},
                upsert=True
            )

            if result.upserted_id:
                inserted_count += 1
            elif result.modified_count > 0:
                updated_count += 1

        # Save upload history with file path (not content)
        upload_history = get_upload_history_collection()
        history_record = {
            'upload_id': upload_id,
            'filename': original_filename,
            'saved_filename': saved_filename,
            'file_path': str(saved_file_path),
            'file_size': file_size,
            'content_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' if filename.endswith('.xlsx') else 'application/vnd.ms-excel' if filename.endswith('.xls') else 'text/csv',
            'total_records': len(records),
            'inserted_count': inserted_count,
            'updated_count': updated_count,
            'uploaded_by': payload.get('username', 'admin'),
            'uploaded_at': datetime.utcnow(),
            'status': 'success'
        }
        upload_history.insert_one(history_record)

        return JsonResponse({
            'success': True,
            'message': f'Successfully processed {len(records)} records',
            'upload_id': upload_id,
            'inserted': inserted_count,
            'updated': updated_count
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_all_debtors(request):
    """Get all debtors with pagination, search, and filtering (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Get pagination parameters
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))

        # Limit page size to prevent abuse
        page_size = min(page_size, 100)

        # Get search and filter parameters
        search = request.GET.get('search', '').strip()
        sort_by = request.GET.get('sort_by', 'created_at')
        sort_order = request.GET.get('sort_order', 'desc')
        debt_type = request.GET.get('debt_type', '')
        upload_id = request.GET.get('upload_id', '')

        debtors = get_debtors_collection()

        # Build query
        query = {}

        # Text search across multiple fields
        if search:
            # Use regex for flexible search (works without text index too)
            search_regex = {'$regex': search, '$options': 'i'}
            query['$or'] = [
                {'account_number': search_regex},
                {'national_id': search_regex},
                {'name': search_regex},
                {'case_id': search_regex},
                {'email': search_regex},
                {'phone': search_regex},
            ]

        # Filter by debt type
        if debt_type:
            query['debt_type'] = debt_type

        # Filter by upload ID
        if upload_id:
            query['upload_id'] = upload_id

        # Get total count for pagination
        total_count = debtors.count_documents(query)
        total_pages = (total_count + page_size - 1) // page_size

        # Build sort
        sort_direction = -1 if sort_order == 'desc' else 1
        sort_field = sort_by if sort_by in ['created_at', 'updated_at', 'outstanding_balance', 'name', 'account_number', 'case_id'] else 'created_at'

        # Calculate skip value
        skip = (page - 1) * page_size

        # Execute query with pagination
        cursor = debtors.find(query, {'_id': 0}).sort(sort_field, sort_direction).skip(skip).limit(page_size)
        page_debtors = list(cursor)

        # Convert datetime objects to ISO format strings
        for debtor in page_debtors:
            if 'created_at' in debtor and debtor['created_at']:
                debtor['created_at'] = debtor['created_at'].isoformat()
            if 'updated_at' in debtor and debtor['updated_at']:
                debtor['updated_at'] = debtor['updated_at'].isoformat()

        return JsonResponse({
            'success': True,
            'debtors': page_debtors,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["DELETE"])
def delete_debtor(request, account_number):
    """Delete a debtor (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        debtors = get_debtors_collection()
        result = debtors.delete_one({'account_number': account_number})

        if result.deleted_count > 0:
            return JsonResponse({'success': True, 'message': 'Debtor deleted successfully'})
        else:
            return JsonResponse({'error': 'Debtor not found'}, status=404)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def debtor_login(request):
    """Debtor login - send OTP to registered email (supports multiple login methods)"""
    try:
        data = json.loads(request.body)
        login_method = data.get('login_method', 'national_id')  # national_id, phone, email, account_number
        login_value = data.get('login_value') or data.get('national_id')  # Support both formats
        language = data.get('language', 'en')  # Get language preference from frontend

        if not login_value:
            error_messages = {
                'national_id': 'National ID is required',
                'phone': 'Phone number is required',
                'email': 'Email is required',
                'account_number': 'Account number is required'
            }
            return JsonResponse({'error': error_messages.get(login_method, 'Login value is required')}, status=400)

        debtors = get_debtors_collection()
        national_id = None
        debtor_list = []

        # Find accounts based on login method
        if login_method == 'national_id':
            national_id = login_value
            debtor_list = list(debtors.find({'national_id': national_id}))
        elif login_method == 'phone':
            debtor_list = list(debtors.find({'phone': login_value}))
            if debtor_list:
                national_id = debtor_list[0].get('national_id')
                # Get ALL accounts with this national_id
                if national_id:
                    debtor_list = list(debtors.find({'national_id': national_id}))
        elif login_method == 'email':
            debtor_list = list(debtors.find({'email': login_value}))
            if debtor_list:
                national_id = debtor_list[0].get('national_id')
                # Get ALL accounts with this national_id
                if national_id:
                    debtor_list = list(debtors.find({'national_id': national_id}))
        elif login_method == 'account_number':
            debtor = debtors.find_one({'account_number': login_value})
            if debtor:
                national_id = debtor.get('national_id')
                # Get ALL accounts with this national_id
                if national_id:
                    debtor_list = list(debtors.find({'national_id': national_id}))

        if not debtor_list:
            error_messages = {
                'national_id': 'No accounts found. Please check your National ID.',
                'phone': 'No accounts found. Please check your phone number.',
                'email': 'No accounts found. Please check your email address.',
                'account_number': 'No accounts found. Please check your account number.'
            }
            return JsonResponse({'error': error_messages.get(login_method, 'No accounts found.')}, status=404)

        # Get email for OTP from the first account (or any account with email)
        email = None
        for debtor in debtor_list:
            if debtor.get('email'):
                email = debtor.get('email')
                break

        if not email:
            return JsonResponse({'error': 'No email registered for your accounts. Please contact support.'}, status=400)

        # Generate OTP
        otp = generate_otp()

        # Use national_id as the key for OTP storage (since one person can have multiple accounts)
        otp_store[national_id] = {
            'otp': otp,
            'expires': datetime.utcnow() + timedelta(minutes=5),
            'email': email
        }

        # Mask email for display (e.g., j***@email.com)
        email_parts = email.split('@')
        if len(email_parts) == 2 and len(email_parts[0]) > 2:
            masked_email = email_parts[0][:2] + '***@' + email_parts[1]
        else:
            masked_email = '***@***.***'

        # Send OTP via email in the user's preferred language
        email_sent = False
        try:
            account_count = len(debtor_list)
            subject = get_email_template('otp_subject', language)
            email_body = get_email_template('otp_body', language).format(
                otp=otp,
                account_count=account_count
            )
            send_mail(
                subject=subject,
                message=email_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            email_sent = True
            print(f"OTP email sent successfully to {email} in {language}")
        except Exception as email_error:
            print(f"Failed to send OTP email: {email_error}")
            import traceback
            traceback.print_exc()

        return JsonResponse({
            'success': True,
            'message': f'OTP sent to {masked_email}',
            'masked_email': masked_email,
            'national_id': national_id,
            'account_count': len(debtor_list),
            'email_sent': email_sent,
            # For demo/testing - remove in production
            'demo_otp': otp if not email_sent else None
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def verify_otp(request):
    """Verify OTP and login debtor (returns all accounts for the national_id)"""
    try:
        data = json.loads(request.body)
        national_id = data.get('national_id')
        otp = data.get('otp')

        if not national_id or not otp:
            return JsonResponse({'error': 'National ID and OTP are required'}, status=400)

        # Check OTP
        stored_otp_data = otp_store.get(national_id)

        if not stored_otp_data:
            return JsonResponse({'error': 'OTP expired or not found. Please request a new OTP.'}, status=400)

        if datetime.utcnow() > stored_otp_data['expires']:
            del otp_store[national_id]
            return JsonResponse({'error': 'OTP expired. Please request a new OTP.'}, status=400)

        if stored_otp_data['otp'] != otp:
            return JsonResponse({'error': 'Invalid OTP'}, status=400)

        # Clear OTP after successful verification
        del otp_store[national_id]

        # Get ALL debtor accounts for this national_id
        debtors = get_debtors_collection()
        debtor_list = list(debtors.find({'national_id': national_id}, {'_id': 0}))

        # Calculate total outstanding balance
        total_balance = sum(d.get('outstanding_balance', 0) for d in debtor_list)

        # Get account numbers for the token
        account_numbers = [d.get('account_number') for d in debtor_list]

        # Create token for debtor (24 hours expiry) with national_id
        token = create_jwt_token({
            'national_id': national_id,
            'account_numbers': account_numbers,
            'role': 'debtor'
        }, expires_hours=24)

        # Convert datetime objects to ISO format strings
        for debtor in debtor_list:
            if 'created_at' in debtor and debtor['created_at']:
                debtor['created_at'] = debtor['created_at'].isoformat()
            if 'updated_at' in debtor and debtor['updated_at']:
                debtor['updated_at'] = debtor['updated_at'].isoformat()

        # Check if PDPA consent has been given (check first account)
        pdpa_consent = debtor_list[0].get('pdpa_consent', False) if debtor_list else False
        pdpa_consent_date = debtor_list[0].get('pdpa_consent_date') if debtor_list else None
        if pdpa_consent_date:
            pdpa_consent_date = pdpa_consent_date.isoformat() if hasattr(pdpa_consent_date, 'isoformat') else pdpa_consent_date

        return JsonResponse({
            'success': True,
            'token': token,
            'national_id': national_id,
            'accounts': debtor_list,
            'account_count': len(debtor_list),
            'total_balance': total_balance,
            'pdpa_consent': pdpa_consent,
            'pdpa_consent_date': pdpa_consent_date
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def save_pdpa_consent(request):
    """Save PDPA consent for a debtor (all accounts under the national_id)"""
    try:
        # Verify debtor token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') != 'debtor':
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        national_id = payload.get('national_id')
        if not national_id:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # Update all accounts for this national_id with PDPA consent
        debtors = get_debtors_collection()
        consent_date = datetime.utcnow()

        result = debtors.update_many(
            {'national_id': national_id},
            {
                '$set': {
                    'pdpa_consent': True,
                    'pdpa_consent_date': consent_date,
                    'pdpa_consent_text': 'I hereby give my explicit consent to Power Asset Management Co., Ltd. to collect, use, disclose, and process my personal data for the purposes of debt management, payment processing, legal enforcement, regulatory compliance, and related activities in accordance with the Personal Data Protection Act B.E. 2562 (2019) and the Company\'s Privacy Notice.'
                }
            }
        )

        return JsonResponse({
            'success': True,
            'message': 'PDPA consent saved successfully',
            'accounts_updated': result.modified_count,
            'consent_date': consent_date.isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def save_payment_consent(request):
    """Save payment consent for a debtor before making payment"""
    try:
        # Verify debtor token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') != 'debtor':
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        national_id = payload.get('national_id')
        if not national_id:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # Update all accounts for this national_id with payment consent
        debtors = get_debtors_collection()
        consent_date = datetime.utcnow()

        # Store payment consent with timestamp
        result = debtors.update_many(
            {'national_id': national_id},
            {
                '$set': {
                    'payment_terms_consent': True,
                    'payment_terms_consent_date': consent_date,
                    'digital_receipt_consent': True,
                    'digital_receipt_consent_date': consent_date,
                    'payment_terms_text': 'I acknowledge and agree that this payment is made toward my outstanding debt under the above contract. This payment does not automatically constitute full settlement or legal closure unless expressly confirmed by the Asset Management Company in writing.',
                    'digital_receipt_text': 'I consent to receive my payment receipt, tax documents (if applicable), and related confirmations in electronic format. I acknowledge that such electronic documents shall be legally binding under the Electronic Transactions Act B.E. 2544 (2001).'
                }
            }
        )

        return JsonResponse({
            'success': True,
            'message': 'Payment consent saved successfully',
            'accounts_updated': result.modified_count,
            'consent_date': consent_date.isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_debtor_account(request, account_number):
    """Get debtor account details"""
    try:
        # Verify token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Check if user is authorized to access this account
        if payload.get('role') == 'debtor':
            # Check both old format (single account_number) and new format (account_numbers list)
            account_numbers = payload.get('account_numbers', [])
            single_account = payload.get('account_number')
            if single_account:
                account_numbers.append(single_account)

            if account_number not in account_numbers:
                return JsonResponse({'error': 'Unauthorized'}, status=401)

        debtors = get_debtors_collection()
        debtor = debtors.find_one({'account_number': account_number}, {'_id': 0})

        if not debtor:
            return JsonResponse({'error': 'Account not found'}, status=404)

        # Convert datetime objects to ISO format strings
        if 'created_at' in debtor and debtor['created_at']:
            debtor['created_at'] = debtor['created_at'].isoformat()
        if 'updated_at' in debtor and debtor['updated_at']:
            debtor['updated_at'] = debtor['updated_at'].isoformat()

        return JsonResponse({
            'success': True,
            'debtor': debtor
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_all_debtor_accounts(request):
    """Get all accounts for the logged-in debtor (by national_id)"""
    try:
        # Verify token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        if payload.get('role') != 'debtor':
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        national_id = payload.get('national_id')
        if not national_id:
            return JsonResponse({'error': 'Invalid token - missing national_id'}, status=401)

        debtors = get_debtors_collection()
        debtor_list = list(debtors.find({'national_id': national_id}, {'_id': 0}))

        # Calculate total outstanding balance
        total_balance = sum(d.get('outstanding_balance', 0) for d in debtor_list)

        # Convert datetime objects to ISO format strings
        for debtor in debtor_list:
            if 'created_at' in debtor and debtor['created_at']:
                debtor['created_at'] = debtor['created_at'].isoformat()
            if 'updated_at' in debtor and debtor['updated_at']:
                debtor['updated_at'] = debtor['updated_at'].isoformat()

        return JsonResponse({
            'success': True,
            'national_id': national_id,
            'accounts': debtor_list,
            'account_count': len(debtor_list),
            'total_balance': total_balance
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["PUT"])
def update_debtor_contact(request, account_number):
    """Update debtor contact information (phone and/or email)"""
    try:
        # Verify token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Check if user is authorized to update this account
        if payload.get('role') == 'debtor':
            # Check both old format (single account_number) and new format (account_numbers list)
            account_numbers = payload.get('account_numbers', [])
            single_account = payload.get('account_number')
            if single_account:
                account_numbers.append(single_account)

            if account_number not in account_numbers:
                return JsonResponse({'error': 'Unauthorized'}, status=401)

        data = json.loads(request.body)
        phone = data.get('phone')
        email = data.get('email')

        if not phone and not email:
            return JsonResponse({'error': 'Phone or email is required'}, status=400)

        debtors = get_debtors_collection()

        # Build update object
        update_data = {'updated_at': datetime.utcnow()}
        if phone:
            update_data['phone'] = phone
        if email:
            update_data['email'] = email

        result = debtors.update_one(
            {'account_number': account_number},
            {'$set': update_data}
        )

        if result.matched_count == 0:
            return JsonResponse({'error': 'Account not found'}, status=404)

        # Fetch updated debtor data
        debtor = debtors.find_one({'account_number': account_number}, {'_id': 0})

        return JsonResponse({
            'success': True,
            'message': 'Contact information updated successfully',
            'debtor': debtor
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def generate_receipt_filename(account_number, transaction_number):
    """Generate unique filename for payment receipt"""
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    safe_account = account_number.replace('/', '_').replace('\\', '_')
    safe_trans = transaction_number.replace('/', '_').replace('\\', '_')[:20] if transaction_number else 'notrans'
    return f"receipt_{safe_account}_{safe_trans}_{timestamp}"


@csrf_exempt
@require_http_methods(["POST"])
def send_payment_interest_notification(request):
    """Send email notification when debtor submits a payment with transaction number and optional receipt"""
    try:
        # Verify token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Handle both JSON and multipart/form-data
        content_type = request.content_type or ''
        if 'multipart/form-data' in content_type:
            # Form data with file upload
            account_number = request.POST.get('account_number')
            payment_type = request.POST.get('payment_type', 'N/A')
            payment_amount = float(request.POST.get('payment_amount', 0))
            transaction_number = request.POST.get('transaction_number', 'N/A')
            receipt_file = request.FILES.get('receipt')
            language = request.POST.get('language', 'en')  # Get language preference
        else:
            # JSON data
            data = json.loads(request.body)
            account_number = data.get('account_number')
            payment_type = data.get('payment_type', 'N/A')
            payment_amount = data.get('payment_amount', 0)
            transaction_number = data.get('installment_plan', 'N/A')
            receipt_file = None
            language = data.get('language', 'en')  # Get language preference

        if not account_number:
            return JsonResponse({'error': 'Account number is required'}, status=400)

        # Get debtor details
        debtors = get_debtors_collection()
        debtor = debtors.find_one({'account_number': account_number}, {'_id': 0})

        if not debtor:
            return JsonResponse({'error': 'Debtor not found'}, status=404)

        # Get recipient email from system settings
        system_settings = get_system_settings_collection()
        settings_doc = system_settings.find_one({'key': 'app_settings'})
        recipient_email = None
        if settings_doc:
            recipient_email = settings_doc.get('notification_email')

        # Fallback to Django settings if not configured in system settings
        if not recipient_email:
            recipient_email = getattr(settings, 'COLLECTIONS_TEAM_EMAIL', 'collections@example.com')

        # Prepare email content using language templates
        subject = get_email_template('payment_subject', language).format(
            account_number=account_number,
            transaction_number=transaction_number
        )

        email_body = get_email_template('payment_body', language).format(
            account_number=debtor.get('account_number', 'N/A'),
            name=debtor.get('name', 'N/A'),
            national_id=debtor.get('national_id', 'N/A'),
            phone=debtor.get('phone', 'N/A'),
            email=debtor.get('email', 'N/A'),
            original_creditor=debtor.get('original_creditor', 'N/A'),
            debt_type=debtor.get('debt_type', 'N/A'),
            outstanding_balance=format_thai_currency(debtor.get('outstanding_balance', 0)),
            loan_contract_date=debtor.get('loan_contract_date', 'N/A'),
            payment_type=payment_type,
            payment_amount=format_thai_currency(payment_amount),
            transaction_number=transaction_number,
            timestamp=get_bangkok_time()
        )

        # Try to send email
        try:
            # Debug: Log email settings
            print(f"=== EMAIL DEBUG ===")
            print(f"EMAIL_HOST: {settings.EMAIL_HOST}")
            print(f"EMAIL_PORT: {settings.EMAIL_PORT}")
            print(f"EMAIL_USE_TLS: {settings.EMAIL_USE_TLS}")
            print(f"EMAIL_HOST_USER: {settings.EMAIL_HOST_USER}")
            print(f"DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
            print(f"Recipient: {recipient_email}")
            print(f"===================")

            send_mail(
                subject=subject,
                message=email_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient_email],
                fail_silently=False,
            )
            email_sent = True
            email_message = f'Email notification sent to {recipient_email}'
            print(f"Email sent successfully to {recipient_email}")
        except Exception as email_error:
            # If email fails, log but don't fail the request
            email_sent = False
            email_message = f'Email could not be sent: {str(email_error)}'
            print(f"Email sending failed: {email_error}")
            import traceback
            traceback.print_exc()

        # Handle receipt file upload
        receipt_filename = None
        receipt_path = None
        if receipt_file:
            try:
                # Generate unique filename
                file_ext = os.path.splitext(receipt_file.name)[1].lower()
                if file_ext not in ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.webp']:
                    file_ext = '.jpg'  # Default extension
                base_filename = generate_receipt_filename(account_number, transaction_number)
                receipt_filename = f"{base_filename}{file_ext}"
                receipt_path = RECEIPTS_DIR / receipt_filename

                # Save the file
                with open(receipt_path, 'wb+') as destination:
                    for chunk in receipt_file.chunks():
                        destination.write(chunk)

                print(f"Receipt saved: {receipt_path}")
            except Exception as file_error:
                print(f"Failed to save receipt: {file_error}")
                receipt_filename = None

        # Log the payment in database (optional - for tracking)
        payment_log = {
            'account_number': account_number,
            'debtor_name': debtor.get('name'),
            'payment_type': payment_type,
            'payment_amount': payment_amount,
            'transaction_number': transaction_number,
            'email_sent': email_sent,
            'recipient_email': recipient_email,
            'receipt_filename': receipt_filename,
            'timestamp': datetime.utcnow()
        }

        # Create notification for admin portal (include receipt info)
        create_notification(
            notification_type='payment_submitted',
            title='Payment Submitted',
            message=f'{debtor.get("name", "A customer")} has submitted a payment with transaction #{transaction_number}.',
            debtor_data=debtor,
            metadata={
                'payment_type': payment_type,
                'payment_amount': payment_amount,
                'transaction_number': transaction_number,
                'receipt_filename': receipt_filename,
                'payment_terms_consent': debtor.get('payment_terms_consent', False),
                'payment_terms_consent_date': debtor.get('payment_terms_consent_date').isoformat() if debtor.get('payment_terms_consent_date') else None,
                'digital_receipt_consent': debtor.get('digital_receipt_consent', False),
                'digital_receipt_consent_date': debtor.get('digital_receipt_consent_date').isoformat() if debtor.get('digital_receipt_consent_date') else None,
            }
        )

        return JsonResponse({
            'success': True,
            'message': 'Payment recorded successfully',
            'email_sent': email_sent,
            'email_message': email_message,
            'receipt_saved': receipt_filename is not None,
            'log': {
                'account_number': account_number,
                'payment_type': payment_type,
                'payment_amount': payment_amount,
                'transaction_number': transaction_number,
                'receipt_filename': receipt_filename,
                'timestamp': datetime.utcnow().isoformat()
            }
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def send_not_ready_to_pay_notification(request):
    """Send email notification when debtor is not ready to pay"""
    try:
        # Verify token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        data = json.loads(request.body)
        account_number = data.get('account_number')
        reason = data.get('reason', 'Not specified')
        notes = data.get('notes', '')
        language = data.get('language', 'en')  # Get language preference
        preferred_contact_date = data.get('preferred_contact_date', '')
        preferred_contact_time = data.get('preferred_contact_time', '')
        preferred_contact_method = data.get('preferred_contact_method', '')
        preferred_contact_value = data.get('preferred_contact_value', '')

        if not account_number:
            return JsonResponse({'error': 'Account number is required'}, status=400)

        if not reason:
            return JsonResponse({'error': 'Reason for non-payment is required'}, status=400)

        # Get debtor details
        debtors = get_debtors_collection()
        debtor = debtors.find_one({'account_number': account_number}, {'_id': 0})

        if not debtor:
            return JsonResponse({'error': 'Debtor not found'}, status=404)

        # Prepare email content using language templates
        subject = get_email_template('not_ready_subject', language).format(
            account_number=account_number
        )

        no_notes_text = 'No additional notes provided.' if language == 'en' else 'ไม่มีหมายเหตุเพิ่มเติม'
        not_specified_text = 'Not specified' if language == 'en' else 'ไม่ระบุ'

        # Map contact time values to readable text
        time_labels = {
            'morning': 'Morning (9AM - 12PM)' if language == 'en' else 'ช่วงเช้า (9.00 - 12.00 น.)',
            'afternoon': 'Afternoon (12PM - 5PM)' if language == 'en' else 'ช่วงบ่าย (12.00 - 17.00 น.)',
            'evening': 'Evening (5PM - 8PM)' if language == 'en' else 'ช่วงเย็น (17.00 - 20.00 น.)',
            'anytime': 'Anytime' if language == 'en' else 'ติดต่อได้ทุกเวลา',
        }

        # Map contact method values to readable text
        method_labels = {
            'phone': 'Phone Call' if language == 'en' else 'โทรศัพท์',
            'email': 'Email' if language == 'en' else 'อีเมล',
        }

        # Format contact method with value if provided
        contact_method_display = method_labels.get(preferred_contact_method, not_specified_text)
        if preferred_contact_value and preferred_contact_method in ['phone', 'email']:
            contact_method_display = f"{contact_method_display}: {preferred_contact_value}"

        email_body = get_email_template('not_ready_body', language).format(
            account_number=debtor.get('account_number', 'N/A'),
            name=debtor.get('name', 'N/A'),
            national_id=debtor.get('national_id', 'N/A'),
            phone=debtor.get('phone', 'N/A'),
            email=debtor.get('email', 'N/A'),
            original_creditor=debtor.get('original_creditor', 'N/A'),
            debt_type=debtor.get('debt_type', 'N/A'),
            outstanding_balance=format_thai_currency(debtor.get('outstanding_balance', 0)),
            loan_contract_date=debtor.get('loan_contract_date', 'N/A'),
            reason=reason,
            notes=notes if notes else no_notes_text,
            preferred_contact_date=preferred_contact_date if preferred_contact_date else not_specified_text,
            preferred_contact_time=time_labels.get(preferred_contact_time, not_specified_text),
            preferred_contact_method=contact_method_display,
            timestamp=get_bangkok_time()
        )

        # Get recipient email from system settings
        system_settings = get_system_settings_collection()
        settings_doc = system_settings.find_one({'key': 'app_settings'})
        recipient_email = None
        if settings_doc:
            recipient_email = settings_doc.get('notification_email')

        # Fallback to Django settings if not configured
        if not recipient_email:
            recipient_email = getattr(settings, 'COLLECTIONS_TEAM_EMAIL', 'collections@example.com')

        # Try to send email
        try:
            send_mail(
                subject=subject,
                message=email_body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient_email],
                fail_silently=False,
            )
            email_sent = True
            email_message = f'Email notification sent to {recipient_email}'
        except Exception as email_error:
            email_sent = False
            email_message = f'Email could not be sent: {str(email_error)}'
            print(f"Email sending failed: {email_error}")

        # Create notification for admin portal
        create_notification(
            notification_type='not_ready_to_pay',
            title='Need Support to Pay',
            message=f'{debtor.get("name", "A customer")} needs support to pay.',
            debtor_data=debtor,
            metadata={
                'reason': reason,
                'notes': notes,
                'preferred_contact_date': preferred_contact_date,
                'preferred_contact_time': preferred_contact_time,
                'preferred_contact_method': preferred_contact_method,
                'preferred_contact_value': preferred_contact_value,
            }
        )

        return JsonResponse({
            'success': True,
            'message': 'Non-payment reason recorded successfully',
            'email_sent': email_sent,
            'email_message': email_message,
            'log': {
                'account_number': account_number,
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat()
            }
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_notifications(request):
    """Get all notifications for admin portal"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        notifications = get_notifications_collection()

        # Get all notifications sorted by created_at descending
        all_notifications = list(notifications.find().sort('created_at', -1).limit(50))

        # Convert ObjectId to string for JSON serialization
        for notification in all_notifications:
            notification['_id'] = str(notification['_id'])
            if 'created_at' in notification:
                notification['created_at'] = notification['created_at'].isoformat()

        # Count unread notifications
        unread_count = notifications.count_documents({'read': False})

        return JsonResponse({
            'success': True,
            'notifications': all_notifications,
            'unread_count': unread_count
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["PUT"])
def mark_notification_read(request, notification_id):
    """Mark a notification as read"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        notifications = get_notifications_collection()

        result = notifications.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'read': True}}
        )

        if result.matched_count == 0:
            return JsonResponse({'error': 'Notification not found'}, status=404)

        return JsonResponse({
            'success': True,
            'message': 'Notification marked as read'
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["PUT"])
def mark_all_notifications_read(request):
    """Mark all notifications as read"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        notifications = get_notifications_collection()

        result = notifications.update_many(
            {'read': False},
            {'$set': {'read': True}}
        )

        return JsonResponse({
            'success': True,
            'message': f'{result.modified_count} notifications marked as read'
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def upload_qr_code(request):
    """Upload LINE QR code image (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Get uploaded file
        if 'file' not in request.FILES:
            return JsonResponse({'error': 'No file uploaded'}, status=400)

        file = request.FILES['file']
        filename = file.name.lower()

        # Validate file type
        valid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp']
        if not any(filename.endswith(ext) for ext in valid_extensions):
            return JsonResponse({'error': 'Invalid file type. Please upload an image file (PNG, JPG, GIF, WEBP)'}, status=400)

        # Read and encode file as base64
        file_content = file.read()
        base64_image = base64.b64encode(file_content).decode('utf-8')

        # Determine content type
        content_type = file.content_type or 'image/png'

        # Store in settings collection
        settings = get_settings_collection()
        settings.update_one(
            {'key': 'line_qr_code'},
            {
                '$set': {
                    'key': 'line_qr_code',
                    'value': base64_image,
                    'content_type': content_type,
                    'filename': file.name,
                    'updated_at': datetime.utcnow()
                }
            },
            upsert=True
        )

        return JsonResponse({
            'success': True,
            'message': 'QR code uploaded successfully'
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_qr_code(request):
    """Get LINE QR code image (public endpoint for debtors)"""
    try:
        settings = get_settings_collection()
        qr_setting = settings.find_one({'key': 'line_qr_code'})

        if not qr_setting:
            return JsonResponse({
                'success': True,
                'qr_code': None,
                'message': 'No QR code configured'
            })

        return JsonResponse({
            'success': True,
            'qr_code': {
                'image': qr_setting.get('value'),
                'content_type': qr_setting.get('content_type', 'image/png'),
                'filename': qr_setting.get('filename', 'qr_code.png')
            }
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["DELETE"])
def delete_qr_code(request):
    """Delete LINE QR code image (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        settings = get_settings_collection()
        result = settings.delete_one({'key': 'line_qr_code'})

        if result.deleted_count > 0:
            return JsonResponse({
                'success': True,
                'message': 'QR code deleted successfully'
            })
        else:
            return JsonResponse({
                'success': True,
                'message': 'No QR code to delete'
            })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_upload_history(request):
    """Get upload history (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        upload_history = get_upload_history_collection()

        # Get all upload history sorted by uploaded_at descending (exclude file_content)
        history_records = list(upload_history.find(
            {},
            {'file_content': 0}  # Exclude file content from listing
        ).sort('uploaded_at', -1).limit(100))

        # Convert ObjectId to string for JSON serialization
        for record in history_records:
            record['_id'] = str(record['_id'])
            if 'uploaded_at' in record:
                record['uploaded_at'] = record['uploaded_at'].isoformat()

        return JsonResponse({
            'success': True,
            'history': history_records,
            'count': len(history_records)
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def download_upload_file(request, upload_id):
    """Download a previously uploaded file (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        upload_history = get_upload_history_collection()

        # Find the upload record
        record = upload_history.find_one({'_id': ObjectId(upload_id)})

        if not record:
            return JsonResponse({'error': 'File not found'}, status=404)

        # Check for file path (new system) or file_content (legacy)
        if 'saved_filename' in record:
            # New file system storage
            file_path = UPLOADS_DIR / record['saved_filename']
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    file_content = base64.b64encode(f.read()).decode('utf-8')
                return JsonResponse({
                    'success': True,
                    'filename': record.get('filename', 'download.xlsx'),
                    'content_type': record.get('content_type', 'application/octet-stream'),
                    'file_content': file_content
                })
            else:
                return JsonResponse({'error': 'File not found on disk'}, status=404)
        elif 'file_content' in record:
            # Legacy base64 storage (for backwards compatibility)
            return JsonResponse({
                'success': True,
                'filename': record.get('filename', 'download.xlsx'),
                'content_type': record.get('content_type', 'application/octet-stream'),
                'file_content': record['file_content']
            })
        else:
            return JsonResponse({'error': 'File content not available'}, status=404)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================
# SUPER ADMIN ENDPOINTS
# ============================================

@csrf_exempt
@require_http_methods(["GET"])
def get_system_settings(request):
    """Get system settings (public endpoint for frontend configuration)"""
    try:
        system_settings = get_system_settings_collection()
        settings_doc = system_settings.find_one({'key': 'app_settings'}, {'_id': 0, 'key': 0})

        if not settings_doc:
            # Return default settings if none exist
            settings_doc = {
                'admin_tabs': {
                    'upload_data': True,
                    'view_accounts': True,
                    'debtor_requests': True,
                    'upload_history': True,
                    'settings': True,
                },
                'enable_image_upload': False,
                'debtor_features': {
                    'make_payment': True,
                    'not_ready_to_pay': True,
                    'line_qr_support': True,
                    'update_contact': True,
                },
                'notification_email': '',
                'bank_account': {
                    'bank_name': '',
                    'account_name': '',
                    'account_number': '',
                    'promptpay_id': '',
                },
                'admin_filters': {
                    'type_filter': True,
                    'status_filter': True,
                },
                'table_actions': {
                    'view_accounts': True,
                    'debtor_requests': True,
                    'upload_history': True,
                },
                'maintenance_mode': {
                    'enabled': False,
                    'title': '',
                    'message': '',
                    'estimated_time': '',
                },
            }

        # Convert datetime to ISO format if exists
        if 'updated_at' in settings_doc and settings_doc['updated_at']:
            settings_doc['updated_at'] = settings_doc['updated_at'].isoformat()

        return JsonResponse({
            'success': True,
            'settings': settings_doc
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["PUT"])
def update_system_settings(request):
    """Update system settings (super admin only)"""
    try:
        # Verify super admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') != 'super_admin':
            return JsonResponse({'error': 'Super admin access required'}, status=403)

        data = json.loads(request.body)
        print(f"Received settings update: {data}")  # Debug log

        system_settings = get_system_settings_collection()

        # Get existing settings first
        existing = system_settings.find_one({'key': 'app_settings'})

        # Build update object with proper merging
        update_data = {
            'key': 'app_settings',
            'updated_at': datetime.utcnow()
        }

        # Update admin tabs - merge with existing or use provided
        if 'admin_tabs' in data:
            existing_tabs = existing.get('admin_tabs', {}) if existing else {}
            update_data['admin_tabs'] = {**existing_tabs, **data['admin_tabs']}
        elif existing and 'admin_tabs' in existing:
            update_data['admin_tabs'] = existing['admin_tabs']

        # Update image upload setting if provided
        if 'enable_image_upload' in data:
            update_data['enable_image_upload'] = data['enable_image_upload']
        elif existing:
            update_data['enable_image_upload'] = existing.get('enable_image_upload', False)

        # Update admin OTP setting if provided
        if 'admin_otp_enabled' in data:
            update_data['admin_otp_enabled'] = data['admin_otp_enabled']
        elif existing:
            update_data['admin_otp_enabled'] = existing.get('admin_otp_enabled', False)

        # Update debtor features - merge with existing or use provided
        if 'debtor_features' in data:
            existing_features = existing.get('debtor_features', {}) if existing else {}
            update_data['debtor_features'] = {**existing_features, **data['debtor_features']}
        elif existing and 'debtor_features' in existing:
            update_data['debtor_features'] = existing['debtor_features']

        # Update notification email
        if 'notification_email' in data:
            update_data['notification_email'] = data['notification_email']
        elif existing and 'notification_email' in existing:
            update_data['notification_email'] = existing['notification_email']

        # Update bank account details
        if 'bank_account' in data:
            existing_bank = existing.get('bank_account', {}) if existing else {}
            update_data['bank_account'] = {**existing_bank, **data['bank_account']}
        elif existing and 'bank_account' in existing:
            update_data['bank_account'] = existing['bank_account']

        # Update admin filters settings
        if 'admin_filters' in data:
            existing_filters = existing.get('admin_filters', {}) if existing else {}
            update_data['admin_filters'] = {**existing_filters, **data['admin_filters']}
        elif existing and 'admin_filters' in existing:
            update_data['admin_filters'] = existing['admin_filters']

        # Update table action column settings
        if 'table_actions' in data:
            existing_table_actions = existing.get('table_actions', {}) if existing else {}
            update_data['table_actions'] = {**existing_table_actions, **data['table_actions']}
        elif existing and 'table_actions' in existing:
            update_data['table_actions'] = existing['table_actions']

        # Update table columns visibility settings
        if 'table_columns' in data:
            existing_table_columns = existing.get('table_columns', {}) if existing else {}
            # Deep merge for nested structure (table_name -> column_name -> boolean)
            merged_table_columns = {**existing_table_columns}
            for table_name, columns in data['table_columns'].items():
                if table_name in merged_table_columns:
                    merged_table_columns[table_name] = {**merged_table_columns[table_name], **columns}
                else:
                    merged_table_columns[table_name] = columns
            update_data['table_columns'] = merged_table_columns
        elif existing and 'table_columns' in existing:
            update_data['table_columns'] = existing['table_columns']

        # Update maintenance mode settings
        if 'maintenance_mode' in data:
            existing_maintenance = existing.get('maintenance_mode', {}) if existing else {}
            update_data['maintenance_mode'] = {**existing_maintenance, **data['maintenance_mode']}
        elif existing and 'maintenance_mode' in existing:
            update_data['maintenance_mode'] = existing['maintenance_mode']

        print(f"Saving settings: {update_data}")  # Debug log

        result = system_settings.replace_one(
            {'key': 'app_settings'},
            update_data,
            upsert=True
        )

        print(f"Save result: matched={result.matched_count}, modified={result.modified_count}")  # Debug log

        return JsonResponse({
            'success': True,
            'message': 'System settings updated successfully'
        })

    except Exception as e:
        print(f"Error saving settings: {str(e)}")  # Debug log
        return JsonResponse({'error': str(e)}, status=500)


# ============================================
# PAYMENT RECEIPT ENDPOINTS
# ============================================

@csrf_exempt
@require_http_methods(["GET"])
def serve_payment_receipt(request, filename):
    """Serve payment receipt file (admin only)"""
    try:
        # Verify token - admin only
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Only admin or super_admin can view receipts
        if payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized - Admin access required'}, status=401)

        # Check if file exists
        receipt_path = RECEIPTS_DIR / filename
        print(f"Looking for receipt at: {receipt_path}")

        if not receipt_path.exists():
            # Try without extension as fallback
            base_name = os.path.splitext(filename)[0]
            receipt_path_no_ext = RECEIPTS_DIR / base_name
            print(f"Trying without extension: {receipt_path_no_ext}")

            if receipt_path_no_ext.exists():
                receipt_path = receipt_path_no_ext
                filename = base_name
                print(f"Found file without extension: {receipt_path}")
            else:
                # Also try to find any file starting with the base name
                try:
                    matching_files = list(RECEIPTS_DIR.glob(f"{base_name}*"))
                    print(f"Glob search found: {matching_files}")
                    if matching_files:
                        receipt_path = matching_files[0]
                        filename = receipt_path.name
                        print(f"Found matching file: {receipt_path}")
                    else:
                        print(f"Receipt not found: {receipt_path}")
                        return JsonResponse({'error': f'Receipt not found: {filename}'}, status=404)
                except Exception as glob_error:
                    print(f"Glob error: {glob_error}")
                    return JsonResponse({'error': f'Receipt not found: {filename}'}, status=404)

        # Determine content type based on extension or default to PNG
        file_ext = os.path.splitext(str(receipt_path))[1].lower()
        print(f"File extension: '{file_ext}'")

        content_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.pdf': 'application/pdf',
        }

        # Default to PNG for images without extension
        content_type = content_types.get(file_ext, 'image/png')
        print(f"Content type: {content_type}")

        # Read and return file
        with open(receipt_path, 'rb') as f:
            file_data = f.read()

        print(f"Serving receipt: {filename}, size: {len(file_data)} bytes")
        response = HttpResponse(file_data, content_type=content_type)
        response['Content-Disposition'] = f'inline; filename="{filename}"'
        return response

    except Exception as e:
        import traceback
        print(f"Error serving receipt: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)


# ============================================
# TEST EMAIL ENDPOINT
# ============================================

@csrf_exempt
@require_http_methods(["GET"])
def test_email(request):
    """Test endpoint to verify email configuration"""
    try:
        # Get recipient email from query params or use default
        recipient = request.GET.get('email')

        if not recipient:
            # Try system settings first
            system_settings = get_system_settings_collection()
            settings_doc = system_settings.find_one({'key': 'app_settings'})
            if settings_doc:
                recipient = settings_doc.get('notification_email')

            # Fallback to Django settings
            if not recipient:
                recipient = getattr(settings, 'COLLECTIONS_TEAM_EMAIL', None)

        if not recipient:
            return JsonResponse({
                'success': False,
                'error': 'No recipient email configured. Set notification_email in SuperAdmin or pass ?email=your@email.com'
            }, status=400)

        # Log email settings for debugging
        email_config = {
            'EMAIL_HOST': settings.EMAIL_HOST,
            'EMAIL_PORT': settings.EMAIL_PORT,
            'EMAIL_USE_TLS': settings.EMAIL_USE_TLS,
            'EMAIL_HOST_USER': settings.EMAIL_HOST_USER,
            'DEFAULT_FROM_EMAIL': settings.DEFAULT_FROM_EMAIL,
            'recipient': recipient,
        }

        print(f"=== TEST EMAIL CONFIG ===")
        for key, value in email_config.items():
            print(f"{key}: {value}")
        print(f"=========================")

        # Try to send test email
        send_mail(
            subject='Test Email from Debtor Portal',
            message=f'''This is a test email from the Debtor Portal.

If you received this email, your email configuration is working correctly.

Email Settings:
- Host: {settings.EMAIL_HOST}
- Port: {settings.EMAIL_PORT}
- TLS: {settings.EMAIL_USE_TLS}
- From: {settings.DEFAULT_FROM_EMAIL}

Timestamp: {get_bangkok_time()} (Bangkok)
''',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
        )

        return JsonResponse({
            'success': True,
            'message': f'Test email sent successfully to {recipient}',
            'config': email_config
        })

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Test email failed: {error_details}")

        return JsonResponse({
            'success': False,
            'error': str(e),
            'details': error_details,
            'config': {
                'EMAIL_HOST': settings.EMAIL_HOST,
                'EMAIL_PORT': settings.EMAIL_PORT,
                'EMAIL_USE_TLS': settings.EMAIL_USE_TLS,
                'EMAIL_HOST_USER': settings.EMAIL_HOST_USER,
                'DEFAULT_FROM_EMAIL': settings.DEFAULT_FROM_EMAIL,
            }
        }, status=500)


# ============================================
# DEBTOR IMAGES ENDPOINTS
# ============================================

@csrf_exempt
@require_http_methods(["POST"])
def upload_debtor_images(request):
    """Upload debtor images or PDF files with QR codes to file system (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Get uploaded files
        files = request.FILES.getlist('images')

        if not files:
            return JsonResponse({'error': 'No files uploaded'}, status=400)

        debtor_images = get_debtor_images_collection()
        debtors = get_debtors_collection()

        uploaded_count = 0
        not_found_count = 0
        pdf_extracted_count = 0
        errors = []

        valid_image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp']

        for file in files:
            filename = file.name

            # Check if it's a PDF file
            if filename.lower().endswith('.pdf'):
                # Process PDF to extract QR codes
                if not PDF_PROCESSING_AVAILABLE:
                    errors.append(f'{filename}: PDF processing not available (install required libraries)')
                    continue

                print(f"Processing PDF file: {filename}")
                qr_results, pdf_errors = process_pdf_for_qr(file)
                errors.extend(pdf_errors)

                for account_number, qr_bytes in qr_results:
                    # Check if debtor exists
                    debtor = debtors.find_one({'account_number': account_number})
                    if not debtor:
                        not_found_count += 1
                        errors.append(f'{filename}: Account {account_number} not found in database')
                        continue

                    # Save QR image to disk (PNG format for better quality)
                    safe_filename = f"{account_number}.png"
                    file_path = IMAGES_DIR / safe_filename

                    # Delete existing images with different extensions
                    for old_ext in valid_image_extensions:
                        old_path = IMAGES_DIR / f"{account_number}{old_ext}"
                        if old_path.exists() and old_path != file_path:
                            old_path.unlink()

                    with open(file_path, 'wb') as f:
                        f.write(qr_bytes)

                    # Store metadata in MongoDB
                    debtor_images.update_one(
                        {'account_number': account_number},
                        {
                            '$set': {
                                'account_number': account_number,
                                'filename': safe_filename,
                                'content_type': 'image/png',
                                'file_path': str(file_path),
                                'uploaded_by': payload.get('username', 'admin'),
                                'uploaded_at': datetime.utcnow(),
                                'source': 'pdf_extraction',
                                'source_file': filename
                            }
                        },
                        upsert=True
                    )
                    pdf_extracted_count += 1
                    uploaded_count += 1

                continue

            # Regular image file processing
            # Extract account number from filename (remove extension)
            account_number = filename.rsplit('.', 1)[0].strip()

            # Validate file type
            file_ext = None
            for ext in valid_image_extensions:
                if filename.lower().endswith(ext):
                    file_ext = ext
                    break

            if not file_ext:
                errors.append(f'{filename}: Invalid file type (use PNG, JPG, GIF, WEBP, or PDF)')
                continue

            # Check if debtor exists
            debtor = debtors.find_one({'account_number': account_number})
            if not debtor:
                not_found_count += 1
                errors.append(f'{filename}: Account {account_number} not found')
                continue

            # Determine content type
            content_type = file.content_type or 'image/png'

            # Create safe filename (account_number + extension)
            safe_filename = f"{account_number}{file_ext}"
            file_path = IMAGES_DIR / safe_filename

            # Delete existing image if different extension
            for old_ext in valid_image_extensions:
                old_path = IMAGES_DIR / f"{account_number}{old_ext}"
                if old_path.exists() and old_path != file_path:
                    old_path.unlink()

            # Save file to disk
            with open(file_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            # Store metadata in MongoDB (not the image itself)
            debtor_images.update_one(
                {'account_number': account_number},
                {
                    '$set': {
                        'account_number': account_number,
                        'filename': safe_filename,
                        'content_type': content_type,
                        'file_path': str(file_path),
                        'uploaded_by': payload.get('username', 'admin'),
                        'uploaded_at': datetime.utcnow()
                    }
                },
                upsert=True
            )
            uploaded_count += 1

        # Build response message
        if pdf_extracted_count > 0:
            message = f'Successfully processed: {uploaded_count} QR images ({pdf_extracted_count} from PDF extraction)'
        else:
            message = f'Successfully uploaded {uploaded_count} images'

        return JsonResponse({
            'success': True,
            'message': message,
            'uploaded': uploaded_count,
            'pdf_extracted': pdf_extracted_count,
            'not_found': not_found_count,
            'errors': errors if errors else None
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_debtor_image(request, account_number):
    """Get debtor image data by account number (returns base64 for display)"""
    try:
        # Verify token (admin or debtor can access)
        auth_header = request.headers.get('Authorization')
        print(f"=== DEBUG AUTH ===")
        print(f"Auth header present: {auth_header is not None}")

        if not auth_header or not auth_header.startswith('Bearer '):
            print("No valid auth header")
            return JsonResponse({'error': 'Unauthorized - No token'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)
        print(f"Token payload: {payload}")

        if not payload:
            print("Token verification failed")
            return JsonResponse({'error': 'Unauthorized - Invalid token'}, status=401)

        # Check if user is authorized
        print(f"Role: {payload.get('role')}, Token accounts: {payload.get('account_numbers')}, Requested: {account_number}")
        if payload.get('role') == 'debtor':
            # Check both old format (single account_number) and new format (account_numbers list)
            account_numbers = payload.get('account_numbers', [])
            single_account = payload.get('account_number')
            if single_account:
                account_numbers.append(single_account)

            if account_number not in account_numbers:
                print("Account mismatch")
                return JsonResponse({'error': 'Unauthorized - Account mismatch'}, status=401)

        # First check database for image record
        debtor_images = get_debtor_images_collection()
        image_doc = debtor_images.find_one({'account_number': account_number})

        print(f"=== DEBUG get_debtor_image ===")
        print(f"Account: {account_number}")
        print(f"IMAGES_DIR: {IMAGES_DIR}")
        print(f"Image doc found: {image_doc is not None}")
        if image_doc:
            print(f"Filename in DB: {image_doc.get('filename')}")

        if image_doc:
            # Read image from file system and return as base64 for display
            filename = image_doc.get('filename')
            if filename:
                file_path = IMAGES_DIR / filename
                print(f"Looking for file: {file_path}")
                print(f"File exists: {file_path.exists()}")
                if file_path.exists():
                    with open(file_path, 'rb') as f:
                        image_data = base64.b64encode(f.read()).decode('utf-8')
                        return JsonResponse({
                            'success': True,
                            'image': {
                                'data': image_data,
                                'content_type': image_doc.get('content_type', 'image/png'),
                                'filename': filename
                            }
                        })

        # Fallback: Check file system directly for manually placed files
        valid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.PNG', '.JPG', '.JPEG', '.Jpg', '.Png']
        for ext in valid_extensions:
            file_path = IMAGES_DIR / f"{account_number}{ext}"
            if file_path.exists():
                # Determine content type
                ext_lower = ext.lower()
                content_type = 'image/png'
                if ext_lower in ['.jpg', '.jpeg']:
                    content_type = 'image/jpeg'
                elif ext_lower == '.gif':
                    content_type = 'image/gif'
                elif ext_lower == '.webp':
                    content_type = 'image/webp'

                with open(file_path, 'rb') as f:
                    image_data = base64.b64encode(f.read()).decode('utf-8')
                    return JsonResponse({
                        'success': True,
                        'image': {
                            'data': image_data,
                            'content_type': content_type,
                            'filename': f"{account_number}{ext}"
                        }
                    })

        return JsonResponse({
            'success': True,
            'image': None,
            'message': 'No image found for this account'
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def serve_debtor_image(request, account_number):
    """Serve actual image file for a debtor"""
    try:
        # Verify token (admin or debtor can access)
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Check if user is authorized
        if payload.get('role') == 'debtor':
            # Check both old format (single account_number) and new format (account_numbers list)
            account_numbers = payload.get('account_numbers', [])
            single_account = payload.get('account_number')
            if single_account:
                account_numbers.append(single_account)

            if account_number not in account_numbers:
                return JsonResponse({'error': 'Unauthorized'}, status=401)

        debtor_images = get_debtor_images_collection()
        image_doc = debtor_images.find_one({'account_number': account_number})

        if not image_doc:
            raise Http404("Image not found")

        # Find the image file
        filename = image_doc.get('filename')
        if filename:
            file_path = IMAGES_DIR / filename
            if file_path.exists():
                return FileResponse(
                    open(file_path, 'rb'),
                    content_type=image_doc.get('content_type', 'image/png')
                )

        raise Http404("Image file not found")

    except Http404:
        raise
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def get_debtor_images_batch(request):
    """Get image URLs for multiple debtors in one request (for lazy loading)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Get account numbers from query params
        account_numbers = request.GET.get('accounts', '').split(',')
        account_numbers = [a.strip() for a in account_numbers if a.strip()]

        if not account_numbers:
            return JsonResponse({'success': True, 'images': {}})

        debtor_images = get_debtor_images_collection()

        # Query all images at once
        images = list(debtor_images.find(
            {'account_number': {'$in': account_numbers}},
            {'_id': 0, 'account_number': 1, 'filename': 1, 'content_type': 1}
        ))

        # Build response dict
        result = {}
        for img in images:
            result[img['account_number']] = {
                'url': f'/api/admin/images/{img["account_number"]}/file/',
                'content_type': img.get('content_type', 'image/png'),
                'filename': img.get('filename')
            }

        return JsonResponse({
            'success': True,
            'images': result
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@require_http_methods(["DELETE"])
def delete_debtor_image(request, account_number):
    """Delete debtor image from file system (admin only)"""
    try:
        # Verify admin token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)

        if not payload or payload.get('role') not in ['admin', 'super_admin']:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        debtor_images = get_debtor_images_collection()
        image_doc = debtor_images.find_one({'account_number': account_number})

        # Delete file from disk if exists
        if image_doc and image_doc.get('filename'):
            file_path = IMAGES_DIR / image_doc['filename']
            if file_path.exists():
                file_path.unlink()

        # Delete metadata from MongoDB
        result = debtor_images.delete_one({'account_number': account_number})

        if result.deleted_count > 0:
            return JsonResponse({
                'success': True,
                'message': 'Image deleted successfully'
            })
        else:
            return JsonResponse({
                'success': True,
                'message': 'No image found to delete'
            })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
