from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model,authenticate, login
from django.core.cache import cache
from django.utils.crypto import get_random_string
from datetime import timedelta
from django.utils import timezone
from .serializers import *
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.cache import cache
from .models import CustomUser
from django.utils.crypto import get_random_string


CustomUser  = get_user_model()

# Rate limit parameters (example: 5 requests in 5 minutes)
OTP_RATE_LIMIT = {
    'MAX_REQUESTS': 5,
    'TIME_WINDOW': timedelta(minutes=2)
}


#TO send otp to both email and mobile number
class RegistrationView(APIView):
    """Handles user registration and OTP generation and verification."""
    
    def post(self, request):
        registration_serializer = RegistrationSerializer(data=request.data)
        
        if registration_serializer.is_valid():
            data = registration_serializer.validated_data
            mobile_number = data['mobile_number']
            email = data.get('email')  # Get the email address if provided
            
            # Check if the user exceeded OTP rate limits
            rate_limit_key = f"otp_rate_limit_{mobile_number}"
            requests_made = cache.get(rate_limit_key, 0)
            if requests_made >= OTP_RATE_LIMIT['MAX_REQUESTS']:
                reset_time = cache.get(f"otp_rate_limit_reset_time_{mobile_number}")
                if reset_time:
                    remaining_time = reset_time - timezone.now()
                    return Response({"rate_limit": f"Too many OTP requests. Try again after {remaining_time}."}, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP and store it in cache
            otp = get_random_string(length=4, allowed_chars='0123456789')
            cache_key = f"otp_{mobile_number}"
            cache.set(cache_key, {"otp": otp, "user_data": data}, timeout=300)  # Store OTP for 5 minutes
            
            # Send OTP via SMS
            message = f"Your OTP for registration is: {otp}"
            send_sms(mobile_number, message,"signup")

            # Send OTP via Email if email is provided
            if email:
                email_subject = "Your OTP for Registration"
                email_message = f"Dear User,\n\nYour OTP for registration with Only2Bali is: {otp}\n\nPlease use this OTP to complete your signup process.\n\nBest regards,\nOnly2Bali Team"

                send_mail(
                    email_subject,
                    email_message,
                    settings.DEFAULT_FROM_EMAIL,  # Make sure to define DEFAULT_FROM_EMAIL in settings.py
                    [email],
                    fail_silently=False,
                )

            # Increment OTP request count and set reset time
            cache.set(rate_limit_key, requests_made + 1, timeout=OTP_RATE_LIMIT['TIME_WINDOW'].seconds)
            cache.set(f"otp_rate_limit_reset_time_{mobile_number}", timezone.now() + OTP_RATE_LIMIT['TIME_WINDOW'], timeout=OTP_RATE_LIMIT['TIME_WINDOW'].seconds)
            
            return Response({"message": "OTP sent successfully to your mobile number and email address."}, status=status.HTTP_200_OK)

        return Response(registration_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPVerificationView(APIView):
    """Handles OTP verification and user creation."""
    def post(self, request,mobile_number):
        # otp_serializer = OTPVerificationSerializer(data=request.data, context={'view': self})
        otp_serializer = OTPVerificationSerializer(
    data=request.data,
    context={'mobile_number': mobile_number}
)


        if otp_serializer.is_valid():
          #  mobile_number = otp_serializer.validated_data.get('mobile_number')
            otp = otp_serializer.validated_data.get('otp')

            # Retrieve OTP data from cache
            cache_key = f"otp_{mobile_number}"
            cached_data = cache.get(cache_key)

            if not cached_data:
                return Response({"error": "OTP has expired or is invalid."}, status=status.HTTP_400_BAD_REQUEST)

            # Verify OTP
            if cached_data['otp'] != otp:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Create the user after OTP verification
            user_data = cached_data['user_data']
            user = CustomUser .objects.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],  # Make sure password is hashed
                mobile_number=user_data['mobile_number']
            )

            return Response({"message": "User  registered successfully."}, status=status.HTTP_201_CREATED)
        else:
            return Response(otp_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class PasswordResetRequestView(APIView):
    """Handle password reset request by sending a reset email with a token."""

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = CustomUser.objects.filter(email=email).first()

            if user:
                # Generate token for password reset
                token = default_token_generator.make_token(user)
                
                # Generate UID (User ID) encoded in base64
                uid = urlsafe_base64_encode(str(user.pk).encode())
                

                
                reset_url = f"https://only2bali.com/reset-password/{uid}/{token}/" 
                # reset_url = f"{settings.react_ip}/reset-password/{uid}/{token}/"
                
                # Send the reset email
                subject = "Password Reset Request"
                message = f"Hello {user.username},\n\nYou can reset your password using the following link: {reset_url}\n\nIf you did not request this, please ignore this email."
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            return Response({"message": "If the email is registered, a password reset link will be sent."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class PasswordResetVerifyView(APIView):
    """Handle password reset using the token in the reset URL."""

    def post(self, request):
        serializer = PasswordResetVerifySerializer(data=request.data)
        
        if serializer.is_valid():
            uid = serializer.validated_data['uid']
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            try:
                # Decode the user ID
                user_id = urlsafe_base64_decode(uid).decode()
                user = CustomUser.objects.get(id=user_id)
                
                # Validate the token
                if not default_token_generator.check_token(user, token):
                    return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

                # Set new password
                user.set_password(new_password)
                user.save()

                return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

            except CustomUser.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileView(APIView):
    """Retrieve the profile details of the authenticated user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # Get the authenticated user
        serializer = UserProfileSerializer(user)  # Serialize the user data
        return Response(serializer.data)  # Send the serialized data as response
    
class UserProfileUpdateView(APIView):
    """Allow users to update their profile."""
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        data = request.data

        # Validate uniqueness of email and mobile number
        if 'email' in data and CustomUser.objects.filter(email=data['email']).exclude(id=user.id).exists():
            return Response({"error": "Email is already in use."}, status=status.HTTP_400_BAD_REQUEST)
        if 'mobile_number' in data and CustomUser.objects.filter(mobile_number=data['mobile_number']).exclude(id=user.id).exists():
            return Response({"error": "Mobile number is already in use."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Update user details
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.mobile_number = data.get('mobile_number', user.mobile_number)
        user.dob = data.get('dob', user.dob)
        user.gender=data.get('gender',user.gender)
        user.save()

        return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    Handles logout by blacklisting the refresh token (for JWT authentication).
    """
    def post(self, request):
        try:
            # Get the refresh token from the request data (sent in the request body)
            refresh_token = request.data.get('refresh', None)

            if refresh_token:
                # Blacklist the refresh token to prevent further use
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }



#To send otp to both email and mobile number
class LoginView(APIView):
    """
    Handles login via password or OTP.
    Returns JWT tokens upon successful authentication.
    """
    def post(self, request):
        login_type = request.data.get('login_type', 'password')  # Default to password login
        identifier = request.data.get('identifier')  # Email or mobile number
        password = request.data.get('password', None)
        otp = request.data.get('otp', None)

        if login_type == 'password':
            # Authenticate using email or mobile number and password
            user = CustomUser.objects.filter(email=identifier).first() or CustomUser.objects.filter(mobile_number=identifier).first()
            if user:
                user = authenticate(username=user.username, password=password)
                if user:
                    tokens = get_tokens_for_user(user)
                    return Response({"message": "Logged in successfully.", "tokens": tokens}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        elif login_type == 'otp':
            # Handle OTP generation or resend
            if otp is None:
                # Generate OTP if not provided
                user = None
                
                # Check if the identifier is a mobile number or email
                # Strip the '+' from the mobile number before checking
                cleaned_identifier = identifier.lstrip('+')

                if cleaned_identifier.isdigit():  # Check if the identifier is a mobile number (simplified check)
                    user = CustomUser.objects.filter(mobile_number=identifier).first()  # Use the original identifier with + if it's mobile
                elif '@' in identifier:  # Check if the identifier is an email
                    user = CustomUser.objects.filter(email=identifier).first()

                if user:
                    otp = get_random_string(length=4, allowed_chars='0123456789')
                    cache_key = f"otp_{identifier}"

                    # Clear old OTP data if it exists
                    cache.delete(cache_key)

                    # Cache the new OTP for 5 minutes
                    cache.set(cache_key, {"otp": otp, "user_id": user.id}, timeout=300)
                    
                    # Send OTP to the appropriate channel
                    if cleaned_identifier.isdigit():  # If it's a mobile number, send SMS
                        send_sms(user.mobile_number, otp,"signin")  # Pass the number with or without '+' as required by your service
                    elif '@' in identifier:  # If it's an email, send email
                        email_subject = "Your OTP for login"
                        email_message = f"Your OTP for login is: {otp}"
                        send_mail(
                            email_subject,
                            email_message,
                            settings.DEFAULT_FROM_EMAIL,  # Use your default from email in settings.py
                            [user.email],  # Send to user's email
                            fail_silently=False,
                        )
                    
                    return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)

                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            # Verify OTP
            cache_key = f"otp_{identifier}"
            cached_data = cache.get(cache_key)
            if cached_data and cached_data['otp'] == otp:
                user = CustomUser.objects.get(id=cached_data['user_id'])
                tokens = get_tokens_for_user(user)
                return Response({"message": "Logged in successfully.", "tokens": tokens}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid OTP."}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({"error": "Invalid login type."}, status=status.HTTP_400_BAD_REQUEST)



# FAQ for zoho desk

# ZOHO API Configuration - Credentials from environment variables
ZOHO_API_URL = "https://desk.zoho.com/api/v1/tickets"
ZOHO_CLIENT_ID = os.getenv("ZOHO_CLIENT_ID")
ZOHO_CLIENT_SECRET = os.getenv("ZOHO_CLIENT_SECRET")
ZOHO_REFRESH_TOKEN = os.getenv("ZOHO_REFRESH_TOKEN")
ZOHO_ACCESS_TOKEN = os.getenv("ZOHO_ACCESS_TOKEN")
ZOHO_DEPARTMENT_ID = os.getenv("ZOHO_DEPARTMENT_ID")

class SendToZohoAPIView(APIView):
    def get_access_token(self):
        """
        Function to get a new access token using the refresh token.
        """
        refresh_url = "https://accounts.zoho.com/oauth/v2/token"
        data = {
            "client_id": ZOHO_CLIENT_ID,
            "client_secret": ZOHO_CLIENT_SECRET,
            "refresh_token": ZOHO_REFRESH_TOKEN,
            "grant_type": "refresh_token"
        }

        try:
            response = requests.post(refresh_url, data=data)
            response_data = response.json()
            if response.status_code == 200:
                return response_data["access_token"]
            else:
                raise Exception("Failed to refresh the access token")
        except Exception as e:
            raise Exception(f"Error refreshing access token: {e}")

    def post(self, request):
        # Retrieve the form data from the request
        name = request.data.get('name')
        email = request.data.get('email')
        subject = request.data.get('subject')
        message = request.data.get('message')

        # Ensure the 'name' parameter is provided and valid
        if not name:
            return Response({"error": "'name' parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Handle splitting of the name safely (first_name only)
        name_parts = name.split() if name else []
        first_name = name_parts[0] if len(name_parts) > 0 else ""

        # Get access token (if expired, refresh it)
        access_token = ZOHO_ACCESS_TOKEN
        try:
            # Send the data to Zoho Desk
            zoho_data = {
                "subject": subject,
                "description": message,
                "contact": {
                    # "first_name": first_name,
                    "email": email
                },
                "departmentId": ZOHO_DEPARTMENT_ID  # Add the departmentId here
            }

            headers = {
                'Authorization': f'Zoho-oauthtoken {access_token}',
                'Content-Type': 'application/json'
            }

            # Attempt to send data to Zoho Desk
            response = requests.post(ZOHO_API_URL, json=zoho_data, headers=headers)

            if response.status_code == 401:  # Unauthorized, token may have expired
                access_token = self.get_access_token()  # Refresh token
                headers['Authorization'] = f'Zoho-oauthtoken {access_token}'  # Update the headers with the new access token

                # Retry the request after refreshing the token
                response = requests.post(ZOHO_API_URL, json=zoho_data, headers=headers)

            if response.status_code in [200, 201]:
                return Response({"success": True}, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": "Failed to create ticket in Zoho Desk", "details": response.json()}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


