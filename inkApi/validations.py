from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
UserModel = get_user_model()


def custom_validation(data):
    errors = {}

    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not email or UserModel.objects.filter(email=email).exists():
        errors['email'] = 'Choose another email'

    if not password or len(password) < 8:
        errors['password'] = 'Choose another password, min 8 characters'

    if not username or UserModel.objects.filter(username=username).exists():
        errors['username'] = 'Choose another username'

    if errors:
        return errors
    else:
        return data


def is_strong_password(password):
    if len(password) < 8:
        return False

    if not any(char.isupper() for char in password):
        return False

    if not any(char.isdigit() for char in password):
        return False

    special_characters = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?"
    if not any(char in special_characters for char in password):
        return False

    return True


def validate_email(data):
    email = data['email'].strip()
    if not email:
        raise ValidationError('an email is needed')
    return True


def validate_username(data):
    username = data['username'].strip()
    if not username:
        raise ValidationError('choose another username')
    return True


def validate_password(data):
    password = data['password'].strip()
    if not password:
        raise ValidationError('a password is needed')
    return True
