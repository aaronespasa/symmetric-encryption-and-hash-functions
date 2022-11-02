from rest_framework import serializers
from .models import User, Password, Prescription

class PasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = '__all__'

class PrescriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Prescription
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'