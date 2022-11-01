from django.db import models

class Password(models.Model):
    id = models.AutoField(primary_key=True)
    password_key = models.CharField(max_length=255)
    password_iv = models.CharField(max_length=255)
    password_ciphertext = models.CharField(max_length=255)

    def __str__(self):
        return self.password

class Prescription(models.Model):
    id = models.AutoField(primary_key=True)
    prescription_key = models.CharField(max_length=255)
    prescription_iv = models.CharField(max_length=255)
    prescription_ciphertext = models.CharField(max_length=255)

    def __str__(self):
        return self.prescription

class User(models.Model):
    class Meta:
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"
    user = models.CharField(max_length=255, unique=True, primary_key=True)
    password = models.ForeignKey(Password, on_delete=models.CASCADE)
    password_salt = models.CharField(max_length=255)
    prescription = models.ForeignKey(Prescription, on_delete=models.CASCADE)

    def __str__(self):
        return self.user