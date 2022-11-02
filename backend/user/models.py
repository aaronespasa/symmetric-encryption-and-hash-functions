from django.db import models

class Password(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=255)
    iv = models.CharField(max_length=255)
    ciphertext = models.CharField(max_length=256)
    salt = models.CharField(max_length=255)

    def __str__(self):
        return str(self.id)

class Prescription(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=255)
    iv = models.CharField(max_length=255)
    ciphertext = models.CharField(max_length=256)

    def __str__(self):
        return str(self.id)

class User(models.Model):
    class Meta:
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"
    user = models.CharField(max_length=255, unique=True, primary_key=True)
    password = models.ForeignKey(Password, on_delete=models.CASCADE)
    prescription = models.ForeignKey(Prescription, on_delete=models.CASCADE)

    def __str__(self):
        return self.user