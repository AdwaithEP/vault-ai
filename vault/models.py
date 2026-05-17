from django.db import models
from django.contrib.auth.models import User

class Password(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,related_name="vault_passwords")
    site_name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    password = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.site_name