from django.db import models
from django.contrib.auth.models import User

class ScanHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.TextField()
    verdict = models.CharField(max_length=20)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.url}"