from django.db import models


class Members(models.Model):
    class Meta:
        db_table = 'members'

    created_at = models.DateTimeField(auto_now_add=False)
    updated_at = models.DateTimeField(auto_now_add=False, null=True)
    user_id = models.CharField(null=True, max_length=30)
    user_pw = models.CharField(null=True, max_length=20)
    user_name = models.CharField(null=True, max_length=10)