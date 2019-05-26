import os
import peewee as pw
import datetime
from playhouse.postgres_ext import PostgresqlExtDatabase
from flask_login import UserMixin

db = PostgresqlExtDatabase(os.getenv('DATABASE'))

class BaseModel(pw.Model):
    created_at = pw.DateTimeField(default=datetime.datetime.now)
    updated_at = pw.DateTimeField(default=datetime.datetime.now)

    def save(self, *args, **kwargs):
        self.updated_at = datetime.datetime.now()
        return super(BaseModel, self).save(*args, **kwargs)

    class Meta:
        database = db
        legacy_table_names = False

class User(BaseModel, UserMixin):
    name = pw.CharField(unique=True)
    email = pw.CharField(unique=True)
    password = pw.CharField(null=True)
    amount = pw.DecimalField(unique=False, default=0)