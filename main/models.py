from django.db import models


# Create your models here.
# user chat models

class User(models.Model):
    login = models.CharField("Login", max_length=255)
    password = models.CharField("Password", max_length=255)

    def __str__(self):
        return self.login


class Chat(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chat_user_id', default='0')
    opponent_user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='opponent_user_id', default='0')
    latest_message_text = models.TextField("Latest Message")

    def __str__(self):
        return self.latest_message_text


class Message(models.Model):
    chat_id = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='chat_id', default='0')
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_id', default='0')
    sender_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender_id', default='0')
    message_text = models.TextField("Message")

    def __str__(self):
        return self.message_text
