"""djangoProject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from . import views

urlpatterns = [
    # caesar
    path('', views.index, name='home'),
    path('enc', views.encryptCaesar, name='encrypt'),
    path('enc_caesar', views.encrypt_caesar, name="enc_text"),
    path('dec', views.decryptCaesar, name='decrypt'),
    path('dec_caesar', views.decrypt_caesar, name='dec_text'),
    path('hack', views.hack, name='hack'),

    # vigenere
    path('vigenere_enc', views.vigenere_encrypt, name='vigenere_enc'),
    path('vigenere_dec', views.vigenere_decrypt, name='vigenere_dec'),

    # playfair cipher
    path('playfair_enc', views.playfair_encrypt, name='playfair_enc'),
    path('playfair_dec', views.playfair_decrypt, name='playfair_dec'),

    # transposition
    path('transposition_enc', views.transposition_encrypt, name='transposition_enc'),
    path('transposition_dec', views.transposition_decrypt, name='transposition_decrypt'),

    # blowfish
    path('blowfish', views.blowfish_all, name='blowfish'),
    path('blowfish_ecb_enc', views.blowfish_ecb_enc, name='blowfish_ecb_enc'),
    path('blowfish_ecb_dec', views.blowfish_ecb_dec, name='blowfish_ecb_dec'),
    path('blowfish_cbc_enc', views.blowfish_cbc_enc, name='blowfish_cbc_enc'),
    path('blowfish_cbc_dec', views.blowfish_cbc_dec, name='blowfish_cbc_dec'),
    path('blowfish_cfb_enc', views.blowfish_cfb_enc, name='blowfish_cfb_enc'),
    path('blowfish_cfb_dec', views.blowfish_cfb_dec, name='blowfish_cfb_dec'),
    path('blowfish_ofb_enc', views.blowfish_ofb_enc, name='blowfish_ofb_enc'),
    path('blowfish_ofb_dec', views.blowfish_ofb_dec, name='blowfish_ofb_dec'),

    # rsa
    path('rsa_encrypt', views.rsa_encrypt, name="rsa_encrypt"),
    path('rsa_decrypt', views.rsa_decrypt, name="rsa_decrypt"),
]
