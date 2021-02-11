import string
import urllib.parse

from base64 import b64encode
from base64 import b64decode
from django.shortcuts import render, redirect
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import binascii

from django.urls import reverse


def index(request):
    return render(request, 'main/index.html')


def encrypt_caesar(request):
    encrypted = request.GET.get('encrypted_text')
    plain_text = request.GET.get('plain_text')
    key = request.GET.get('key')
    data = {
        'encrypted_text': encrypted,
        'plain_text': plain_text,
        'key': key,
    }
    return render(request, 'main/index.html', data)


def encryptCaesar(request):
    global text
    encrypted = ""
    key = ""
    if request.method == 'POST':
        text = request.POST['plain_text']
        key = request.POST['key']
        print(text, key)
        for c in text:
            if c.isupper():
                c_ind = ord(c) - ord('A')
                print(c_ind)
                shift = (c_ind + int(key)) % 26 + ord('A')
                c_new = chr(shift)
                encrypted += c_new
            elif c.islower():
                c_ind = ord(c) - ord('a')
                shift = (c_ind + int(key)) % 26 + ord('a')
                c_new = chr(shift)
                encrypted += c_new
            elif c.isdigit():
                c_new = (int(c) + int(key)) % 10
                encrypted += str(c_new)
            else:
                encrypted += c
    data = {
        "encrypted_text": encrypted,
        "plain_text": text,
        "key": key
    }
    url = '{}?{}'.format(reverse('enc_text'), urllib.parse.urlencode(data))
    # return render(request, 'main/index.html', data)
    # return redirect('enc_text', data)
    return redirect(url)


def decrypt_caesar(request):
    decrypted = request.GET.get('decrypted_text')
    text1 = request.GET.get('cipher')
    key = request.GET.get('dec_key')
    data = {
        "decrypted_text": decrypted,
        "cipher": text1,
        "dec_key": key,
    }
    return render(request, 'main/index.html', data)


def decryptCaesar(request):
    global text
    decrypted = ""
    key = ""
    if request.method == 'POST':
        text = request.POST['decrypted_text']
        key = request.POST['key']
        for c in text:
            if c.isupper():
                ind = ord(c) - ord('A')
                pos = (ind - int(key)) % 26 + ord('A')
                p = chr(pos)
                decrypted += p
            elif c.islower():
                ind = ord(c) - ord('a')
                pos = (ind - int(key)) % 26 + ord('a')
                p = chr(pos)
                decrypted += p
            elif c.isdigit():
                pos = (int(c) - int(key)) % 10
                decrypted += str(pos)
            else:
                decrypted += c
    data = {
        "decrypted_text": decrypted,
        "cipher": text,
        "dec_key": key,
    }
    url = '{}?{}'.format(reverse('dec_text'), urllib.parse.urlencode(data))
    # return redirect(url+"#profile")
    return redirect(url)


def cipher_decrypt_lower(ciphertext, key):
    decrypted = ""

    for c in ciphertext:

        if c.islower():

            c_index = ord(c) - ord('a')

            c_og_pos = (c_index - key) % 26 + ord('a')

            c_og = chr(c_og_pos)

            decrypted += c_og

        else:

            decrypted += c

    return decrypted


def hack(request):
    texts = []
    t = []
    if request.method == 'POST':
        cryptic_text = request.POST['ciphertext']
        for i in range(0, 26):
            t = cipher_decrypt_lower(cryptic_text, i)
            texts.append(t)
            texts.sort()
    return render(request, 'main/index.html', {"texts": texts})


def vigenere_encrypt(request):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    enc_string = ""
    input_string = ""
    enc_key = ""
    if request.method == 'POST':
        # Takes encrpytion key from user
        enc_key = request.POST['code']
        enc_key = enc_key.lower()

        # Takes string from user
        input_string = request.POST['plain_text']
        input_string = input_string.lower()

        # Lengths of input_string
        string_length = len(input_string)

        # Expands the encryption key to make it longer than the inputted string
        expanded_key = enc_key
        expanded_key_length = len(expanded_key)

        while expanded_key_length < string_length:
            # Adds another repetition of the encryption key
            expanded_key = expanded_key + enc_key
            expanded_key_length = len(expanded_key)

        key_position = 0

        for letter in input_string:
            if letter in alphabet:
                # cycles through each letter to find it's numeric position in the alphabet
                position = alphabet.find(letter)
                # moves along key and finds the characters value
                key_character = expanded_key[key_position]
                key_character_position = alphabet.find(key_character)
                key_position = key_position + 1
                # changes the original of the input string character
                new_position = position + key_character_position
                if new_position > 26:
                    new_position = new_position - 26
                new_character = alphabet[new_position]
                enc_string = enc_string + new_character
            else:
                enc_string = enc_string + letter

    data = {
        "encrypted": enc_string,
        "plain_text": input_string,
        "code": enc_key,
    }
    print(data)
    return render(request, 'main/vigenere.html', data)


def vigenere_decrypt(request):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    input_string = ""
    dec_key = ""
    dec_string = ""

    if request.method == 'POST':
        # Takes encrpytion key from user
        dec_key = request.POST['code']
        dec_key = dec_key.lower()

        # Takes string from user
        input_string = request.POST['decrypted_text']
        input_string = input_string.lower()

        # Lengths of input_string
        string_length = len(input_string)

        # Expands the encryption key to make it longer than the inputted string
        expanded_key = dec_key
        expanded_key_length = len(expanded_key)

        while expanded_key_length < string_length:
            # Adds another repetition of the encryption key
            expanded_key = expanded_key + dec_key
            expanded_key_length = len(expanded_key)

        key_position = 0

        for letter in input_string:
            if letter in alphabet:
                # cycles through each letter to find it's numeric position in the alphabet
                position = alphabet.find(letter)
                # moves along key and finds the characters value
                key_character = expanded_key[key_position]
                key_character_position = alphabet.find(key_character)
                key_position = key_position + 1
                # changes the original of the input string character
                new_position = position - key_character_position
                if new_position > 26:
                    new_position = new_position + 26
                new_character = alphabet[new_position]
                dec_string = dec_string + new_character
            else:
                dec_string = dec_string + letter

    data = {
        "decrypted": dec_string,
        "cipher": input_string,
        "dec_code": dec_key,
    }
    return render(request, 'main/vigenere.html', data)


def playfair_key(key):
    alphabet = string.ascii_lowercase.replace('j', '.')
    code = key
    key_matrix = ['' for i in range(5)]
    i, j = 0, 0
    for c in code:
        if c in alphabet:
            key_matrix[i] += c
            alphabet = alphabet.replace(c, '.')
            j += 1
            if j > 4:
                i += 1
                j = 0

    for c in alphabet:
        if c != '.':
            key_matrix[i] += c
            j += 1
            if j > 4:
                i += 1
                j = 0
    return key_matrix


def playfair_encrypt(request):
    plain_text = ""
    plain_text_pair = []
    cipher_text_pair = []
    code = ""
    if request.method == 'POST':
        code = request.POST['code']
        plain_text = request.POST['plain_text']
        print(code)
        key_matrix = playfair_key(code)
        i = 0
        while i < len(plain_text):
            a = plain_text[i]
            b = ''
            if (i + 1) == len(plain_text):
                b = 'x'
            else:
                b = plain_text[i + 1]
            if a != b:
                plain_text_pair.append(a + b)
                i += 2
            else:
                plain_text_pair.append(a + 'x')
                i += 1
        for pair in plain_text_pair:
            rule = False
            for row in key_matrix:
                if pair[0] in row and pair[1] in row:
                    j0 = row.find(pair[0])
                    j1 = row.find(pair[1])

                    text_pair = row[(j0 + 1) % 5] + row[(j1 + 1) % 5]
                    cipher_text_pair.append(text_pair)
                    rule = True

            if rule:
                continue
            for j in range(5):
                col = "".join([key_matrix[i][j] for i in range(5)])
                if pair[0] in col and pair[1] in col:
                    i0 = col.find(pair[0])
                    i1 = col.find(pair[1])
                    text_pair = col[(i0 + 1) % 5] + col[(i1 + 1) % 5]
                    cipher_text_pair.append(text_pair)
                    rule = True
            if rule:
                continue
            i0, i1, j0, j1 = 0, 0, 0, 0
            for i in range(5):
                row = key_matrix[i]
                if pair[0] in row:
                    i0 = i
                    j0 = row.find(pair[0])

                if pair[1] in row:
                    i1 = i
                    j1 = row.find(pair[1])
            text_pair = key_matrix[i0][j1] + key_matrix[i1][j0]
            cipher_text_pair.append(text_pair)

    data = {
        "encrypted": "".join(cipher_text_pair),
        "plain_text": "".join(plain_text_pair),
        "code": code,
    }

    print(data)

    return render(request, 'main/playfair.html', data)


def playfair_decrypt(request):
    cipher_text = ""
    plain_text_pair = []
    cipher_text_pair = []
    code = ""

    if request.method == 'POST':
        code = request.POST['code']
        plain_text = ""
        cipher_text = request.POST['decrypted_text']
        print(code)
        key_matrix = playfair_key(code)
        i = 0
        while i < len(cipher_text):
            a = cipher_text[i]
            b = cipher_text[i + 1]
            cipher_text_pair.append(a + b)
            i += 2
        for pair in cipher_text_pair:
            rule = False
            for row in key_matrix:
                if pair[0] in row and pair[1] in row:
                    j0 = row.find(pair[0])
                    j1 = row.find(pair[1])

                    text_pair = row[(j0 + 4) % 5] + row[(j1 + 4) % 5]
                    plain_text_pair.append(text_pair)
                    rule = True

            if rule:
                continue
            for j in range(5):
                col = "".join([key_matrix[i][j] for i in range(5)])
                if pair[0] in col and pair[1] in col:
                    i0 = col.find(pair[0])
                    i1 = col.find(pair[1])
                    text_pair = col[(i0 + 4) % 5] + col[(i1 + 4) % 5]
                    plain_text_pair.append(text_pair)
                    rule = True
            if rule:
                continue
            i0, i1, j0, j1 = 0, 0, 0, 0
            for i in range(5):
                row = key_matrix[i]
                if pair[0] in row:
                    i0 = i
                    j0 = row.find(pair[0])

                if pair[1] in row:
                    i1 = i
                    j1 = row.find(pair[1])
            text_pair = key_matrix[i0][j1] + key_matrix[i1][j0]
            plain_text_pair.append(text_pair)

    data = {
        "to_decrypt": "".join(cipher_text_pair),
        "result": "".join(plain_text_pair),
        "dec_code": code,
    }

    print(data)

    return render(request, 'main/playfair.html', data)


def transposition_encrypt(request):
    ciphertext = ""
    message = ""
    keyword = ""

    if request.method == 'POST':
        keyword = request.POST['code']
        message = request.POST['plain_text']
        matrix = createEncMatrix(len(keyword), message)
        keywordSequence = getKeywordSequence(keyword)

        for num in range(len(keywordSequence)):
            pos = keywordSequence.index(num + 1)
            for row in range(len(matrix)):
                if len(matrix[row]) > pos:
                    ciphertext += matrix[row][pos]

    data = {
        "plain_text": message,
        "code": keyword,
        "encrypted": ciphertext,

    }
    return render(request, 'main/transposition.html', data)


def createEncMatrix(width, message):
    r = 0
    c = 0
    matrix = [[]]
    for pos, ch in enumerate(message):
        matrix[r].append(ch)
        c += 1
        if c >= width:
            c = 0
            r += 1
            matrix.append([])

    return matrix


def getKeywordSequence(keyword):
    sequence = []
    for pos, ch in enumerate(keyword):
        previousLetters = keyword[:pos]
        newNumber = 1
        for previousPos, previousCh in enumerate(previousLetters):
            if previousCh > ch:
                sequence[previousPos] += 1
            else:
                newNumber += 1
        sequence.append(newNumber)
    return sequence


def transposition_decrypt(request):
    plaintext = ""
    message = ""
    keyword = ""

    if request.method == 'POST':
        message = request.POST['text_cipher']
        keyword = request.POST['code']

        matrix = createDecrMatrix(getKeywordSequence(keyword), message)
        for r in range(len(matrix)):
            for c in range(len(matrix[r])):
                plaintext += matrix[r][c]

    data = {
        "cipher": message,
        "dec_code": keyword,
        "decrypted": plaintext,
    }
    return render(request, 'main/transposition.html', data)


def createDecrMatrix(keywordSequence, message):
    width = len(keywordSequence)
    height = int(len(message) / width)
    if height * width < len(message):
        height += 1

    matrix = createEmptyMatrix(width, height, len(message))

    pos = 0
    for num in range(len(keywordSequence)):
        column = keywordSequence.index(num + 1)

        r = 0
        while (r < len(matrix)) and (len(matrix[r]) > column):
            matrix[r][column] = message[pos]
            r += 1
            pos += 1

    return matrix


def createEmptyMatrix(width, height, length):
    matrix = []
    totalAdded = 0
    for r in range(height):
        matrix.append([])
        for c in range(width):
            if totalAdded >= length:
                return matrix
            matrix[r].append('')
            totalAdded += 1
    return matrix


def getKeywordSequence(keyword):
    sequence = []
    for pos, ch in enumerate(keyword):
        previousLetters = keyword[:pos]
        newNumber = 1
        for previousPos, previousCh in enumerate(previousLetters):
            if previousCh > ch:
                sequence[previousPos] += 1
            else:
                newNumber += 1
        sequence.append(newNumber)
    return sequence


def blowfish_all(request):
    return render(request, 'main/blowfish.html')


def PKCS5Padding(string):
    byteNum = len(string)
    packingLength = 8 - byteNum % 8
    appendage = chr(packingLength) * packingLength
    return string + appendage


def blowfish_ecb_enc(request):
    plain_text = ""
    code = ""
    encrypted = ""
    if request.method == 'POST':
        plain_text = request.POST['plain_text']
        code = request.POST['code']
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_ECB)
        packed = PKCS5Padding(plain_text)
        encrypted = cipher.encrypt(pad(str.encode(plain_text), Blowfish.block_size))
        # encrypted = cipher.encrypt(str.encode(packed))
    data = {
        "plain_ecb": plain_text,
        "code_ecb": code,
        "encrypted_ecb": binascii.hexlify(encrypted).decode('utf-8'),
    }

    return render(request, 'main/blowfish.html', data)


def blowfish_ecb_dec(request):
    cipher_text = ""
    code = ""
    result_ecb = ""
    if request.method == 'POST':
        cipher_text = request.POST['cipher_text']
        code = request.POST['code']
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_ECB)
        res = binascii.unhexlify(cipher_text)
        result_ecb = unpad(cipher.decrypt(res), Blowfish.block_size)
        # result_ecb = result_ecb.decode('windows-1252')

    data = {
        "cipher_text": cipher_text,
        "dec_code_ecb": code,
        "result_ecb": result_ecb.decode(),
    }

    print(data)
    return render(request, 'main/blowfish.html', data)


def blowfish_cbc_enc(request):
    plain_text = ""
    code = ""
    encrypted = ""
    iv = ""
    if request.method == 'POST':
        plain_text = request.POST['plain_text']
        code = request.POST['code']
        if len(code) < 4:
            err = "Enter more than 4 length key or equal"
            return render(request, 'main/blowfish.html', {"err": err})
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_CBC)
        encrypted = cipher.encrypt(pad(str.encode(plain_text), Blowfish.block_size))
        print(cipher.iv)
        print(b64encode(cipher.iv).decode('utf-8'))
        print(b64encode(encrypted).decode('utf-8'))
        iv = b64encode(cipher.iv).decode('utf-8')
        encrypted = b64encode(encrypted).decode('utf-8')
    data = {
        "plain_cbc": plain_text,
        "code_cbc": code,
        "encrypted_cbc": iv + encrypted,
    }
    # binascii.hexlify(encrypted).decode('utf-8')
    return render(request, 'main/blowfish.html', data)


def blowfish_cbc_dec(request):
    cipher_text = ""
    code = ""
    result_ecb = ""
    if request.method == 'POST':
        cipher_text = request.POST['cipher_text']
        code = request.POST['code']
        iv = b64decode('4Ev6B+omCFY=')
        ct = b64decode('ALBbii0J7JAG34QcPjVJW2qXSoWE7QnDU6ZP3vs/sF4=')
        ivtest = cipher_text[:12]
        cipher_text = cipher_text[12:]
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_CBC, b64decode(ivtest))
        print(cipher_text)
        res = b64decode(cipher_text)
        result_ecb = unpad(cipher.decrypt(res), Blowfish.block_size)
        # result_ecb = result_ecb.decode('windows-1252')

    data = {
        "cipher_text_cbc": cipher_text,
        "dec_code_cbc": code,
        "result_cbc": result_ecb.decode(),
    }

    print(data)
    return render(request, 'main/blowfish.html', data)


def blowfish_cfb_enc(request):
    plain_text = ""
    code = ""
    encrypted = ""
    iv = ""
    if request.method == 'POST':
        plain_text = request.POST['plain_text']
        code = request.POST['code']
        if len(code) < 4:
            err = "Enter more than 4 length key or equal"
            return render(request, 'main/blowfish.html', {"err": err})
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_CFB)
        encrypted = cipher.encrypt(str.encode(plain_text))
        print(cipher.iv)
        print(b64encode(cipher.iv).decode('utf-8'))
        print(b64encode(encrypted).decode('utf-8'))
        iv = b64encode(cipher.iv).decode('utf-8')
        encrypted = b64encode(encrypted).decode('utf-8')
    data = {
        "plain_cfb": plain_text,
        "code_cfb": code,
        "encrypted_cfb": iv + encrypted,
    }
    # binascii.hexlify(encrypted).decode('utf-8')
    return render(request, 'main/blowfish.html', data)


def blowfish_cfb_dec(request):
    cipher_text = ""
    code = ""
    result_ecb = ""
    if request.method == 'POST':
        cipher_text = request.POST['cipher_text']
        code = request.POST['code']
        iv = cipher_text[:12]
        cipher_text = cipher_text[12:]
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_CFB, iv=b64decode(iv))
        print(cipher_text)
        res = b64decode(cipher_text)
        result_ecb = cipher.decrypt(res)
        # result_ecb = result_ecb.decode('windows-1252')

    data = {
        "cipher_text_cfb": cipher_text,
        "dec_code_cfb": code,
        "result_cfb": result_ecb.decode(),
    }

    print(data)
    return render(request, 'main/blowfish.html', data)


def blowfish_ofb_enc(request):
    plain_text = ""
    code = ""
    encrypted = ""
    iv = ""
    if request.method == 'POST':
        plain_text = request.POST['plain_text']
        code = request.POST['code']
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_OFB)
        encrypted = cipher.encrypt(str.encode(plain_text))
        print(cipher.iv)
        print(b64encode(cipher.iv).decode('utf-8'))
        print(b64encode(encrypted).decode('utf-8'))
        iv = b64encode(cipher.iv).decode('utf-8')
        encrypted = b64encode(encrypted).decode('utf-8')
    data = {
        "plain_ofb": plain_text,
        "code_ofb": code,
        "encrypted_ofb": iv + encrypted,
    }
    # binascii.hexlify(encrypted).decode('utf-8')
    return render(request, 'main/blowfish.html', data)


def blowfish_ofb_dec(request):
    cipher_text = ""
    code = ""
    result_ecb = ""
    if request.method == 'POST':
        cipher_text = request.POST['cipher_text']
        code = request.POST['code']
        iv = cipher_text[:12]
        cipher_text = cipher_text[12:]
        cipher = Blowfish.new(str.encode(code), Blowfish.MODE_OFB, iv=b64decode(iv))
        print(cipher_text)
        res = b64decode(cipher_text)
        result_ecb = cipher.decrypt(res)
        # result_ecb = result_ecb.decode('windows-1252')

    data = {
        "cipher_text_ofb": cipher_text,
        "dec_code_ofb": code,
        "result_ofb": result_ecb.decode(),
    }

    print(data)
    return render(request, 'main/blowfish.html', data)



