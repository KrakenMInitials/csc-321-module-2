from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from task1_main import encrypt_with_cbc, encrypt_with_ecb
from urllib.parse import quote, unquote

KEY_LEN_PLACEHOLDER = int(128/8)

key = get_random_bytes(KEY_LEN_PLACEHOLDER)  
iv = get_random_bytes(KEY_LEN_PLACEHOLDER)

def decrypt_with_cbc(iv: bytes, ciphertext: bytes):
    #function not modular because it unpads and decode utf-8
    cipher_cpc = AES.new(key, AES.MODE_ECB)
    
    cipherblocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)] 
    plaintext_blocks = []
    
    #Process for CBC decryption:
    #   for decrypting ciphertext block Cn:
    #       X = cipher.decrypt(Cn) // X is a placeholder
    #       Let plaintext block Pn = X xor <previous ciphertext block>
    #!Note that after decryption, X is xor with the previous "ciphertext" block
    # and not the previous decrypted/plaintext block   
    
    previous_block = iv
    for blocks in cipherblocks:
        decrypted_block = cipher_cpc.decrypt(blocks)
        plaintext_block = strxor(decrypted_block, previous_block)
        previous_block = blocks
        
        plaintext_blocks.append(plaintext_block)
    
    plaintext = b''.join(plaintext_blocks)
    try:
        plaintext = unpad(plaintext, 16).decode('utf-8', errors='ignore') 
    except:
        plaintext = plaintext.decode('utf-8', errors='ignore') #bit flipping messes up the padding and raises exception
       
    print(f"Decrypted plaintext (CBC): \n{plaintext}\n")
    return plaintext

def bit_flipping(ciphertext: bytes, iv: bytes,
                 slash_pos: int, original_char: str, target_char: str) -> tuple[bytes, bytes]:
    """
    Flip a single byte in the decrypted plaintext by modifying IV or ciphertext.
    Returns (modified_ciphertext, modified_iv).
    """
    block_num = slash_pos // 16
    offset = slash_pos % 16
    diff = ord(original_char) ^ ord(target_char)

    modified_cipher = bytearray(ciphertext)
    modified_iv = bytearray(iv)

    if block_num == 0: # Plaintext is in block 0 → flip IV
        modified_iv[offset] ^= diff
    else: # Flip prev ciphertext block
        prev_block_start = (block_num - 1) * 16
        modified_cipher[prev_block_start + offset] ^= diff

    return bytes(modified_cipher), bytes(modified_iv)
 
    
# def bit_flipping(encrypted_text: bytes, slash_pos: int, target_char: str, original_char: str) -> str:
#     block_num = (slash_pos // 16) # Block containing the target byte
#     offset = slash_pos % 16
    
#     prev_block_start = (block_num - 1) * 16
#     print("prev block start: ", prev_block_start)

#     modified_ciphertext = bytearray(encrypted_text)
#     diff = ord(original_char) ^ ord(target_char)
#     modified_ciphertext[prev_block_start + offset] ^= diff 


#     return bytes(modified_ciphertext)
    
def submit(input_string: str) -> bytes:
    # prepended_string = "userid=456;userdata=" + quote(input_string, safe='') + ";session-id=31337"
    # url_encoded_string = prepended_string.replace("=", "%3D").replace(";", "%3B")
    
    utf_encoded_string = input_string.encode('utf-8')
    
    print(f"utf: {utf_encoded_string}")
    padded_string_bytes: bytes = pad(utf_encoded_string, 16)

    plaintext_blocks = [padded_string_bytes[i:i+16] for i in range(0, len(padded_string_bytes), 16)]

    ciphertext = encrypt_with_cbc(key, iv, plaintext_blocks)
    return ciphertext

def verify(iv_key: bytes, ciphertext: bytes) -> bool:
    cbc_decryption = decrypt_with_cbc(iv_key, ciphertext)
    
    plaintext = cbc_decryption[:20] + unquote(cbc_decryption[20:-17]) + cbc_decryption[-17:]
    print(f"Decrypted plaintext (CBC) without URL decoding: \n{cbc_decryption}")

    if(";admin=true;" in cbc_decryption):
        print("True")
        return True
    else:
        print("False")
        return False

# simplified main
def main():
    plaintext = input("Enter string:")
    ciphertext = submit(plaintext)
    slash_pos = plaintext.index('/') 

    # Bitflip
    new_cipher, new_iv = bit_flipping(ciphertext, iv, slash_pos, '/', '=')
    
    verify(new_iv, new_cipher)

    
# def main():
#     input_string = input("Enter a string: ")

#     enc = submit(input_string)
    
#     # dec = cipher.decrypt(enc)
#     dec = verify(iv, enc)

#     print("--:BitFlip demonstration:--")
    
#     # print("++++++++++++++unurlencoded+++++++++++")
#     # prepended_string = "userid=456;userdata=" + input_string + ";session-id=31337"
#     # # url_encoded_string = prepended_string.replace("=", "%3D").replace(";", "%3B")
    
#     # utf_encoded_string = prepended_string.encode('utf-8')
    
#     # print(f"utf: {utf_encoded_string}")
#     # padded_string_bytes: bytes = pad(utf_encoded_string, 16)

#     # plaintext_blocks = [padded_string_bytes[i:i+16] for i in range(0, len(padded_string_bytes), 16)]
#     # print("Without URL Encoding:", encrypt_with_cbc(key, iv, plaintext_blocks))
    
#     # print("+++++++++++++++++++++++++")
    
#     new_enc = submit(input_string)
    
#     #test url encoding
#     url_encoded = quote(input_string, safe='')
#     predict_prepended = "userid=456;userdata=" + url_encoded + ";session-id=31337"
#     slash_pos1 = predict_prepended.index('%2F')

#     # '/' acts as the bookmark to replace bits
#     # slash_pos2 = new_enc.index('%', slash_pos1 + 1)
#     # slash_pos3 = new_enc.index('%', slash_pos2 + 1)

#     # flip1 = bit_flipping(new_enc, slash_pos1, ';')
#     # flip2 = bit_flipping(flip1, percent_positions[1], '=')
#     # flip3 = bit_flipping(flip2, percent_positions[2], ';')
    
#     # pos1 = #byte position of ciphered text that represents first occurence of ;
#     # new_enc[20] first occurance of ;
#     # need to find the encrypted version of ;//hopefully abstracted by bit_flipping()
#     print("==unflipped=")
#     dec = verify(iv, new_enc)
#     print("====")
    
#     flipped_enc = bit_flipping(new_enc, slash_pos1, '=', '%')
    
#     dec = verify(iv, flipped_enc)

    
    
    

if __name__ == "__main__":
    main()