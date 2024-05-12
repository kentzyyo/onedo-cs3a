import streamlit as st

st.header("XOR Cipher")

plaintext = bytes(st.text_area("Plain Text:").encode())

key = bytes(st.text_input("Key:").encode())

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, st.writeing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        input_text_byte = plaintext[i]
        key_byte =  key[i % len(key)]
        encrypted_byte = input_text_byte ^ key_byte
        ciphertext.append(encrypted_byte)
        st.write(f"Plaintext byte: {format(input_text_byte, '08b')} = {chr(input_text_byte)}")
        st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
        st.write(f"XOR result:     {format(encrypted_byte, '08b')} = {chr(encrypted_byte)}")
        
        st.write("--------------------")
    return ciphertext



def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption



if st.button("Submit"):
    if plaintext.decode() == key.decode():
        st.write("No input at all")
    elif not plaintext:
        st.error("No Input in the textbox!")
    elif not key:
        st.error("No input for key!")
    elif len(key.decode()) > len(plaintext.decode()):
        st.write("Plaintext length should be equal or greater than the length of key")
    else:
        encrypted_text = xor_encrypt(plaintext, key)
        st.write("Ciphertext:", encrypted_text.decode())
        decrypted_text = xor_decrypt(encrypted_text, key)
        st.write("Decrypted:", plaintext.decode())
    st.balloons()
        