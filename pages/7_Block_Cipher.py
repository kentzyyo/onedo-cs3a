import streamlit as st

st.divider()
st.header("Block Cipher")
st.text('by by Selwyn Kent Oñedo')
st.divider()

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                        

def unpad(data):
    padding_length = data[-1]
    assert padding_length > 0 
    message, padding = data[:-padding_length], data[-padding_length:]
    assert all(p == padding_length for p in padding)
    return message                  

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block             

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)  

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for x, i in enumerate(range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data                              

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for x, i in enumerate(range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data                           

def main():
    st.title("Block Cipher - XOR Encryption")

    plaintext = st.text_input("Plaintext:")
    key = st.text_input("Key:")
    block_size = st.text_input("Block Size:")
    submit_button = st.button("Submit")

    if submit_button:
        if block_size:
            block_size = int(block_size)
            if block_size not in [8, 16, 32, 64, 128]:
                st.divider()
                st.error("Block size must be one of 8, 16, 32, 64, or 128 bytes")
                return

        if plaintext and key and block_size:
            key = pad(bytes(key.encode()), block_size)
            # key = pad(key, block_size)
            ciphertext = xor_encrypt(bytes(plaintext.encode()), key, block_size)
            # ciphertext = xor_encrypt(plaintext, key, block_size)
            decrypted_data = xor_decrypt(ciphertext, key, block_size)

            st.divider()
            st.subheader("Encrypted blocks")
            for x, i in enumerate(range(0, len(ciphertext), block_size)):
                # ciphertext_block = ciphertext[i:i+block_size]
                decrypted_block = decrypted_data[i:i+block_size]
                # st.write(f"Plain  block[{x}]: {ciphertext_block.hex()} : {ciphertext_block}")
                st.write(f"Plain \t\tblock[{x}]: {decrypted_block.hex()} : {decrypted_block}")
                # decrypted_block = decrypted_data[i:i+block_size]
                ciphertext_block = ciphertext[i:i+block_size]
                encrypted_str = ''.join([f"`{chr(b)}`" for b in ciphertext_block])
                # st.write(f"Cipher block[{x}]: {decrypted_block.hex()} : {decrypted_block}")
                st.write(f"Cipher block[{x}]: {ciphertext_block.hex()} : {ciphertext_block}")

            st.subheader("Decrypted blocks")
            for x, i in enumerate(range(0, len(decrypted_data), block_size)):
                decrypted_block = decrypted_data[i:i+block_size]
                st.write(f"block[{x}]: {decrypted_block.hex()}: {decrypted_block}")

            st.write("\t")
            st.write("\nOriginal plaintext:", decrypted_data)
            st.write("Key byte      :", key)
            st.write("Key hex       :", key.hex())
            st.write("Encrypted data:", ciphertext.hex())
            st.write(f"Decrypted data: {decrypted_data.hex()}")
            st.write("Decrypted data:", decrypted_data)

if __name__ == "__main__":
    main()

st.divider()
st.snow()