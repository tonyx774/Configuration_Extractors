import subprocess
import pefile
import sys
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import string

# Used to remove unneeded non ascii characters from dumped config
def remove_non_ascii(a_str):
    ascii_chars = set(string.printable)

    return ''.join(filter(lambda x: x in ascii_chars, a_str))

# Used to decrypt encrypted configuration data for Phobos Ransomware
def decrypt(encrypted_config, aes_key):
    #print(" ---- Attempting to Decrypt Configuration ---- \n")

    # Try except statement to catch any possible unknown version errors
  #  try:
        # Phobos Ransomware always has an IV of 16 null bytes
        iv = bytes([0] * 16)

        # Creating AES cipher for decryption
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Adding Padding needed to ensure correct block size for successful decryption
        padding_length = AES.block_size - (len(encrypted_config) % AES.block_size)

        # Applying padding to the encrypted configuration data
        padded_encrypted_config = encrypted_config + bytes([padding_length] * padding_length)



        # Decrypting padding data with AES
        decrypted_data = cipher.decrypt(padded_encrypted_config)

        # decoding unpadded data to latin-1 and removing non ascii characters
        decrypted_config = remove_non_ascii(decrypted_data.decode('latin-1'))

        print("\n ---- Succesfully Decrypted Configuration ---- \n")
        print(decrypted_config)

        # Dump decrypted configuration to 'decrypted_config.dump'
        with open('decrypted_config.dump','w') as file:
            file.write(decrypted_config)
        print('\n ---- Decrypted Configuration has also been Dumped to decrypted_config.dump ---- \n')
    #except:
    #    print("Could not decrypt configuration. Likely either not Phobos Ransomware or an incompatible version")

def main():
    # Get the pefile as first arguement to program
    pe = pefile.PE(sys.argv[1])

    try:
        # Get the .cdata section
        sectionData = pe.sections[4].get_data()

        # Extract the encrypted data which starts at offset 776
        encrypted_config = sectionData[776:]

        # Extract the configuration key
        aes_key = pe.sections[2].get_data()[1040:1072]

    except:
        print("Could not grab encrypted data. Likely either not Phobos Ransomware or an incompatible version")

    # Decrypt encrypted configuration with aes key
    decrypt(encrypted_config, aes_key)

if __name__ == "__main__":
    main()
