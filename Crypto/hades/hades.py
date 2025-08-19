from Crypto.Cipher import AES
from os import urandom
import random
import binascii

flag = open("flag.txt", "rb").read()

class NextGenPRF:
    def __init__(self, option):
        self.key = urandom(16)
        # 1 = pseudorandom, 0 = true random
        self.option = option
    
    def pseudorandom(self, msg: bytes): # pseudorandom function
        cipher = AES.new(msg, AES.MODE_ECB)
        random_string = random.randbytes(16)
        ciphertext = cipher.encrypt(random_string) + cipher.decrypt(random_string)
        return ciphertext
    
    def true_random(self, msg):
        random_string = random.randbytes(32)
        return bytes(rs ^ m for rs, m in zip(random_string, msg))
    
    def oracle(self, msg):
        if (len(msg) != 32):
            return None
        if (self.option == 0):
            return self.true_random(msg)
        else:
            return self.pseudorandom(msg)
    
    def guess(self, mode_guess):
        return (self.option == mode_guess)


def judgement(questions_left, left_soul, right_soul):
    while True:
        if (questions_left == 0):
            break
        print("State your question for the souls: ", end="")
        hex_message = input()
        try:
            message = binascii.unhexlify(hex_message)
        except binascii.Error:
            continue
        if (len(message) != 32):
            continue
        left_response = binascii.hexlify(left_soul.oracle(message)).decode("utf-8")
        right_response = binascii.hexlify(right_soul.oracle(message)).decode("utf-8")
        print(f"The left soul screams: {left_response}")
        print(f"The right soul screams: {right_response}")
        return (questions_left - 1)

BANNER = """
   ___   _   __  __ ___             
  / __| /_\ |  \/  | __|            
 | (_ |/ _ \| |\/| | _|             
  \___/_/_\_\_|  |_|___|            
  / _ \| __|                        
 | (_) | _|                         
  \___/|_|   ___  ___ ___  
 | || | /_\ |   \| __/ __| 
 | __ |/ _ \| |) | _|\__ \ 
 |_||_/_/ \_\___/|___|___/ 
                                                              
\n\n\n
"""
NYX_HEADER = """
|\ | \ / \_/ 
| \|  |  / \ 
"""
INTRO_TEXT = """
/   Melinoë, dear, I have heard of your issues with Chronos,
|   You know your Father cannot stomach such, and your Mother, why, she
|   worries about you. Your quest is mighty, but it may prove your last.
|   To prepare you against Chronos' illusions, your Father devised a
|   great test. Tell apart the souls, strike true, and you will be 
\   ready for all that is to come.
"""
FAIL = """
...the light fades. Back to the forest you go.
"""
SUCCESS = """
Soul vanquished.
"""
WIN_TEXT = """
/   Wonderful work.
|   
|   I knew you could do it. Here, have this. You Father wanted you
\   to have it once you're ready.
"""
def main():
    souls = 50
    questions = 50
    print(BANNER)
    print(NYX_HEADER)
    print(INTRO_TEXT)
    while (souls > 0):
        truth = random.getrandbits(1) # 0 is left, 1 is right
        if (truth == 0):
            left = NextGenPRF(0) # true random
            right = NextGenPRF(1) # pseudorandom
        else:
            left = NextGenPRF(1) # pseudorandom
            right = NextGenPRF(0) # true random
        
        while True:
            print("> ", end="")
            decision = input()
            match decision:
                case "1": # left door
                    if (left.guess(0)):
                        print(SUCCESS)
                        souls -= 1
                        break
                    else:
                        print(FAIL)
                        return
                case "2": # right door
                    if (right.guess(0)):
                        print(SUCCESS)
                        souls -= 1
                        break
                    else:
                        print(FAIL)
                        return
                case "3":
                    if questions == 0:
                        print(FAIL)
                        return
                    questions = judgement(questions, left, right)
    
    print(NYX_HEADER)
    print(WIN_TEXT)
    print(flag)

if (__name__ == "__main__"):
    main()
