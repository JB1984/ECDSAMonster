#!/usr/bin/env python
# coding: utf-8

# [slides](https://docs.google.com/presentation/d/19K9nVjuSOCrZGM6lmFeEEarTm2xZwDSiZEIzf-Ywr5o/edit?usp=sharing)
# 
# [python-ecdsa docs](https://github.com/warner/python-ecdsa)

# # Signing our First Message with ECDSA

# # Defining ECDSAMonster
# 
# * A monster is just a list of transfers, and some other variables for health, damage, and an image. 
#     
# * The `public_key` in the last transfer is who owns the coin
# * To transfer the monster append a new transfer. Use the public key of the person you are sending to, and sign it using your private key.

# In[66]:


class Transfer:
    
    def __init__(self, signature, public_key):
        self.signature = signature #Proof from previous owner that they authorize transfer
        self.public_key = public_key #New Owner
        
class ECDSAMonster:
    
    def __init__(self, transfers, health, damage, image):
        self.transfers = transfers
        self.health = health
        self.damage = damage
        self.image = image        


# In[67]:


# The usual suspects ... 
# SECP256k1 is a detail about the "magical multiplication" used under the covers
from ecdsa import SigningKey, SECP256k1

bank_private_key = SigningKey.generate(curve=SECP256k1)
bob_private_key = SigningKey.generate(curve=SECP256k1)
alice_private_key = SigningKey.generate(curve=SECP256k1)

bank_public_key = bank_private_key.get_verifying_key()
bob_public_key = bob_private_key.get_verifying_key()
alice_public_key = alice_private_key.get_verifying_key()


# In[68]:


from utils import serialize
import random
from PIL import Image, ImageTk

def issue(public_key, path_to_image):
    
    message = serialize(public_key)
    
    signature = bank_private_key.sign(message)
    
    transfer = Transfer(
        signature = signature,
        public_key = public_key
    )
    
    monster = ECDSAMonster([transfer], random.randint(1,10), random.randint(1,10), Image.open(path_to_image))
    return monster


# # Validating the First Transfer

# In[74]:


def validate(monster):
    
    transfer = monster.transfers[0]
    
    message = serialize(transfer.public_key)
    
    bank_public_key.verify(transfer.signature, message)
    


# In[75]:


alice_monster = issue(alice_public_key, 'godzilla.jpg')

validate(alice_monster)


# # Validating Subsequent Transfers

# In[76]:


def transfer_message(previous_signature, next_owner_public_key):
    return serialize({
        "previous_signature": previous_signature,
        "next_owner_public_key": next_owner_public_key
    })

def validate(monster):
    #Check the first transfer
    transfer = monster.transfers[0]
    message = serialize(transfer.public_key)
    bank_public_key.verify(transfer.signature, message)
    
    #Check the rest of coin.transfers
    previous_transfer = monster.transfers[0]
    for next_transfer in monster.transfers[1:]:
        message = transfer_message(previous_transfer.signature, next_transfer.public_key)
        previous_transfer.public_key.verify(
            next_transfer.signature,
            message,
        )
        
    


# In[77]:


def get_owner(monster):
    database = {
        bob_public_key: "Bob",
        alice_public_key: "Alice",
        bank_public_key: "Bank",
    }
    
    public_key = monster.transfers[-1].public_key
    return database[public_key]


# In[79]:


monster = issue(alice_public_key, 'godzilla.jpg')

print("This monster is owned by", get_owner(monster))

message = transfer_message(monster.transfers[-1].signature, bob_public_key)
alice_to_bob = Transfer(
    signature = alice_private_key.sign(message),
    public_key = bob_public_key,
)

monster.transfers.append(alice_to_bob)

print("This monster is owned by", get_owner(monster))


message = transfer_message(monster.transfers[-1].signature, bob_public_key)
bob_to_bank = Transfer(
    signature = bob_private_key.sign(message),
    public_key = bank_public_key,
)

monster.transfers.append(bob_to_bank)

print("This monster is owned by", get_owner(monster))


# # Serialization

# In[80]:


from utils import to_disk, from_disk


# In[81]:


import os

filename = "monster.ecdsacoin"

print("Does the monsterfile exist on disk?", os.path.isfile(filename))


# In[82]:


monster = issue(alice_public_key, 'godzilla.jpg')

to_disk(alice_monster, filename)


# In[83]:


print("Does the monsterfile exist on disk?", os.path.isfile(filename))


# In[89]:


monster1 = from_disk(filename)
monster1


# # Display your monster using basic TKinter

# In[90]:


import tkinter as tk

def display_monster(monster):
    root = tk.Tk()
    picture1 = monster.image
    photo = ImageTk.PhotoImage(picture1)

    w1=tk.Label(root, image=photo).pack(side="right")

    stats = "Health: " + str(monster.health) + "\n\n\nDamage: " + str(monster.damage)

    w2 = tk.Label(root, 
                justify = tk.LEFT,
                 padx = 10,
                 text = stats).pack(side="left")
    root.mainloop()


# # Test it can display image from within monster object

# In[91]:


monster2 = issue(bob_public_key, 'mothra.jpg')


# In[92]:


display_monster(monster1)


# In[93]:


display_monster(monster2)

