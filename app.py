import streamlit as st
import pandas as pd
import secrets
import binascii
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum,
    Bip44, Bip49, Bip84, Bip86, Bip44Coins, Bip44Changes,
    Bip39Languages
)

st.set_page_config(page_title="Bitcoin Internals Explorer", layout="wide")

st.title("₿ Bitcoin Internals Explorer")
st.markdown("""
เครื่องมือนี้จะพาคุณเจาะลึกเบื้องหลังการทำงานของ Bitcoin Wallet ตั้งแต่ความสุ่ม (Entropy) 
ไปจนถึงคณิตศาสตร์ Elliptic Curve ที่ซับซ้อนเพื่อสร้าง Address ประเภทต่างๆ
""")

# --- SIDEBAR: Configuration ---
st.sidebar.header("⚙️ Configuration")
input_method = st.sidebar.radio("Input Method", ["Random Generate", "Manual Hex", "Manual Binary"])
address_type_select = st.sidebar.selectbox(
    "Derivation Path / Wallet Type",
    ["Legacy (BIP-44) - 1...", "Segwit (BIP-49) - 3...", "Native Segwit (BIP-84) - bc1q...", "Taproot (BIP-86) - bc1p..."]
)

# --- STEP 1: ENTROPY ---
st.header("1. Entropy: The Source of Truth")
st.info("ทุกอย่างเริ่มต้นที่ความสุ่ม (Entropy) คอมพิวเตอร์ต้องสุ่มตัวเลขขนาด 128-256 bit ขึ้นมา")

entropy_hex = ""
entropy_bin = ""

if input_method == "Random Generate":
    if st.button("🎲 Generate Random Entropy"):
        ent_bytes = secrets.token_bytes(16) # 128 bits for 12 words
        entropy_hex = binascii.hexlify(ent_bytes).decode()
        entropy_bin = bin(int(entropy_hex, 16))[2:].zfill(128)
        st.session_state['entropy_hex'] = entropy_hex
    elif 'entropy_hex' in st.session_state:
        entropy_hex = st.session_state['entropy_hex']
        entropy_bin = bin(int(entropy_hex, 16))[2:].zfill(128)

elif input_method == "Manual Hex":
    entropy_hex = st.text_input("Enter Hex (32 chars for 128 bits):", value="00000000000000000000000000000000")
    try:
        entropy_bin = bin(int(entropy_hex, 16))[2:].zfill(len(entropy_hex)*4)
    except:
        st.error("Invalid Hex")

elif input_method == "Manual Binary":
    entropy_bin = st.text_area("Enter Binary (0s and 1s):", value="0"*128)
    try:
        entropy_hex = hex(int(entropy_bin, 2))[2:]
    except:
        st.error("Invalid Binary")

if entropy_hex:
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Hex ({len(entropy_hex)} chars):** `{entropy_hex}`")
    with col2:
        st.write(f"**Binary ({len(entropy_bin)} bits):** `{entropy_bin}`")

    st.markdown("---")

    # --- STEP 2: MNEMONIC GENERATION ---
    st.header("2. Mnemonic Generation (BIP-39)")
    st.markdown("นำ Entropy มาคำนวณ Checksum แล้วหั่นเป็นท่อน ท่อนละ 11 bits เพื่อแปลงเป็นคำศัพท์")
    
    with st.expander("Show Detailed Calculation (Checksum & Indices)"):
        # Calculate Checksum logic for display
        # (This is simplified for visualization)
        st.write(f"1. Entropy Bits: `{entropy_bin}`")
        st.write("2. SHA256(Entropy) -> Take first N bits as Checksum")
        st.write("3. Combined Bits / 11 = Word Index")
        st.caption("Standard BIP-39 Wordlist has 2048 words.")

    try:
        # Generate Mnemonic
        mnemonic_gen = Bip39MnemonicGenerator()
        mnemonic = mnemonic_gen.FromEntropy(binascii.unhexlify(entropy_hex))
        
        st.success(f"**Seed Phrase:** {mnemonic}")
        
        passphrase = st.text_input("Passphrase (Optional Salt):", value="")
        
    except Exception as e:
        st.error(f"Error deriving mnemonic: {e}")
        st.stop()

    st.markdown("---")

    # --- STEP 3: SEED & MASTER KEY ---
    st.header("3. The Master Node (BIP-32)")
    st.markdown("แปลงคำศัพท์ + Passphrase ให้กลายเป็น **Binary Seed (512-bit)** ผ่านฟังก์ชัน `PBKDF2-HMAC-SHA512`")
    
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    seed_hex = binascii.hexlify(seed_bytes).decode()
    
    with st.expander("🔍 ดูความซับซ้อนของ Seed"):
        st.code(f"Seed (Hex): {seed_hex}", language="text")
        st.write("ตัวเลขนี้คือ 'รากแก้ว' (Root) ของกระเป๋าทั้งหมดของคุณ")

    st.markdown("---")

    # --- STEP 4: DERIVATION ---
    st.header("4. Derivation Path & Private Key")
    
    # Mapping selection to Logic
    if "Legacy" in address_type_select:
        cls_wrapper = Bip44
        purpose = 44
        desc = "Legacy (P2PKH) - เริ่มต้นด้วย 1"
    elif "Segwit" in address_type_select and "Native" not in address_type_select:
        cls_wrapper = Bip49
        purpose = 49
        desc = "Nested Segwit (P2SH-P2WPKH) - เริ่มต้นด้วย 3"
    elif "Native Segwit" in address_type_select:
        cls_wrapper = Bip84
        purpose = 84
        desc = "Native Segwit (P2WPKH) - เริ่มต้นด้วย bc1q"
    elif "Taproot" in address_type_select:
        cls_wrapper = Bip86
        purpose = 86
        desc = "Taproot (P2TR) - เริ่มต้นด้วย bc1p"

    st.write(f"**Current Mode:** {desc}")
    st.latex(f"Path: m / {purpose}' / 0' / 0' / 0 / 0")
    
    st.info("จาก Master Key เราจะ 'แตกกิ่ง' (Derive) ลงมาตามเส้นทาง (Path) เพื่อให้ได้ Private Key ของ Address แรก")

    # Constructing the wallet object
    bip_obj_ctx = cls_wrapper.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    # Derive account -> chain -> address
    bip_acc = bip_obj_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    bip_addr_0 = bip_acc.AddressIndex(0)

    private_key_hex = bip_addr_0.PrivateKey().Raw().ToHex()
    public_key_hex = bip_addr_0.PublicKey().RawCompressed().ToHex()
    final_address = bip_addr_0.PublicKey().ToAddress()

    col_pk1, col_pk2 = st.columns([1, 2])
    with col_pk1:
        st.metric("Index", "0")
    with col_pk2:
        st.text_input("Derived Private Key (Hex)", value=private_key_hex, disabled=True)

    # --- STEP 5: ELLIPTIC CURVE MATH ---
    st.header("5. The Math: Private Key ➡️ Public Key")
    st.markdown("""
    ขั้นตอนนี้คือหัวใจของความปลอดภัย Bitcoin ใช้ **Elliptic Curve Cryptography (secp256k1)**
    """)
    
    st.latex(r"K = k * G")
    st.caption("เมื่อ k คือ Private Key, G คือ Generator Point และ K คือ Public Key")

    with st.expander("🤯 เจาะลึกความยากของการคำนวณ"):
        st.markdown("""
        การคูณใน Elliptic Curve ไม่ใช่การคูณปกติ แต่เป็นการ **"Dot"** จุดบนกราฟซ้ำๆ จำนวนเท่ากับ Private Key (ซึ่งเป็นเลขขนาดมหาศาล)
        
        **ทำไมถึงปลอดภัย?**
        มันง่ายที่จะคำนวณไปข้างหน้า (จาก Private -> Public) แต่เป็นไปไม่ได้ในทางปฏิบัติที่จะคำนวณย้อนกลับ (Discrete Logarithm Problem)
        """)
        # Visualize Generator Point (Static for example)
        st.code("""
        G (x) = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        G (y) = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        """, language="text")

    st.text_input("Calculated Public Key (Compressed)", value=public_key_hex, disabled=True)

    # --- STEP 6: ADDRESS FORMATTING ---
    st.header("6. Formatting the Address")
    st.markdown(f"สุดท้าย เรานำ Public Key มา Hash (SHA256 + RIPEMD160) แล้วเข้ากระบวนการ Encoding แบบ **{desc.split('-')[0].strip()}**")

    if "Legacy" in address_type_select:
        st.markdown("**Process:** `Base58Check(Version + RIPEMD160(SHA256(PubKey)))`")
    else:
        st.markdown("**Process:** `Bech32/Bech32m Encoding` (Witness Program)")

    st.success(f"### Final Address: {final_address}")

    st.markdown("---")
    st.subheader("🛠 ลองเล่นดู!")
    st.write("ลองเปลี่ยน Derivation Path ด้านบนซ้าย แล้วดูว่า Private Key เดิม สร้าง Address ที่หน้าตาต่างกันอย่างไร")