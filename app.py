import streamlit as st
import pandas as pd
import secrets
import binascii
import hashlib
import numpy as np
import matplotlib.pyplot as plt
import graphviz
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator,
    Bip44, Bip49, Bip84, Bip86, Bip44Coins, Bip44Changes
)

# ==========================================
# 1. SETUP & THEME (CYBERPUNK STYLE)
# ==========================================
st.set_page_config(page_title="Bitcoin Core: Entropy Lab", layout="wide", page_icon="₿")

# Custom CSS for Neon/Dark Theme
st.markdown("""
<style>
    /* Global Background */
    .stApp {
        background-color: #0e1117;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Input Fields */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
        background-color: #1c1f26;
        color: #00ff41 !important;
        border: 1px solid #00ff41;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #fff !important;
        text-shadow: 0 0 10px #00ff41;
    }
    
    /* Metrics */
    div[data-testid="stMetricValue"] {
        color: #00ff41;
        text-shadow: 0 0 5px #00ff41;
    }
    
    /* Buttons */
    .stButton button {
        background-color: #003300;
        color: #00ff41;
        border: 1px solid #00ff41;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #00ff41;
        color: #000;
        box-shadow: 0 0 15px #00ff41;
    }
    
    /* Custom Info Box */
    .tech-box {
        background-color: #001a05;
        border-left: 5px solid #00ff41;
        padding: 15px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

st.title("⚡ BITCOIN CORE: ENTROPY LAB")
st.markdown("**PROTOCOL:** `BIP-39` | `BIP-32` | `BIP-44/84/86` | **STATUS:** `ONLINE`")

# ==========================================
# 2. SIDEBAR CONFIGURATION
# ==========================================
st.sidebar.header("🎛 CONTROL PANEL")

word_count = st.sidebar.radio("Mnemonic Length", [12, 24], index=0)
input_mode = st.sidebar.selectbox("Entropy Input Mode", ["🎲 Random Generator", "⌨️ Manual Hex", "0️⃣1️⃣ Manual Binary"])
network_type = st.sidebar.selectbox("Wallet Protocol", [
    "Native Segwit (bc1q) - BIP84",
    "Taproot (bc1p) - BIP86",
    "Nested Segwit (3...) - BIP49",
    "Legacy (1...) - BIP44"
])

# Determine Bits based on word count
# 12 words = 128 bits entropy + 4 bits checksum = 132 bits
# 24 words = 256 bits entropy + 8 bits checksum = 264 bits
entropy_bits = 128 if word_count == 12 else 256
checksum_bits = 4 if word_count == 12 else 8
total_bits = entropy_bits + checksum_bits

# ==========================================
# 3. ENTROPY ENGINE (REAL-TIME)
# ==========================================
st.markdown("---")
st.header("1. ENTROPY GENERATION (The Genesis)")
st.markdown(f"<div class='tech-box'>Entropy คือความสุ่มที่แท้จริง สำหรับ {word_count} คำ ต้องใช้ความสุ่มขนาด <b>{entropy_bits} bits</b></div>", unsafe_allow_html=True)

# Initialize Session State
if 'entropy_hex' not in st.session_state:
    st.session_state['entropy_hex'] = secrets.token_hex(entropy_bits // 8)

current_hex = ""
current_bin = ""

# Handle Inputs
if input_mode == "🎲 Random Generator":
    if st.button("RE-GENERATE ENTROPY"):
        st.session_state['entropy_hex'] = secrets.token_hex(entropy_bits // 8)
    current_hex = st.session_state['entropy_hex']
    current_bin = bin(int(current_hex, 16))[2:].zfill(entropy_bits)

elif input_mode == "⌨️ Manual Hex":
    default_val = st.session_state.get('entropy_hex', '0' * (entropy_bits // 4))
    user_hex = st.text_input(f"Enter {entropy_bits//4} Hex Characters:", value=default_val)
    # Validation
    try:
        int(user_hex, 16)
        if len(user_hex) * 4 != entropy_bits:
            st.warning(f"Warning: Length mismatch. Expected {entropy_bits//4} chars.")
        current_hex = user_hex
        current_bin = bin(int(current_hex, 16))[2:].zfill(entropy_bits)
    except:
        st.error("Invalid Hex String")
        st.stop()

elif input_mode == "0️⃣1️⃣ Manual Binary":
    # Default binary from current hex
    default_bin = bin(int(st.session_state['entropy_hex'], 16))[2:].zfill(entropy_bits)
    user_bin = st.text_area(f"Enter {entropy_bits} Bits (0/1):", value=default_bin, height=100)
    # Validation
    if not all(c in '01' for c in user_bin):
        st.error("Invalid Binary. Only 0 and 1 allowed.")
        st.stop()
    current_bin = user_bin
    current_hex = hex(int(current_bin, 2))[2:]

# Display Entropy
col1, col2 = st.columns(2)
with col1:
    st.code(current_hex, language="text")
    st.caption("HEXADECIMAL FORMAT")
with col2:
    st.code(current_bin, language="text")
    st.caption("BINARY FORMAT")

# ==========================================
# 4. CHECKSUM & MNEMONIC
# ==========================================
st.markdown("---")
st.header("2. CHECKSUM CALCULATION")

# Calculate Checksum manually to show the process
entropy_bytes = binascii.unhexlify(current_hex.zfill(entropy_bits // 4))
hash_bytes = hashlib.sha256(entropy_bytes).digest()
hash_bin = "".join(f"{b:08b}" for b in hash_bytes)
checksum_val = hash_bin[:checksum_bits]

st.markdown(f"<div class='tech-box'>SHA256(Entropy) -> เอา {checksum_bits} บิตแรกมาทำเป็น Checksum เพื่อป้องกันการจดผิด</div>", unsafe_allow_html=True)

col_c1, col_c2, col_c3 = st.columns([4, 1, 4])
with col_c1:
    st.markdown("**Entropy Bits**")
    st.text(current_bin)
with col_c2:
    st.markdown("**+ Checksum**")
    st.success(checksum_val)
with col_c3:
    st.markdown("**= Total Bits (Mnemonic Source)**")
    final_bits = current_bin + checksum_val
    st.text(final_bits)

st.markdown("### 🧩 WORD SPLITTING (11 Bits per Word)")
# Split into 11-bit chunks
chunks = [final_bits[i:i+11] for i in range(0, len(final_bits), 11)]

# Generate Mnemonic using Library
mnemonic_gen = Bip39MnemonicGenerator()
mnemonic_str = mnemonic_gen.FromEntropy(entropy_bytes).ToStr()
words = mnemonic_str.split()

# Create a DataFrame for visualization
df_data = []
for i, chunk in enumerate(chunks):
    decimal_val = int(chunk, 2)
    word = words[i]
    df_data.append([f"Word {i+1}", chunk, decimal_val, word])

df = pd.DataFrame(df_data, columns=["Order", "11-Bit Binary", "Index (Dec)", "BIP-39 Word"])
st.dataframe(df, use_container_width=True)

st.success(f"🔑 **FINAL SEED PHRASE:** {mnemonic_str}")

# ==========================================
# 5. BIP-32 HIERARCHY (VISUALIZATION)
# ==========================================
st.markdown("---")
st.header("3. DERIVATION TREE (BIP-32)")

passphrase = st.text_input("Optional Passphrase (Salt):", value="")

# Generate Seed
seed_bytes = Bip39SeedGenerator(mnemonic_str).Generate(passphrase)
seed_hex = binascii.hexlify(seed_bytes).decode()

# Logic for paths
if "Native Segwit" in network_type:
    purpose = 84
    wrapper = Bip84
    prefix = "bc1q"
elif "Taproot" in network_type:
    purpose = 86
    wrapper = Bip86
    prefix = "bc1p"
elif "Nested" in network_type:
    purpose = 49
    wrapper = Bip49
    prefix = "3"
else:
    purpose = 44
    wrapper = Bip44
    prefix = "1"

# Derive Keys
bip_ctx = wrapper.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip_acc = bip_ctx.Purpose().Coin().Account(0)
bip_change = bip_acc.Change(Bip44Changes.CHAIN_EXT)
bip_addr = bip_change.AddressIndex(0)

# Graphviz Tree
graph = graphviz.Digraph()
graph.attr(bgcolor='#0e1117', fontcolor='white', rankdir='LR')
graph.attr('node', style='filled', fillcolor='#1c1f26', color='#00ff41', fontcolor='white', fontname='Courier')
graph.attr('edge', color='#00ff41')

# Nodes
root_label = f"Master Seed\n(512-bit)\n{seed_hex[:16]}..."
graph.node('ROOT', root_label, shape='box')

purpose_label = f"Purpose\n{purpose}'"
graph.node('PURPOSE', purpose_label)

coin_label = "Coin\n0' (BTC)"
graph.node('COIN', coin_label)

account_label = "Account\n0'"
graph.node('ACC', account_label)

change_label = "Change\n0 (External)"
graph.node('CHANGE', change_label)

addr_label = f"Index 0\n{bip_addr.PublicKey().ToAddress()}"
graph.node('ADDR', addr_label, color='#ff00ff', penwidth='2')

# Edges
graph.edge('ROOT', 'PURPOSE')
graph.edge('PURPOSE', 'COIN')
graph.edge('COIN', 'ACC')
graph.edge('ACC', 'CHANGE')
graph.edge('CHANGE', 'ADDR')

st.graphviz_chart(graph)
st.caption(f"Derivation Path: m / {purpose}' / 0' / 0' / 0 / 0")

# ==========================================
# 6. ELLIPTIC CURVE MATH (VISUALIZATION)
# ==========================================
st.markdown("---")
st.header("4. ELLIPTIC CURVE CRYPTOGRAPHY (secp256k1)")
st.markdown("<div class='tech-box'>Bitcoin ใช้สมการ <b>y² = x³ + 7</b> กราฟด้านล่างจำลองหน้าตาของ Curve บนจำนวนจริง (ในความเป็นจริง Bitcoin ใช้บน Finite Field ที่ซับซ้อนกว่านี้) จุดสีแดงคือ Private Key ของคุณ</div>", unsafe_allow_html=True)

col_graph, col_keys = st.columns([1, 1])

with col_graph:
    # Plotting y^2 = x^3 + 7
    x = np.linspace(-3, 3, 400)
    y_sq = x**3 + 7
    y_pos = np.sqrt(y_sq)
    y_neg = -np.sqrt(y_sq)

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(x, y_pos, 'b', lw=2, color='#00ff41')
    ax.plot(x, y_neg, 'b', lw=2, color='#00ff41')
    
    # Fake Point P (Just for visualization) based on Entropy first byte
    rand_idx = int(entropy_bytes[0]) % len(x)
    px = x[rand_idx]
    py = y_pos[rand_idx]
    
    ax.plot(px, py, 'ro', markersize=8, label='Your Key Point')
    ax.plot([px, px], [0, py], 'r--', alpha=0.3)
    
    # Styling Plot
    ax.set_facecolor('#1c1f26')
    fig.patch.set_facecolor('#0e1117')
    ax.grid(True, color='#003300')
    ax.spines['bottom'].set_color('#00ff41')
    ax.spines['left'].set_color('#00ff41')
    ax.tick_params(colors='white')
    ax.set_title("y² = x³ + 7 (Simulation)", color='white')
    ax.legend()
    
    st.pyplot(fig)

with col_keys:
    st.subheader("🔑 KEY PAIR")
    
    pk_hex = bip_addr.PrivateKey().Raw().ToHex()
    pub_hex = bip_addr.PublicKey().RawCompressed().ToHex()
    
    st.text_input("Private Key (k)", value=pk_hex, disabled=True)
    st.caption("⚠️ ห้ามเปิดเผยสิ่งนี้ให้ใครเห็นเด็ดขาด")
    
    st.text_input("Public Key (K = k*G)", value=pub_hex, disabled=True)
    st.caption("ใช้สำหรับตรวจสอบลายเซ็นและสร้าง Address")

    st.markdown("---")
    st.subheader(f"📬 FINAL ADDRESS ({prefix}...)")
    st.code(bip_addr.PublicKey().ToAddress(), language="text")

# ==========================================
# FOOTER
# ==========================================
st.markdown("---")
st.markdown("<center><small>Developed for Bitcoin Education | Powered by Python, Streamlit & Docker, Chollatis Maneewong</small></center>", unsafe_allow_html=True)