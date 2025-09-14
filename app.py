# app.py
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objs as go
from PIL import Image, ImageFilter
import io, os, hashlib, time, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Any

# ---------------------------
# Configuration / constants
# ---------------------------
PAGE_TITLE = "Quantum Crypto Simulator — BB84(pro)"
QBER_ABORT_THRESHOLD = 0.11  # 11%
EVE_IMAGE_PATH = "windows-3.png"

# ---------------------------
# Utility helpers
# ---------------------------
def load_default_image():
    p = os.path.join("images", "windows.png")
    if os.path.exists(p):
        return Image.open(p).convert("RGB")
    return None

def pil_to_bytes(img: Image.Image, fmt="PNG"):
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

def derive_key_from_bits(bits: np.ndarray) -> bytes:
    if len(bits) == 0:
        # fallback
        return AESGCM.generate_key(bit_length=256)
    s = "".join(map(str, bits.tolist()))
    return hashlib.sha256(s.encode("utf-8")).digest()

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)

# A nice deterministic pixelation + static noise for Eve's view
def make_eve_view(img: Image.Image, pixel_scale: int = 12, noise_level: float = 0.08) -> Image.Image:
    # pixelate
    w, h = img.size
    small = img.resize((max(1, w // pixel_scale), max(1, h // pixel_scale)), Image.NEAREST)
    pixelated = small.resize((w, h), Image.NEAREST)
    pixelated = pixelated.filter(ImageFilter.GaussianBlur(radius=0.8))
    # add noise overlay
    arr = np.array(pixelated).astype(np.int16)
    noise = (np.random.default_rng(int(time.time()%1_000_000)).normal(loc=0.0, scale=255*noise_level, size=arr.shape)).astype(np.int16)
    arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(arr)

# ---------------------------
# BB84 simulation core
# ---------------------------
def simulate_bb84(num_bits: int, p_noise: float, p_eve: float, seed: int | None = None) -> Dict[str, Any]:
    rng = np.random.default_rng(seed)
    alice_bits = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    alice_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)  # 0=Z,1=X
    bob_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    bob_results = np.empty(num_bits, dtype=np.int8)
    eve_intercept = rng.random(num_bits) < p_eve
    eve_bases = rng.integers(0, 2, size=num_bits, dtype=np.int8)
    eve_results = np.empty(num_bits, dtype=np.int8)

    for i in range(num_bits):
        if eve_intercept[i]:
            # Eve measures
            if eve_bases[i] == alice_bases[i]:
                eve_results[i] = alice_bits[i]
            else:
                eve_results[i] = rng.integers(0, 2)
            sender_basis = eve_bases[i]
            sender_bit = int(eve_results[i])
        else:
            sender_basis = alice_bases[i]
            sender_bit = int(alice_bits[i])

        # Bob measures
        bob_bit = sender_bit if bob_bases[i] == sender_basis else rng.integers(0, 2)
        # channel noise flips bit with prob p_noise
        if rng.random() < p_noise:
            bob_bit ^= 1
        bob_results[i] = int(bob_bit)

    sift_mask = alice_bases == bob_bases
    alice_sift = alice_bits[sift_mask]
    bob_sift = bob_results[sift_mask]
    sift_len = int(sift_mask.sum())
    qber = (np.count_nonzero(alice_sift != bob_sift) / sift_len) if sift_len > 0 else float("nan")

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_results": bob_results,
        "eve_intercept": eve_intercept,
        "eve_bases": eve_bases,
        "eve_results": eve_results,
        "sift_mask": sift_mask,
        "alice_sift": alice_sift,
        "bob_sift": bob_sift,
        "sift_len": sift_len,
        "qber": qber,
    }

# ---------------------------
# App layout & behavior
# ---------------------------
st.set_page_config(page_title=PAGE_TITLE, layout="wide", page_icon="🔐")
st.title(" Quantum Cryptography Simulator — BB84 ")
st.write("Flow: Alice uploads → photons animate → basis matching graph → Eve view → QBER check (abort if >11%) → AES-GCM encrypt/decrypt → Bob downloads.")

# Sidebar controls
with st.sidebar:
    st.header("Controls")
    num_bits = st.slider("Number of transmitted qubits", 200, 10000, 2000, step=100)
    p_noise = st.slider("Channel noise (flip prob)", 0.0, 0.5, 0.03, step=0.01)
    p_eve = st.slider("Eve intercept probability", 0.0, 1.0, 0.05, step=0.01)
    seed = st.number_input("Random seed (for reproducibility)", value=42, step=1)
    st.markdown("---")
    st.caption("QBER threshold: transfer is aborted if QBER > 11% to illustrate security decision.")
    st.markdown("---")
    st.write("History & Exports")
    history_limit = st.number_input("History size (keep last N runs)", min_value=1, max_value=100, value=20)
   

# Tabs
tabs = st.tabs(["Simulation", "Graphs & Analysis"])

# ---------------------------
# Simulation tab
# ---------------------------
with tabs[0]:
    st.header("Simulation")
    left, right = st.columns([1, 1])

    # Upload area on the left
    with left:
        st.subheader("1) Alice uploads an image (or use default)")
        uploaded = st.file_uploader("Upload image (png/jpg) — Alice's message", type=["png", "jpg", "jpeg"])
        default_img = load_default_image()
        if uploaded is None and default_img is None:
            st.warning("No image provided and no default available. Add images/windows.png or upload an image.")
        if uploaded is not None:
            alice_bytes = uploaded.getvalue()
            alice_name = uploaded.name
            try:
                alice_img = Image.open(io.BytesIO(alice_bytes)).convert("RGB")
            except Exception:
                alice_img = None
        elif default_img is not None:
            alice_img = default_img
            alice_bytes = pil_to_bytes(default_img, fmt="PNG")
            alice_name = "windows.png"
            st.info("Using default sample image from images/windows.png")
        else:
            alice_img = None
            alice_bytes = None
            alice_name = None

        if alice_img is not None:
            st.image(alice_img, caption=f"Alice's image: {alice_name}", use_container_width=True)
            st.write(f"Image size: {alice_img.size[0]} x {alice_img.size[1]} — bytes: {len(alice_bytes)}")

    # Controls and run on right (but results below left to stay left-aligned)
    with right:
        st.subheader("2) Transmission controls")
        st.write("Adjust parameters in the sidebar. Click **Run BB84** to start.")
        run = st.button("▶ Run BB84")

    # If user requested run
    if run:
        if alice_bytes is None:
            st.error("No file to send. Upload image or add default image to repo/images/windows.png.")
        else:
            # 2A: Animation — show photons traveling (Plotly frames)
            with st.spinner("Animating qubits..."):
                small_n = min(18,  max(6, num_bits//100))  # small sample for animation
                anim_res = simulate_bb84(small_n, p_noise, p_eve, seed)
                frames = []
                ys = np.linspace(0.05, 0.95, small_n)
                for t in range(0, 21):
                    xs = np.full(small_n, t/20)
                    colors = ['red' if anim_res["eve_intercept"][i] else 'royalblue' for i in range(small_n)]
                    frames.append(go.Frame(data=[go.Scatter(x=xs, y=ys, mode='markers',
                                                            marker=dict(size=12, color=colors))]))
                fig_anim = go.Figure(
                    data=[go.Scatter(x=[0], y=[0])],
                    layout=go.Layout(xaxis=dict(range=[0,1], showgrid=False, title="Channel (Alice → Bob)"),
                                     yaxis=dict(range=[0,1], showgrid=False, showticklabels=False),
                                     height=280),
                    frames=frames
                )
                fig_anim.update_layout(updatemenus=[dict(type="buttons", showactive=False,
                                                         buttons=[dict(label="Play", method="animate",
                                                                       args=[None, {"frame": {"duration": 80, "redraw": True},
                                                                                    "fromcurrent": True}])],
                                                         x=0.85, y=1.15)])
                st.plotly_chart(fig_anim, use_container_width=True)

            # 2B: Run full simulation with num_bits
            with st.spinner("Running BB84 simulation..."):
                res = simulate_bb84(num_bits=num_bits, p_noise=p_noise, p_eve=p_eve, seed=seed)
            qber = res["qber"]
            sift_len = res["sift_len"]

            # LEFT-ALIGNED Results area (under left column)
            st.markdown("---")
            st.subheader("3) Results (left-aligned)")

            m1, m2, m3 = st.columns(3)
            m1.metric("Sifted key length", sift_len)
            m2.metric("QBER (%)", f"{qber*100:.3f}" if not np.isnan(qber) else "N/A")
            m3.metric("Agreement (%)", f"{(1-qber)*100:.3f}" if not np.isnan(qber) else "N/A")

            # 3A: Bases / measurements graph (sample)
            st.write("Sample of bases & measurements (first 150 transmissions shown):")
            sample_n = min(150, num_bits)
            idx = np.arange(sample_n)
            # prepare matching indicator (for sample)
            matches = (res["alice_bases"][:sample_n] == res["bob_bases"][:sample_n])
            trace_a = go.Scatter(x=idx, y=res["alice_bases"][:sample_n], mode="markers", name="Alice bases (0=Z,1=X)",
                                 marker=dict(symbol="circle", size=8))
            trace_b = go.Scatter(x=idx, y=res["bob_bases"][:sample_n], mode="markers", name="Bob bases (0=Z,1=X)",
                                 marker=dict(symbol="x", size=8))
            # highlight matches by background color via shapes (simple approach: color markers)
            colors_match = ['green' if matches[i] else 'gray' for i in range(len(matches))]
            trace_match = go.Bar(x=idx, y=[0.15]*len(idx), base= -0.1, marker_color=colors_match, opacity=0.25, name="Match indicator")
            fig_bases = go.Figure(data=[trace_a, trace_b])
            fig_bases.update_layout(height=300, template="plotly_white", showlegend=True,
                                    xaxis_title="Transmission index", yaxis=dict(tickvals=[0,1], ticktext=['Z','X']))
            st.plotly_chart(fig_bases, use_container_width=True)

            # 3B: Show small preview of sifted bits table
            if sift_len > 0:
                preview_n = min(60, sift_len)
                df_preview = pd.DataFrame({
                    "Index": np.arange(preview_n),
                    "Alice bit": res["alice_sift"][:preview_n].astype(int),
                    "Bob bit": res["bob_sift"][:preview_n].astype(int),
                })
                st.subheader("Sample sifted key (Alice vs Bob)")
                st.dataframe(df_preview, use_container_width=True)
            else:
                st.info("No sifted bits (increase num_bits).")

            # 4) Eve's view (pixelated static or user-provided)
            st.markdown("---")
            st.subheader("4) Eve's View (corrupted / pixelated)")
            # If user provided a custom Eve image path, load that; else generate static pixelation of Alice image
            eve_custom_img = None
            if EVE_IMAGE_PATH:
                try:
                    eve_custom_img = Image.open(EVE_IMAGE_PATH).convert("RGB")
                except Exception as e:
                    st.warning(f"Could not open custom Eve image at {EVE_IMAGE_PATH}: {e}")
            if eve_custom_img is not None:
                st.image(eve_custom_img, caption="Eve's provided corrupted view (use EVE_IMAGE_PATH)", use_container_width=True)
            else:
                if alice_img is not None:
                    eve_img = make_eve_view(alice_img, pixel_scale=12, noise_level=0.08)
                    st.image(eve_img, caption="Eve's pixelated corrupted view (generated)", use_container_width=True)
                else:
                    st.write("Eve receives corrupted data (non-image).")

            # 5) QBER check -> abort if > 11%
            st.markdown("---")
            st.subheader("5) QBER decision")
            if np.isnan(qber):
                st.error("QBER undefined (no sifted bits) — aborting.")
                aborted = True
            elif qber > QBER_ABORT_THRESHOLD:
                st.error(f"QBER = {qber*100:.3f}% > {QBER_ABORT_THRESHOLD*100:.0f}% → ABORTING transfer for security.")
                aborted = True
            else:
                st.success(f"QBER = {qber*100:.3f}% ≤ {QBER_ABORT_THRESHOLD*100:.0f}% → Proceeding to derive key & encrypt.")
                aborted = False

            # 6) Derive key & encrypt/decrypt if not aborted
            alice_key = derive_key_from_bits(res["alice_sift"])
            bob_key = derive_key_from_bits(res["bob_sift"])
            st.subheader("6) Key derivation")
            st.code(f"Derived key (SHA-256 of sifted bits) — demo only: {alice_key.hex()}", language="text")

            encrypted_blob = None
            decrypted_blob = None
            if not aborted:
                try:
                    encrypted_blob = aes_gcm_encrypt(bob_key, alice_bytes)
                    decrypted_blob = aes_gcm_decrypt(bob_key, encrypted_blob)
                    ok = decrypted_blob == alice_bytes
                except Exception as e:
                    ok = False
                if ok:
                    st.success("Encrypt → Decrypt verification OK (Bob can recover file).")
                else:
                    st.error("Encryption/decryption verification FAILED (unexpected).")

            # 7) Show original / eve / bob and downloads (left-aligned)
            st.markdown("---")
            st.subheader("7) Transfer artifacts")
            st.write("**Alice (original)**")
            if alice_img is not None:
                st.image(alice_img, use_container_width=True)
            st.download_button("Download Original (Alice)", data=alice_bytes, file_name=f"alice_{alice_name}")

            st.write("**Eve (corrupted)**")
            if EVE_IMAGE_PATH and eve_custom_img is not None:
                st.download_button("Download Eve Provided Image", data=pil_to_bytes(eve_custom_img), file_name="eve_provided.png")
            else:
                if alice_img is not None:
                    st.download_button("Download Eve's Generated Corrupted Image", data=pil_to_bytes(eve_img), file_name="eve_corrupted.png")

            st.write("**Bob (received)**")
            if decrypted_blob is not None and not aborted:
                # show Bob's recovered image if image
                try:
                    bob_img = Image.open(io.BytesIO(decrypted_blob)).convert("RGB")
                    st.image(bob_img, caption="Bob's recovered image (after decrypt)", use_container_width=True)
                except Exception:
                    st.write(f"Recovered file bytes: {len(decrypted_blob)}")
                st.download_button("Download Encrypted Blob (.bin)", data=encrypted_blob, file_name="encrypted_blob.bin")
                st.download_button("Download Decrypted (Bob)", data=decrypted_blob, file_name=f"bob_{alice_name}")
                # also allow downloading the derived key (demo only)
                st.download_button("Download Derived Key (hex).txt", data=alice_key.hex(), file_name="derived_key_hex.txt")
            else:
                st.info("Bob did not receive a decryptable file (transfer aborted or failed).")

            # Save run to history in session_state
            run_record = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "num_bits": num_bits,
                "p_noise": p_noise,
                "p_eve": p_eve,
                "seed": seed,
                "sift_len": sift_len,
                "qber": float(qber) if not np.isnan(qber) else None,
                "aborted": bool(aborted),
            }
            hist = st.session_state.get("history", [])
            hist.insert(0, run_record)
            st.session_state["history"] = hist[:history_limit]

# ---------------------------
# Graphs & Analysis tab
# ---------------------------
with tabs[1]:
    st.header("Graphs & Analysis")
    st.write("Interactive exploration of protocol behavior and history of runs.")

    # HISTORY table + export
    st.subheader("Run History")
    history = st.session_state.get("history", [])
    if len(history) == 0:
        st.info("No runs recorded yet. Run a simulation first.")
    else:
        df_hist = pd.DataFrame(history)
        st.dataframe(df_hist, use_container_width=True)
        csv = df_hist.to_csv(index=False).encode("utf-8")
        st.download_button("Download History CSV", data=csv, file_name="bb84_history.csv")

    st.markdown("---")
    st.subheader("Interactive Sweeps")

    # Sweep controls
    sweep_bits = st.number_input("Bits for sweeps", min_value=200, max_value=10000, value=2000, step=200)
    sweep_seed = st.number_input("Seed for sweeps", value=1234, step=1)
    sweep_noise_max = st.slider("Noise sweep (max)", 0.0, 0.5, 0.5, step=0.01)
    sweep_noise_steps = st.slider("Noise steps", 5, 60, 21, step=1)
    sweep_eve_max = st.slider("Eve sweep (max)", 0.0, 1.0, 1.0, step=0.01)
    sweep_eve_steps = st.slider("Eve steps", 5, 41, 21, step=1)

    if st.button("Run sweeps"):
        with st.spinner("Running sweeps..."):
            noise_vals = np.linspace(0.0, sweep_noise_max, sweep_noise_steps)
            accs = []
            qbers = []
            for n in noise_vals:
                r = simulate_bb84(num_bits=sweep_bits, p_noise=float(n), p_eve=p_eve, seed=int(sweep_seed))
                q = r["qber"]
                qbers.append(q*100 if not np.isnan(q) else None)
                accs.append((1-q)*100 if not np.isnan(q) else None)

            fig1 = go.Figure()
            fig1.add_trace(go.Scatter(x=noise_vals, y=accs, mode="lines+markers", name="Accuracy (%)"))
            fig1.add_trace(go.Scatter(x=noise_vals, y=qbers, mode="lines+markers", name="QBER (%)"))
            fig1.update_layout(title="Accuracy & QBER vs Noise", xaxis_title="Noise prob", yaxis_title="Percent", template="plotly_white")
            st.plotly_chart(fig1, use_container_width=True)
            # downloadable plot as HTML
            st.download_button("Download Accuracy Plot (HTML)", data=fig1.to_html(full_html=False), file_name="accuracy_plot.html")

            eve_vals = np.linspace(0.0, sweep_eve_max, sweep_eve_steps)
            qbers_eve = []
            for e in eve_vals:
                r2 = simulate_bb84(num_bits=sweep_bits, p_noise=p_noise, p_eve=float(e), seed=int(sweep_seed))
                q = r2["qber"]
                qbers_eve.append(q*100 if not np.isnan(q) else None)

            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(x=eve_vals, y=qbers_eve, mode="lines+markers", name="QBER (%)"))
            fig2.update_layout(title=f"QBER vs Eve probability (noise fixed={p_noise})", xaxis_title="Eve prob", yaxis_title="QBER (%)", template="plotly_white")
            st.plotly_chart(fig2, use_container_width=True)
            st.download_button("Download QBER vs Eve Plot (HTML)", data=fig2.to_html(full_html=False), file_name="qber_vs_eve_plot.html")

        st.success("Sweeps complete.")

    st.markdown("---")
    st.subheader("Quick summary of last run")
    if "history" in st.session_state and len(st.session_state["history"]) > 0:
        last = st.session_state["history"][0]
        st.json(last)
    else:
        st.info("No runs yet. Run a simulation to populate summary.")

# ---------------------------
# Footer
# ---------------------------
st.markdown("---")
st.caption("Educational demo. Keys shown / downloadable for demonstration — in real QKD, keys and raw material are handled confidentially.")





