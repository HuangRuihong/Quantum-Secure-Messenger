
# network/inspect_kyber_params.py


try:
    from kyber_py.kyber import Kyber768
    print("Successfully imported Kyber768")
    print(f"Type: {type(Kyber768)}")
    print(f"Dir: {dir(Kyber768)}")
    if hasattr(Kyber768, '__dict__'):
        print(f"Dict keys: {Kyber768.__dict__.keys()}")

    
    # Calculate lengths
    pk_len = 12 * Kyber768.k * Kyber768.n // 8 + 32
    print(f"Calculated PK len: {pk_len}")
    
    sk_len = 12 * Kyber768.k * Kyber768.n // 8 + 32 + 32 + pk_len
    print(f"Calculated SK len: {sk_len}")
    
    c1_len = Kyber768.du * Kyber768.k * Kyber768.n // 8
    c2_len = Kyber768.dv * Kyber768.n // 8
    c_len = c1_len + c2_len
    print(f"Calculated C len: {c_len} (c1={c1_len}, c2={c2_len})")
    
except Exception as e:
    print(f"Error: {e}")
