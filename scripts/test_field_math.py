from hash_utils import SNARK_FIELD_MODULUS, compute_commitment, hash_password_to_field

# Values from the debug output
g0 = 54918
password = "brand123"  # or whatever you used
X = hash_password_to_field(password)

print(f"g0 = {g0}")
print(f"X (hashed password) = {X}")
print(f"Field modulus = {SNARK_FIELD_MODULUS}")
print()

# Compute Y manually
Y_manual = (g0 * X) % SNARK_FIELD_MODULUS
print(f"Y (manual computation) = {Y_manual}")

# Compute Y using our function
Y_func = compute_commitment(g0, X)
print(f"Y (using compute_commitment) = {Y_func}")

# Check if they match
print(f"\nDo they match? {Y_manual == Y_func}")

# Show the raw multiplication before modulo
raw_product = g0 * X
print(f"\nRaw product (g0 * X) = {raw_product}")
print(f"Raw product is larger than field? {raw_product > SNARK_FIELD_MODULUS}")

