import numpy as np
import hashlib


class ChaoticGenerator:
    def __init__(self, initial_conditions=None):
        if initial_conditions is None:
            initial_conditions = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
        self.state = np.array(initial_conditions, dtype=np.float64)
        self.dt = 0.01
        
    def _hyperchaotic_ode(self, state):
        x1, x2, x3, x4, x5, x6 = state
        a, b, c, d, e, f = 10.0, 8.0/3.0, 28.0, -1.0, 2.0, 5.0
        g, h = 0.1, 0.1
        
        dx1 = a * (x2 - x1) + x4
        dx2 = b * x1 - x1 * x3 + x5
        dx3 = x1 * x2 - c * x3 + x6
        dx4 = d * x1 + e * x2
        dx5 = f * x2 + g * x3
        dx6 = h * x1 + x3
        
        return np.array([dx1, dx2, dx3, dx4, dx5, dx6])
    
    def iterate(self, steps=100):
        for _ in range(steps):
            k1 = self._hyperchaotic_ode(self.state)
            k2 = self._hyperchaotic_ode(self.state + 0.5 * self.dt * k1)
            k3 = self._hyperchaotic_ode(self.state + 0.5 * self.dt * k2)
            k4 = self._hyperchaotic_ode(self.state + self.dt * k3)
            
            self.state = self.state + (self.dt / 6.0) * (k1 + 2*k2 + 2*k3 + k4)
    
    def get_random_value(self, min_val=1000, max_val=9999):
        self.iterate(steps=50)
        chaotic_value = abs(self.state[0]) * 1000000
        normalized = int(chaotic_value) % (max_val - min_val + 1) + min_val
        return normalized
    
    def get_chaotic_sequence(self, count=10, min_val=1000, max_val=9999):
        sequence = []
        for _ in range(count):
            sequence.append(self.get_random_value(min_val, max_val))
        return sequence
    
    def get_seed_from_state(self):
        state_bytes = self.state.tobytes()
        hash_obj = hashlib.sha256(state_bytes)
        return int(hash_obj.hexdigest(), 16)


if __name__ == "__main__":
    gen = ChaoticGenerator()
    print("Generating chaotic random values:")
    for i in range(5):
        val = gen.get_random_value()
        print(f"Random value {i+1}: {val}")

