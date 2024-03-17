'''
This code has been developed to ensure the security of the target cache. 
In order to achieve this, we analyze data to identify patterns that could
potentially lead to cache attacks. To generate the necessary data,
we have adopted Jacob Szefer's three-step attack approach. Each attack is 
based on a selection of 25 distinct patterns, with cache addresses, commands, 
hit/miss outcomes, and internal/external factors being chosen at random. 
It is important to note that this code forms part of my Master's project at 
the University of Zanjan, under the supervision of Professor Ali Azarpivand. 
It is important to highlight that while this code is currently in its initial stages,
it is expected to undergo further development and expansion in the future.
Ali Soltan Mohammadi
email: ali.s.mohammadi@znu.ac.ir
'''

import random
# Definition of the three-step pattern of chache attack
AP = [["inv/inv", "read/read", "read/read", "IH"], 
      ["read/read", "read/read", "read/read", "IH"],
      ["inv/read", "read/read", "read/read", "IH"],
      ["inv/inv", "read/read", "read/read", "EH"],
      ["read/read", "read/read", "read/read", "EH"],
      ["inv/read", "read/read", "read/read", "EH"],
      ["inv/read", "read/read", "read/read", "EH"],
      ["inv/read", "read/read", "read/read", "IH"],
      ["read/read", "inv/read", "read/write", "EM"],
      ["read/read", "inv/read", "read/write", "IM"],
      ["read/read", "read/read", "read/write", "EM"],
      ["read/read", "read/read", "read/write", "EM"],
      ["read/read", "read/read", "read/write", "IM"],
      ["read/read", "read/read", "read/write", "EM"],
      ["read/read", "read/read", "read/write", "IM"],
      ["read/read", "inv/read", "read/write", "EM"],
      ["read/read", "inv/read", "read/write", "IM"],
      ["inv/inv", "read/read", "inv/write", "IH"],
      ["read/read", "read/read", "inv/write", "IH"],
      ["read/read", "read/read", "inv/write", "IH"],
      ["inv/read", "read/read", "inv/write", "EH"],
      ["inv/read", "read/read", "inv/write", "IH"],
      ["inv/inv", "read/read", "inv/write", "EH"],
      ["read/read", "read/read", "inv/write", "EH"],
      ["read/read", "read/read", "inv/write", "EH"],
      ["inv/read", "read/read", "inv/write", "EH"],
      ["inv/read", "read/read", "inv/write", "IH"],
      ["read/read", "inv/read", "inv/read", "EM"],
      ["read/read", "inv/read", "inv/read", "IM"],
      ["read/read", "read/read", "inv/read", "EM"],
      ["read/read", "read/read", "inv/read", "EM"],
      ["read/read", "read/read", "inv/read", "IM"],
      ["read/read", "read/read", "inv/read", "EM"],
      ["read/read", "read/read", "inv/read", "IM"],
      ["read/read", "inv/read", "inv/read", "EM"],
      ["read/read", "inv/read", "inv/read", "IM"]]

# Genereate simulation trace with random state
def Generate_Cache_Simulation_Trace():
    z=0
    number_of_pattern = 25
    place_of_attacks = []
    # Define cache address range randomly
    CONSTANT_ADDRESSES_d = [hex(addr) for addr in range(80, 140)]
    CONSTANT_ADDRESSES_ua = [hex(addr) for addr in range(100, 130)]
    CONSTANT_ADDRESSES_o = [hex(addr) for addr in range(200, 230)]
    print("Generate Cache Simulation Trace: Start")
    for n in range(len(AP)):                    # Repeating the algorithm for the number of attack patterns
        for k in range(number_of_pattern):      # Iterate to generate 25 pattern states randomly for each attack 
            success = False
            flage = False
            attempts = 0
            saved_attempts = 100
            attempts_buffer = []
            reserve_attempts_buffer = []
            steps = []
            x = random.randint(0,5)            # A random number of commands between the first and second steps
            y = random.randint(0,5)            # A random number of commands between the second and third steps
            sequential_value = z 
            zz=z
            while not success:                 # Infinite loop for generating random data to cover all possible states of patterns for all attacks
                attempts += 1
                steps = []
                ad_address = random.choice(CONSTANT_ADDRESSES_d)    
                ad_instruction = AP[n][0]
                ad_inex = random.choice(["IH", "EH", "IM", "EM"])
                ad_hit_miss = random.choice(["hit", "miss"])
                steps.append((sequential_value, ad_address, ad_instruction, ad_hit_miss, ad_inex))     # First steps

                sequential_value += 1
                
                for i in range(x):
                    vu_address = random.choice(CONSTANT_ADDRESSES_o) 
                    vu_instruction = random.choice(["inv/inv", "inv/read", "read/read", "read/write", "inv/write"])
                    vu_inex = random.choice(["IH", "EH", "IM", "EM"])
                    vu_hit_miss = random.choice(["hit", "miss"])
                    steps.append((sequential_value, vu_address, vu_instruction, vu_hit_miss, vu_inex))  # The first deception
                    sequential_value +=1

                vu_address = random.choice(CONSTANT_ADDRESSES_ua) 
                vu_instruction = AP[n][1]
                vu_inex = random.choice(["IH", "EH", "IM", "EM"])
                vu_hit_miss = random.choice(["hit", "miss"])
                steps.append((sequential_value, vu_address, vu_instruction, vu_hit_miss, vu_inex))      # Second steps 

                sequential_value +=1
                
                for j in range(y):
                    vu_address = random.choice(CONSTANT_ADDRESSES_o) 
                    vu_instruction = random.choice(["inv/inv", "inv/read", "read/read", "read/write", "inv/write"])
                    vu_inex = random.choice(["IH", "EH", "IM", "EM"])
                    vu_hit_miss = random.choice(["hit", "miss"])
                    steps.append((sequential_value, vu_address, vu_instruction, vu_hit_miss, vu_inex))  # The second deception
                    sequential_value +=1
                
                va_address = random.choice(CONSTANT_ADDRESSES_ua) 
                va_instruction = AP[n][2]
                vu_inex = random.choice(["IH", "EH", "IM", "EM"])
                va_hit_miss = random.choice(["hit", "miss"])
                steps.append((sequential_value, va_address, va_instruction, va_hit_miss, vu_inex))      # Third steps
                      
                
                z = sequential_value 
                sequential_value += 1
                # Generate 3_step cache attacks 
                if steps[0][1] == steps[x+1][1] and steps[x+1][1] == steps[x+y+2][1] and steps[0][3] == "miss" and steps[x+1][3] == "miss" and steps[x+y+2][3] == "hit" and steps[0][2] == AP[n][0] and steps[x+1][2] == AP[n][1] and steps[x+y+2][2] == AP[n][2] and steps[0][4] == AP[n][3] and steps[x+1][4] == AP[n][3] and steps[x+y+2][4] == AP[n][3]:
                    success = True

                attempts_buffer.append(steps)
                if len(attempts_buffer) > saved_attempts and success:
                    reserve_attempts_buffer = attempts_buffer
                    flage = True
                if len(attempts_buffer) > saved_attempts:
                    attempts_buffer = []
                    sequential_value = zz + 1
   
            
            place_of_attacks.append(z)
            if flage:
                attempts_buffer = reserve_attempts_buffer
                flage = False
            with open("./Simulation_trace_to_cache_three_step_attacks.txt", "a") as file:     # Store the pattern in the file
                for attempt in attempts_buffer:
                    for step in attempt:
                        file.write(f"{step[0]}, {step[1]}, {step[2]}, {step[3]}, {step[4]}\n")

        #print("------")
    
    print("Generate Cache Simulation Trace: END")

# Execute the generate function
Generate_Cache_Simulation_Trace()