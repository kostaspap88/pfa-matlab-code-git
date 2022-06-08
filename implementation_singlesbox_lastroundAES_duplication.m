% Duplicateed implementation of sbox and addroundkey operations on the 10th
% round of AES, operating on a single byte
% We use a correct and and a faulted sbox and compare the ciphertext output
function [ciphertext] = implementation_singlesbox_lastroundAES_duplication(key, no_traces, sboxc, vsize)

% Last round AES computation on a single byte (we ommit ShiftRows) 

% generate a random input to the 10th round AES sbox
sbox_input = randi(vsize, no_traces, 1) - 1;

% compute the sbox output using the various versions of the sbox

% fault-free sbox
sbox_output.faultfree = zeros(no_traces, 1);
% faulty sbox
sbox_output.faulty = zeros(no_traces, 1);

% for all traces
for i=1:no_traces
    
    % fault-free sbox computation
    sbox_output.faultfree(i) = sboxc.sbox(sbox_input(i) + 1);
    
    % faulty sbox computation -- here we choose a single-fault sbox but it
    % can be replaced with any other faulty sbox
    sbox_output.faulty(i) = sboxc.sbox_faulty(sbox_input(i) + 1);  
    
end

% compute the ciphertext after the 10th round addroundkey operation

% fault-free
ciphertext.faultfree = bitxor(sbox_output.faultfree, key);

% faulty
ciphertext.faulty = bitxor(sbox_output.faulty, key);

% perform the comparison for the redundant encryption based dual modular 
% redundancy with separate sboxes. That is the 2 encryption modules do not 
% share an sbox in memory because that would imply that both of them would 
% become faulty with a persistent fault.

counter_nco = 1;
for i=1:no_traces
    
   if ciphertext.faultfree(i) == ciphertext.faulty(i) 
       
        % no ciphertext output case (NCO)
        ciphertext.nco(counter_nco,1) = ciphertext.faultfree(i);
        counter_nco = counter_nco + 1;
        
        % zero value output case (ZVO)
        ciphertext.zvo(i,1) = ciphertext.faultfree(i);
        
        % random ciphertext output case (RCO)
        ciphertext.rco(i,1) = ciphertext.faultfree(i);
   else
       
        % no ciphertext output case (NCO)
        % do nothing here
        
        % zero value output case (ZVO)
        % set to zero
        ciphertext.zvo(i,1) = 0;
        
        % random ciphertext output case (RCO)
        % set to random
        ciphertext.rco(i,1) = randi(vsize) - 1;
   end
end


end