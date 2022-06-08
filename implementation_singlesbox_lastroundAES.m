% Implementation of sbox and addroundkey operations on the 10th round of
% AES, operating on a single byte, using various sboxes that have been
% faulted with PFA
function [sbox_input, sbox_output, ciphertext] = implementation_singlesbox_lastroundAES(key, no_traces, sboxc, vsize)

% Last round AES computation on a single byte (we ommit ShiftRows)

% generate a random byte input to the 10th round AES sbox
sbox_input = randi(vsize, no_traces, 1) - 1;

% compute the sbox output using the various versions of the sbox

% fault-free sbox
sbox_output.faultfree = zeros(no_traces, 1);
% single fault sbox
sbox_output.singlefault = zeros(no_traces, 1);
% multiple fault sbox
sbox_output.multiplefaults = zeros(no_traces, 1);

% repeat for all traces
for i=1:no_traces
    
    % fault-free sbox computation
    sbox_output.faultfree(i) = sboxc.sbox(sbox_input(i) + 1);
    
    % single-fault sbox computation
    sbox_output.singlefault(i) = sboxc.sbox_faulty(sbox_input(i) + 1);
    
    % multiple-fault sbox computation
    sbox_output.multiplefaults(i) = sboxc.sbox_faulty_multiple(sbox_input(i) + 1);
    
end

% compute the ciphertext after the 10th round addroundkey operation

% fault-free
ciphertext.faultfree = bitxor(sbox_output.faultfree, key);
% single-fault
ciphertext.singlefault = bitxor(sbox_output.singlefault, key);
% multiple faults
ciphertext.multiplefaults = bitxor(sbox_output.multiplefaults, key);


end