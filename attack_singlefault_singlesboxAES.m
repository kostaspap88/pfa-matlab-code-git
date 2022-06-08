% Single fault PFA using 3 strategies on the last round of a singe-sbox
% AES implementation
function [key] = attack_singlefault_singlesboxAES(ciphertext, vsize, sboxc, faultc)


% make a histogram of the ciphertext values counting the frequency of all
% possible values
frequency = histcounts(ciphertext, vsize);

% find the ciphertext values with the highest and lowest frequency (tmax, tmin)
[frequency_max, index_max] = max(frequency);

% under PFA, tmax will appear with probablity 2*(1/256)
tmax = index_max - 1; 

% under PFA, tmin should never appear
[frequency_min, index_min] = min(frequency);
tmin = index_min - 1;

% do a sanity check here
check_count_tmin = frequency_min == 0; 

% Strategy 1: look at tmin i.e. the ciphertext value that does not appear
% we assume that we know the fault position

v = sboxc.sbox(faultc.fault_single_position + 1);

key.strategy1 = bitxor(v, tmin); 

% Note that if (due to the small number of faults) we have several
% ciphertext values that do not appear, then this strategy will not work
% Note that strategy 1 is accurate in the sense that tmin must be exactly 0
% and any nonzero value implies that it is not the right ciphertext

% Strategy 2: exclude ciphertext values that have count > 0
% We assume that we know the fault position

v = sboxc.sbox(faultc.fault_single_position + 1);

all_values = 0:(vsize-1);

excluded_ciphertext = [];

for i=1:length(all_values) % enumerate over all values
    
    if frequency(all_values(i) + 1) > 0
        
        excluded_ciphertext = [excluded_ciphertext, all_values(i)];
        
    end

end

impossible_keys = bitxor(excluded_ciphertext, v);

all_keys = 0:(vsize-1);

key.strategy2 = setdiff(all_keys, impossible_keys);

% Note that strategy 2 is accurate in the sense that any candidate whose
% respective ciphetext has count > 0 is automatically excluded
% Note that (due to the small number of faults) multiple key candidates may
% remain (i.e. multiple keys may have count==0)

% Strategy 3: find the value that is twice as likely to happen
% We assume that we know fault position and the fault value (that's why we
% pass the single-fault sbox as argument and get it's first position)

v_faulty = sboxc.sbox_faulty(faultc.fault_single_position + 1);

key.strategy3 = bitxor(v_faulty, tmax);

% Note that this strategy is not accurate like strategies 1,2 but it is 
% based on statistics. Typically it requires more ciphertexts for the 
% probability estimation


end