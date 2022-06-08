% PFA with unknown fault and position on the single sbox last round of AES
function [key] = attack_singlefault_singlesboxAES_unknownfaultandposition(ciphertext, vsize, sboxc, sbox_input)

% 1. Recovering the unknown fault value
% First use any available ciphertext to recover it
% and we continue with e.g. an MLE-based PFA attack
% in the single byte case, we use all the available traces to estimate the
% fault
frequency = histcounts(ciphertext, 256);
% find the least frequent value of the ciphertext (lfc)
[lfc_value, lfc] = min(frequency);
lfc = lfc - 1;
% find the most frequent value of the ciphertext (mfc)
[mfc_value, mfc] = max(frequency);
mfc = mfc - 1;
% their difference equals the fault
fault_estimated = bitxor(lfc, mfc);
 
% 2. continue with the mle attack
values = 0:vsize-1;
impossible_ciphertext = [];
for i=1:length(values)   
    if (frequency(values(i) + 1) > 0)
        impossible_ciphertext = [impossible_ciphertext, values(i)];
    end
end
cmin = setdiff(values, impossible_ciphertext);

for i=1:length(cmin)
    cmax(i) = bitxor(cmin(i), fault_estimated);
end
[max_cmax, max_cmax_index] = max(frequency(cmax + 1));

% 3. compute the key
% we enumerate over all positions
key_candidate = zeros(vsize,1);
for fault_position=0:vsize-1
    v = sboxc.sbox(fault_position + 1);
    v_faulty = bitxor(v, fault_estimated);
    key_candidate(fault_position + 1) = bitxor(cmax(max_cmax_index), v_faulty);
end

% We have the ciphertext. We also need a correct plaintext to verify the
% candidate. In this toy example we act as if the sbox input to the last
% round is the plaintext and we get it as a function argument
% Note that we only need a single correct plaintext-ciphtertext pair
correct_plaintext = sbox_input(1);
correct_ciphertext = ciphertext(1);
for i=1:vsize
   verification = bitxor(sboxc.sbox(correct_plaintext + 1), key_candidate(i)) == correct_ciphertext;
   if verification
       key.mle_steps_unknownfault_unknownposition = key_candidate(i);
   end
end


end